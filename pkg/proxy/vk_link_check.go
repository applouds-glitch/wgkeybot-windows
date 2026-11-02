/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	tlsclient "github.com/kiper292/tls-client"
)

// Verdicts of CheckVKLink, read by the expert mode window. The negative codes
// reuse StartProxy's numbering wherever the meaning is the same
// (-2 the call refuses anonymous joins, -3 a captcha stands in the way, -4 the
// call is gone or the link is wrong), so a link the check calls dead is one the
// start would refuse for the same reason.
const (
	linkCheckOK           int32 = 0
	linkCheckTemporary    int32 = -1 // VK unreachable, or it asked to come back later
	linkCheckRequiresAuth int32 = -2
	linkCheckCaptcha      int32 = -3 // VK's captcha gate: a verdict on this client, not on the call
	linkCheckUnavailable  int32 = -4
	linkCheckRefused      int32 = -5 // any other VK error
)

// vkLinkCheckTimeout bounds one check. The flow is five requests that take
// about a second on a healthy path; the bound is for a machine with no route to
// VK at all, where every request would otherwise sit out its own 20s client
// timeout on each of vkCallsAttempts.
const vkLinkCheckTimeout = 45 * time.Second

// joinHash reduces a VK call link to the join hash the API wants: whatever
// follows the last "join/", up to the first path, query or fragment separator.
// A bare hash comes back as is. StartProxy and the link check share it so
// the check judges exactly the string the start would join with.
func joinHash(raw string) string {
	parts := strings.Split(strings.TrimSpace(raw), "join/")
	hash := parts[len(parts)-1]
	if idx := strings.IndexAny(hash, "/?#"); idx != -1 {
		hash = hash[:idx]
	}
	return hash
}

// newVKAPIClient builds the uTLS client every trip to VK goes through — the
// credential fetch and the link check alike — under the session identity: the
// UA, the client hints and the ClientHello all come from the same Chrome major
// (vkSessionIdentity in profiles.go), so the transport cannot claim a different
// browser than the headers do, and the captcha phase cannot claim a different
// one than the phase that triggered it.
// Returns the Chrome major with the client so callers can name it in the log.
func newVKAPIClient() (tlsclient.HttpClient, Profile, int, error) {
	return newVKAPIClientDialing(vkDialCounting)
}

// vkAPIClient is the VK client with the count of connections it made on
// addresses from memory (vk_host_memory.go): its own, not the process's, so a
// flow reads only what its own connections did (Codex review 23.10).
type vkAPIClient struct {
	tlsclient.HttpClient
	remembered *atomic.Uint64
}

func (c vkAPIClient) rememberedDials() uint64 { return c.remembered.Load() }

// newVKAPIClientDialing is newVKAPIClient with every connection dialled by the
// dial dialFor makes for the client's own count: tls-client takes a custom dial
// over its own dialer for all of them.
func newVKAPIClientDialing(dialFor func(remembered *atomic.Uint64) func(ctx context.Context, network, addr string) (net.Conn, error)) (tlsclient.HttpClient, Profile, int, error) {
	remembered := new(atomic.Uint64)
	dial := dialFor(remembered)
	profile, chromeMajor := vkSessionIdentity()
	client, err := tlsclient.NewHttpClient(
		tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		// ClientHello matching the session's Chrome major (vk_tls_clienthello.go)
		// + random extension order: the combination VK's bot detector accepts.
		tlsclient.WithClientProfile(vkChromeClientProfile(chromeMajor)),
		tlsclient.WithRandomTLSExtensionOrder(),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
		tlsclient.WithDialer(getCustomNetDialer()),
		tlsclient.WithDialContext(dial),
		// Additive trust: system CAs + bundled Минцифры chain, in case VK/OK
		// migrate onto Russian roots (see vk_certs.go).
		tlsclient.WithTransportOptions(&tlsclient.TransportOptions{RootCAs: vkRootCAPool()}),
	)
	if err != nil {
		return nil, Profile{}, 0, fmt.Errorf("failed to create tlsclient: %w", err)
	}
	return vkAPIClient{HttpClient: client, remembered: remembered}, profile, chromeMajor, nil
}

// checkVKLink asks VK whether a call still admits anonymous participants, by
// running the same captcha-free VK Calls flow a credential fetch starts with
// and classifying its outcome. Only that flow: the legacy chain behind it is
// where the captcha lives, and a check must never open a captcha dialog for a
// link the user is merely looking at. A verdict the flow cannot give without
// the captcha comes back as linkCheckCaptcha rather than a guess.
func checkVKLink(ctx context.Context, link string, client tlsclient.HttpClient, profile Profile) int32 {
	_, _, _, _, err := getVKCredsViaVKCalls(ctx, link, client, profile)
	switch {
	case err == nil:
		return linkCheckOK
	case isCallUnavailable(err):
		return linkCheckUnavailable
	case errors.Is(err, errCallRequiresAuth):
		return linkCheckRequiresAuth
	case errors.Is(err, errVKCallsCaptchaGate):
		return linkCheckCaptcha
	case isTransientVKCalls(err), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return linkCheckTemporary
	default:
		return linkCheckRefused
	}
}

// CheckVKLink is expert mode's "check this link": it takes a VK call link or a
// bare join hash and returns one of the LinkCheck* verdicts. Independent of the
// proxy — its own client, no credential cache, no vkSemaphore slot — so it can
// run with the tunnel up or down; every dial still asks for its bypass route,
// so with the VPN up the trip leaves by the physical network like every other
// VK request. Blocking for up to vkLinkCheckTimeout or until ctx ends. The link
// is never logged: the journal is exported, and a join link admits anyone.
func CheckVKLink(ctx context.Context, raw string) int32 {
	link := joinHash(raw)
	if link == "" {
		return linkCheckUnavailable
	}
	client, profile, chromeMajor, err := newVKAPIClient()
	if err != nil {
		turnLog("[LinkCheck] cannot build the VK client: %v", err)
		return linkCheckTemporary
	}
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(ctx, vkLinkCheckTimeout)
	defer cancel()
	started := time.Now()
	code := checkVKLink(ctx, link, client, profile)
	turnLog("[LinkCheck] verdict %d after %v (Chrome/%d identity)", code, time.Since(started).Round(time.Millisecond), chromeMajor)
	return code
}

// The verdicts of CheckVKLink, for the host.
const (
	LinkCheckOK           = linkCheckOK
	LinkCheckTemporary    = linkCheckTemporary
	LinkCheckRequiresAuth = linkCheckRequiresAuth
	LinkCheckCaptcha      = linkCheckCaptcha
	LinkCheckUnavailable  = linkCheckUnavailable
	LinkCheckRefused      = linkCheckRefused
)
