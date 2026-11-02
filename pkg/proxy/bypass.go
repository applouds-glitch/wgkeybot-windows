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
	"sync"
	"time"
)

// Keeping the proxy's own sockets out of the tunnel.
//
// On Android VpnService.protect() binds each socket to the physical network.
// Windows has no such call: protectControl is a no-op, and the proxy's traffic
// takes whatever the routing table says — which, once AllowedIPs 0.0.0.0/0 is
// installed, is the wintun adapter. A TURN relay, a VK API host or a DNS
// resolver dialled into the tunnel loops back through this very proxy, and
// while the tunnel is dead (the case a reconnect exists for) it goes nowhere.
//
// The host used to install /32 bypass routes once, before AllowedIPs, for the
// addresses known at that moment: the credentials' relays and the auth hosts
// resolved at bootstrap. Everything learned later — a relay from a rotated
// credential, an address the VK dial moved on to, a captcha widget host — had
// no route. The BypassRouter is asked for one right before every dial instead,
// synchronously, so the route exists before the first packet leaves. In SOCKS
// mode (netstack, no system routes) no router is set and the dials are plain.
type BypassRouter interface {
	// EnsureBypassRoute makes sure ip is routed through the physical gateway.
	// Idempotent; an error means the dial must not proceed.
	EnsureBypassRoute(ip string) error
}

var (
	bypassMu     sync.RWMutex
	bypassRouter BypassRouter
)

// errBypassRoute marks a dial the router would not route outside the tunnel:
// the route could not be added (the gateway's interface went away under it) or
// the address is kept inside on purpose. It is the machine's side, never the
// far end's — the Windows counterpart of Android's protect() refusal, and read
// the same way (ownNetworkFailure).
var errBypassRoute = errors.New("no route outside the tunnel")

// SetBypassRouter installs the router the dials consult; nil removes it.
func SetBypassRouter(r BypassRouter) {
	bypassMu.Lock()
	bypassRouter = r
	bypassMu.Unlock()
}

// ClearBypassRouter removes r, and only r: a Manager torn down after its
// successor connected must not take the successor's router with it.
func ClearBypassRouter(r BypassRouter) {
	bypassMu.Lock()
	if bypassRouter == r {
		bypassRouter = nil
	}
	bypassMu.Unlock()
}

// ensureBypass asks the router, if any, for a route to the host of addr
// (host:port or a bare host). Names are left alone: every dial here goes to
// an address the proxy resolved itself.
func ensureBypass(addr string) error {
	bypassMu.RLock()
	r := bypassRouter
	bypassMu.RUnlock()
	if r == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if net.ParseIP(host) == nil {
		return nil
	}
	if err := r.EnsureBypassRoute(host); err != nil {
		return fmt.Errorf("%w: %w", errBypassRoute, err)
	}
	return nil
}

// DialOutsideTunnel is a DialContext for hosts that must be reached over the
// physical network whatever the tunnel does: the name goes through the
// proxy's own resolver and address walk (vk_dial.go), and every address gets
// its bypass route before it is dialled. The host's captcha reverse proxy uses
// it — its page is served from VK while the VPN routes are up, and during a
// transport rebuild the tunnel it would otherwise use is the dead one.
func DialOutsideTunnel(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}
	return dialVKHost(ctx, hostCache, network, addr, func(ctx context.Context, network, addr string) (net.Conn, error) {
		if err := ensureBypass(addr); err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, addr)
	})
}
