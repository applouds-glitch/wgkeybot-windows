/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/kiper292/tls-client"
)

// withOwnNetworkBudget shortens the own-network retry for one test.
func withOwnNetworkBudget(t *testing.T, budget, delay time.Duration) {
	t.Helper()
	prevBudget, prevDelay := vkCallsOwnNetworkBudget, vkCallsOwnNetworkRetryDelay
	vkCallsOwnNetworkBudget, vkCallsOwnNetworkRetryDelay = budget, delay
	t.Cleanup(func() { vkCallsOwnNetworkBudget, vkCallsOwnNetworkRetryDelay = prevBudget, prevDelay })
}

// scriptedVKAnswer plays the whole captcha-free flow; transport, when set, is
// what every request fails with instead.
func scriptedVKAnswer(t *testing.T, step1 string, transport error) scriptedHTTPClient {
	t.Helper()
	return scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		if transport != nil {
			return nil, transport
		}
		// The VK API names the method in the path, the OK CDN in the query.
		method := r.URL.Query().Get("method")
		if method == "" {
			method = strings.TrimPrefix(r.URL.Path, "/method/")
		}
		switch method {
		case "auth.getAnonymToken":
			if step1 != "" {
				return jsonHTTP(step1), nil
			}
			return jsonHTTP(`{"response":{"token":"anon"}}`), nil
		case "messages.getCallPreview":
			return jsonHTTP(`{"response":{"user_id":1,"secret":"secret"}}`), nil
		case "messages.getAnonymCallToken":
			return jsonHTTP(`{"response":{"token":"ok-token"}}`), nil
		case "auth.anonymLogin":
			return jsonHTTP(`{"session_key":"session"}`), nil
		case "vchat.joinConversationByLink":
			return jsonHTTP(`{"turn_server":{"username":"u","credential":"p","urls":["turn:127.0.0.1:3478"]}}`), nil
		}
		t.Fatalf("unexpected method %s", method)
		return nil, nil
	}}
}

// A request that died in DNS the way dialVKHost reports it, wrapped by the HTTP
// client the way client.Do returns it. reached: whether any resolver was.
func lookupRequestError(r *fhttp.Request, reached bool, cause error) error {
	lookup := dnsResolveError{fmt.Errorf("all DNS servers failed for %s: %w", r.URL.Host, cause), reached}
	return &url.Error{Op: "Post", URL: r.URL.String(), Err: fmt.Errorf("DNS resolution failed for %s: %w", r.URL.Host, lookup)}
}

func deadDNSRequestError(r *fhttp.Request) error {
	return lookupRequestError(r, false, errors.New("i/o timeout"))
}

// leaveNetwork records the host's network as left this instant, the way a
// gateway change does (NotifyNetworkChange).
func leaveNetwork() {
	// Windows can give the attempt start and an immediate synthetic network
	// change the same timestamp. The real change has elapsed time between them.
	time.Sleep(2 * time.Millisecond)
	networkAvailability.Lock()
	networkAvailability.leftAt = time.Now()
	networkAvailability.Unlock()
}

// The field case: DNS dead for longer than three attempts take. The attempts
// that never reached VK are not counted, so the flow is still going when the
// network comes back — and gets the credential without a captcha.
func TestVKCallsOwnNetworkAttemptsAreNotCounted(t *testing.T) {
	withOwnNetworkBudget(t, time.Minute, time.Millisecond)
	const deadFor = 5 // > vkCallsAttempts
	calls := 0
	live := scriptedVKAnswer(t, "", nil)
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		calls++
		if calls <= deadFor {
			return nil, deadDNSRequestError(r)
		}
		return live.Do(r)
	}}
	user, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if err != nil || user != "u" {
		t.Fatalf("flow gave up on its own network: user=%q err=%v", user, err)
	}
}

// A bypass route that could not be set is our side too, and costs no attempt.
func TestVKCallsBypassRefusalIsOwnNetwork(t *testing.T) {
	withOwnNetworkBudget(t, 50*time.Millisecond, time.Millisecond)
	calls := 0
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		calls++
		return nil, &url.Error{Op: "Post", URL: r.URL.String(),
			Err: fmt.Errorf("%w: %w", errBypassRoute, errors.New("add route 87.240.129.133/32 via 192.168.1.1: element not found"))}
	}}
	_, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if !isVKCallsOwnNetwork(err) {
		t.Fatalf("bypass refusal not read as our network: %v", err)
	}
	if calls <= vkCallsAttempts {
		t.Fatalf("only %d attempts in the budget — own-network failures were counted", calls)
	}
}

// A lookup some resolver answered is the name's, whatever errno another
// server's socket carried: the first error can be an unreachable IPv6 resolver
// while the second one said SERVFAIL.
func TestVKCallsAnsweredLookupIsNotOwnNetwork(t *testing.T) {
	withOwnNetworkBudget(t, time.Minute, time.Millisecond)
	calls := 0
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		calls++
		return nil, lookupRequestError(r, true, fmt.Errorf("failed to dial UDP: %w", syscall.ENETUNREACH))
	}}
	_, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if calls != vkCallsAttempts || isVKCallsOwnNetwork(err) {
		t.Fatalf("answered lookup read as our network: calls=%d err=%v", calls, err)
	}
}

// Anything VK answered is VK's, even when the network changed while it did: a
// 5xx is a response, not a request lost on the way.
func TestVKCallsAnswerDuringNetworkChangeIsCounted(t *testing.T) {
	resetNetworkAvailabilityForTest()
	t.Cleanup(resetNetworkAvailabilityForTest)
	withOwnNetworkBudget(t, time.Minute, time.Millisecond)
	calls := 0
	client := scriptedHTTPClient{do: func(*fhttp.Request) (*fhttp.Response, error) {
		calls++
		leaveNetwork()
		return &fhttp.Response{StatusCode: 502, Body: io.NopCloser(strings.NewReader("bad gateway"))}, nil
	}}
	_, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if calls != vkCallsAttempts || isVKCallsOwnNetwork(err) || !isTransientVKCalls(err) {
		t.Fatalf("VK's 502 during a network change: calls=%d err=%v", calls, err)
	}
}

// ...while a request that got no response when the network was left under it is
// ours.
func TestVKCallsNoResponseDuringNetworkChangeIsOwnNetwork(t *testing.T) {
	resetNetworkAvailabilityForTest()
	t.Cleanup(resetNetworkAvailabilityForTest)
	withOwnNetworkBudget(t, 50*time.Millisecond, time.Millisecond)
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		leaveNetwork()
		return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: errors.New("read: connection timed out")}
	}}
	_, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if !isVKCallsOwnNetwork(err) {
		t.Fatalf("no response on a network left mid-attempt not read as ours: %v", err)
	}
}

// Past the budget the flow gives up with an error that is both ours (so
// fetchVkCreds weighs the legacy chain) and transient (so the worker just
// tries again later).
func TestVKCallsOwnNetworkBudgetBoundsTheWait(t *testing.T) {
	withOwnNetworkBudget(t, 40*time.Millisecond, 5*time.Millisecond)
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) { return nil, deadDNSRequestError(r) }}
	started := time.Now()
	_, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("budget of 40ms took %v", elapsed)
	}
	if !isVKCallsOwnNetwork(err) || !isTransientVKCalls(err) {
		t.Fatalf("want own-network and transient, got %v", err)
	}
}

// VK's own "come back later" still gets exactly vkCallsAttempts, whatever our
// network did in between, and the flow ending on it keeps the legacy fallback.
func TestVKCallsOwnNetworkDoesNotStretchVKRetries(t *testing.T) {
	withOwnNetworkBudget(t, time.Minute, time.Millisecond)
	calls, busy := 0, 0
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		calls++
		if calls%2 == 1 {
			return nil, deadDNSRequestError(r)
		}
		busy++
		return jsonHTTP(`{"error":{"error_code":6,"error_msg":"Too many requests"}}`), nil
	}}
	_, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if busy != vkCallsAttempts {
		t.Fatalf("VK asked to come back later %d times, want %d", busy, vkCallsAttempts)
	}
	if isVKCallsOwnNetwork(err) || !isTransientVKCalls(err) {
		t.Fatalf("a flow VK ended must keep the legacy fallback: %v", err)
	}
}

// fakeVKDNS answers login.vk.ru with legacyIP (none: silence) and keeps every
// other name silent, counting the servers asked per name.
func fakeVKDNS(t *testing.T, legacyIP string) (asked func(string) int) {
	t.Helper()
	var mu sync.Mutex
	count := map[string]int{}
	withFakeDNS(t, fakeServers("192.168.1.1", "8.8.8.8"),
		func(_ context.Context, domain string, _ DNSServer) ([]string, error) {
			mu.Lock()
			count[domain]++
			mu.Unlock()
			if domain == vkLegacyFirstHost && legacyIP != "" {
				return []string{legacyIP}, nil
			}
			return nil, errors.New("i/o timeout")
		})
	for _, host := range []string{vkCallsAPIHost, vkLegacyFirstHost} {
		hostCache.Forget(host)
	}
	t.Cleanup(func() {
		for _, host := range []string{vkCallsAPIHost, vkLegacyFirstHost} {
			hostCache.Forget(host)
		}
	})
	return func(domain string) int {
		mu.Lock()
		defer mu.Unlock()
		return count[domain]
	}
}

// stubLegacyChain stands in for the legacy chain and counts the calls.
func stubLegacyChain(t *testing.T) (calls func() int) {
	t.Helper()
	var n atomic.Int32
	prev := vkLegacyChain
	vkLegacyChain = func(context.Context, string, tlsclient.HttpClient, Profile) (string, string, []string, int, error) {
		n.Add(1)
		return "", "", nil, 0, errors.New("legacy stub")
	}
	t.Cleanup(func() { vkLegacyChain = prev })
	return func() int { return int(n.Load()) }
}

// End to end through the real client: with every resolver silent, the error
// survives the HTTP stack as ours, the legacy host is asked once — one walk of
// the two servers — and the legacy chain never starts.
func TestFetchVkCredsSkipsLegacyWhenOurNetworkIsDead(t *testing.T) {
	withOwnNetworkBudget(t, 50*time.Millisecond, 5*time.Millisecond)
	asked := fakeVKDNS(t, "")
	legacy := stubLegacyChain(t)

	_, _, _, _, err := fetchVkCreds(context.Background(), "link")
	if !isVKCallsOwnNetwork(err) {
		t.Fatalf("want an own-network error, got %v", err)
	}
	if asked(vkCallsAPIHost) == 0 {
		t.Fatalf("the captcha-free flow never resolved %s", vkCallsAPIHost)
	}
	if n := asked(vkLegacyFirstHost); n != 2 {
		t.Fatalf("%s asked %d times, want one walk of 2 servers", vkLegacyFirstHost, n)
	}
	if n := legacy(); n != 0 {
		t.Fatalf("legacy chain entered %d times on a dead network", n)
	}
}

// Silence about the VK Calls host alone — a resolver dropping that one name
// while it answers for login.vk.ru — leaves the legacy chain its chance, as
// before own-network failures were told apart.
func TestFetchVkCredsKeepsLegacyWhenItsHostResolves(t *testing.T) {
	withOwnNetworkBudget(t, 50*time.Millisecond, 5*time.Millisecond)
	fakeVKDNS(t, "127.0.0.1")
	legacy := stubLegacyChain(t)

	_, _, _, _, err := fetchVkCreds(context.Background(), "link")
	if n := legacy(); n != 1 {
		t.Fatalf("legacy chain entered %d times although %s resolves (%v)", n, vkLegacyFirstHost, err)
	}
}

// Audit 2026-10-16: login.vk.ru cached from earlier on this network passed for
// a resolver that answers now, and the legacy chain went out — captcha and all
// — over resolvers that had all gone silent. The legacy host is asked afresh,
// and the silence leaves the cached answer where it was.
func TestFetchVkCredsAsksForTheLegacyHostAfresh(t *testing.T) {
	withOwnNetworkBudget(t, 50*time.Millisecond, 5*time.Millisecond)
	asked := fakeVKDNS(t, "")
	hostCache.mu.Lock()
	hostCache.ips[vkLegacyFirstHost] = []string{"127.0.0.1"}
	hostCache.mu.Unlock()
	legacy := stubLegacyChain(t)

	_, _, _, _, err := fetchVkCreds(context.Background(), "link")
	if !isVKCallsOwnNetwork(err) {
		t.Fatalf("want an own-network error, got %v", err)
	}
	if n := asked(vkLegacyFirstHost); n != 2 {
		t.Fatalf("%s asked %d times, want one walk of 2 servers past the cached answer", vkLegacyFirstHost, n)
	}
	if n := legacy(); n != 0 {
		t.Fatalf("legacy chain entered %d times on resolvers that answer nobody", n)
	}
	hostCache.mu.Lock()
	cached := hostCache.ips[vkLegacyFirstHost]
	hostCache.mu.Unlock()
	if len(cached) != 1 || cached[0] != "127.0.0.1" {
		t.Errorf("the failed lookup left %v cached, want the earlier answer kept", cached)
	}
}

// Field log 23.10: a stop during the captcha-free flow read as that flow
// failing, "falling back to legacy captcha path", and the legacy chain was
// entered only to fail on the cancellation. login.vk.ru resolves here, so only
// the stop stands between the fetch and the legacy chain.
func TestFetchVkCredsStoppedMidFlowSkipsLegacy(t *testing.T) {
	withOwnNetworkBudget(t, 50*time.Millisecond, 5*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	withFakeDNS(t, fakeServers("192.168.1.1"),
		func(_ context.Context, domain string, _ DNSServer) ([]string, error) {
			if domain == vkLegacyFirstHost {
				return []string{"127.0.0.1"}, nil
			}
			cancel() // the stop lands while the flow resolves its first host
			return nil, errors.New("i/o timeout")
		})
	for _, host := range []string{vkCallsAPIHost, vkLegacyFirstHost} {
		hostCache.Forget(host)
	}
	t.Cleanup(func() {
		for _, host := range []string{vkCallsAPIHost, vkLegacyFirstHost} {
			hostCache.Forget(host)
		}
	})
	legacy := stubLegacyChain(t)

	_, _, _, _, err := fetchVkCreds(ctx, "link")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want the cancellation back, got %v", err)
	}
	if n := legacy(); n != 0 {
		t.Fatalf("legacy chain entered %d times after the stop", n)
	}
}
