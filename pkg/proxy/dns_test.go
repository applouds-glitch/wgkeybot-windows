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
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// withFakeDNS swaps the active server list and the resolver seam for one test,
// restoring both — and the last-successful bias, which the race writes — after.
func withFakeDNS(t *testing.T, servers []DNSServer, fn func(context.Context, string, DNSServer) ([]string, error)) {
	t.Helper()

	prevServers, prevFn := dnsServers, resolveAnyFn
	lastSuccessfulMu.Lock()
	prevIdx := lastSuccessfulIndex
	lastSuccessfulIndex = 0
	lastSuccessfulMu.Unlock()

	dnsServers, resolveAnyFn = servers, fn

	t.Cleanup(func() {
		dnsServers, resolveAnyFn = prevServers, prevFn
		lastSuccessfulMu.Lock()
		lastSuccessfulIndex = prevIdx
		lastSuccessfulMu.Unlock()
	})
}

func fakeServers(ips ...string) []DNSServer {
	servers := make([]DNSServer, 0, len(ips))
	for _, ip := range ips {
		servers = append(servers, DNSServer{Type: DNSPlain, IP: ip})
	}
	return servers
}

// The healthy case must look exactly as it did before hedging: one query to one
// server. Racing a resolver that answers in milliseconds would multiply DNS
// traffic for nothing.
func TestResolveWithOrderedServersLeavesHealthyServerAlone(t *testing.T) {
	var mu sync.Mutex
	var queried []string

	withFakeDNS(t, fakeServers("192.168.1.1", "77.88.8.8", "8.8.8.8"),
		func(ctx context.Context, domain string, s DNSServer) ([]string, error) {
			mu.Lock()
			queried = append(queried, s.IP)
			mu.Unlock()
			return []string{"93.186.237.1"}, nil
		})

	ips, err := resolveWithOrderedServers(context.Background(), "login.vk.ru")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if len(ips) != 1 || ips[0] != "93.186.237.1" {
		t.Fatalf("got %q, want 93.186.237.1", ips)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(queried) != 1 {
		t.Fatalf("healthy first server was raced: queried %v", queried)
	}
}

// A server that has stopped answering used to cost its full timeout before the
// next one was even tried. Now the next one joins after the hedge — but not
// before it, or the head start the last-successful bias buys would be gone.
func TestResolveWithOrderedServersHedgesPastHungServer(t *testing.T) {
	withFakeDNS(t, fakeServers("192.168.1.1", "8.8.8.8"),
		func(ctx context.Context, domain string, s DNSServer) ([]string, error) {
			if s.IP == "192.168.1.1" {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return []string{"93.186.237.1"}, nil
		})

	start := time.Now()
	ips, err := resolveWithOrderedServers(context.Background(), "login.vk.ru")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if len(ips) != 1 || ips[0] != "93.186.237.1" {
		t.Fatalf("got %q, want the second server's answer", ips)
	}
	if elapsed+time.Millisecond < dnsHedgeDelay {
		t.Fatalf("second server started after %v, before the %v hedge", elapsed, dnsHedgeDelay)
	}
	if elapsed > 2*dnsHedgeDelay {
		t.Fatalf("hung server held the lookup up for %v", elapsed)
	}
}

// A server that has already said no is not worth waiting the stagger out for,
// so a list of fast failures is walked at the speed of the failures.
func TestResolveWithOrderedServersBringsNextForwardOnFailure(t *testing.T) {
	withFakeDNS(t, fakeServers("192.168.1.1", "77.88.8.8", "8.8.8.8"),
		func(ctx context.Context, domain string, s DNSServer) ([]string, error) {
			if s.IP == "8.8.8.8" {
				return []string{"93.186.237.1"}, nil
			}
			return nil, errors.New("i/o timeout")
		})

	start := time.Now()
	ips, err := resolveWithOrderedServers(context.Background(), "login.vk.ru")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if len(ips) != 1 || ips[0] != "93.186.237.1" {
		t.Fatalf("got %q, want the third server's answer", ips)
	}
	if elapsed >= dnsHedgeDelay {
		t.Fatalf("two instant failures took %v — the next server waited out the hedge", elapsed)
	}
}

// Every server failing is still an error, and it carries a cause now.
func TestResolveWithOrderedServersReportsTotalFailure(t *testing.T) {
	withFakeDNS(t, fakeServers("192.168.1.1", "8.8.8.8"),
		func(ctx context.Context, domain string, s DNSServer) ([]string, error) {
			return nil, errors.New("i/o timeout")
		})

	if _, err := resolveWithOrderedServers(context.Background(), "login.vk.ru"); err == nil {
		t.Fatal("expected an error when every server failed")
	}
}

// Two credential fetches asking for the same VK host at the same time — the
// shape vkSemaphore allows — must cost one walk of the server list, not two.
func TestResolveCollapsesConcurrentLookups(t *testing.T) {
	var lookups atomic.Int32
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	withFakeDNS(t, fakeServers("192.168.1.1"),
		func(ctx context.Context, domain string, s DNSServer) ([]string, error) {
			lookups.Add(1)
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			return []string{"93.186.237.1"}, nil
		})

	cache := &DnsCache{
		ips:      make(map[string][]string),
		inflight: make(map[string]*dnsLookup),
	}

	const callers = 5
	results := make([]string, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = cache.Resolve(context.Background(), "login.vk.ru")
		}(i)
	}

	// Let the leader get in, then give the followers time to queue behind it.
	<-started
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := lookups.Load(); got != 1 {
		t.Fatalf("%d callers produced %d lookups, want 1", callers, got)
	}
	for i := 0; i < callers; i++ {
		if errs[i] != nil {
			t.Fatalf("caller %d failed: %v", i, errs[i])
		}
		if results[i] != "93.186.237.1" {
			t.Fatalf("caller %d got %q", i, results[i])
		}
	}
	if cached, ok := cache.ips["login.vk.ru"]; !ok || len(cached) != 1 || cached[0] != "93.186.237.1" {
		t.Fatalf("answer not cached: %q (present=%v)", cached, ok)
	}
	if len(cache.inflight) != 0 {
		t.Fatalf("inflight not cleaned up: %v", cache.inflight)
	}
}

// A failed lookup must not be cached as an answer, and must not leave the name
// wedged in the inflight map either.
func TestResolveDoesNotCacheFailures(t *testing.T) {
	withFakeDNS(t, fakeServers("192.168.1.1"),
		func(ctx context.Context, domain string, s DNSServer) ([]string, error) {
			return nil, errors.New("i/o timeout")
		})

	cache := &DnsCache{
		ips:      make(map[string][]string),
		inflight: make(map[string]*dnsLookup),
	}
	if _, err := cache.Resolve(context.Background(), "login.vk.ru"); err == nil {
		t.Fatal("expected an error")
	}
	if len(cache.ips) != 0 {
		t.Fatalf("failure was cached: %v", cache.ips)
	}
	if len(cache.inflight) != 0 {
		t.Fatalf("inflight not cleaned up: %v", cache.inflight)
	}
}

// Silence from every server is the machine's network; one server that
// answered — even only to say SERVFAIL — makes the failure the name's. A
// refused connection is no answer: a firewall on the way can send that just as
// well.
func TestResolveTellsSilenceFromAnswer(t *testing.T) {
	cases := []struct {
		name    string
		answer  func(DNSServer) ([]string, error)
		reached bool
	}{
		{"every query timed out", func(DNSServer) ([]string, error) { return nil, errors.New("i/o timeout") }, false},
		{"the bypass route was refused for every server", func(DNSServer) ([]string, error) {
			return nil, fmt.Errorf("DNS bypass route: %w", errors.New("add route: the network location cannot be reached"))
		}, false},
		{"one server said SERVFAIL", func(s DNSServer) ([]string, error) {
			if s.IP == "8.8.8.8" {
				return nil, dnsReachedf("DNS error: rcode=2")
			}
			return nil, errors.New("i/o timeout")
		}, true},
		{"one server answered with nothing", func(s DNSServer) ([]string, error) {
			if s.IP == "8.8.8.8" {
				return nil, nil
			}
			return nil, errors.New("i/o timeout")
		}, true},
		{"one server refused the connection", func(s DNSServer) ([]string, error) {
			if s.IP == "8.8.8.8" {
				return nil, fmt.Errorf("failed to connect to DoT server: %w", syscall.ECONNREFUSED)
			}
			return nil, errors.New("i/o timeout")
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFakeDNS(t, fakeServers("192.168.1.1", "8.8.8.8"),
				func(_ context.Context, _ string, s DNSServer) ([]string, error) { return tc.answer(s) })
			_, err := resolveWithOrderedServers(context.Background(), "internal.api.vk.ru")
			reached, isLookup := dnsLookupOutcome(err)
			if !isLookup {
				t.Fatalf("not a lookup failure: %v", err)
			}
			if reached != tc.reached {
				t.Fatalf("reached = %v, want %v (%v)", reached, tc.reached, err)
			}
			if !strings.Contains(err.Error(), "all DNS servers failed for internal.api.vk.ru") {
				t.Fatalf("message changed: %v", err)
			}
		})
	}
}

// Every way parseDNSResponse refuses a reply is a server reached.
func TestParseDNSResponseFailuresReachedAServer(t *testing.T) {
	nxdomain := make([]byte, 12)
	nxdomain[2], nxdomain[3] = 0x81, 0x83 // response, recursion desired/available, rcode 3
	empty := make([]byte, 12)
	empty[2], empty[3] = 0x81, 0x80 // response, rcode 0, no answers
	for name, reply := range map[string][]byte{
		"too short":    {0x00, 0x01},
		"not response": make([]byte, 12),
		"NXDOMAIN":     nxdomain,
		"no answers":   empty,
	} {
		if _, err := parseDNSResponse(reply, "vk.ru"); err == nil || !serverReached(err) {
			t.Errorf("%s: %v is not marked as a server reached", name, err)
		}
	}
}

// A DoT or DoH connection that was accepted and then hung up before the TLS
// handshake proved anything is no answer: a captive portal or a middlebox takes
// connections to 443 and 853 just as readily. Played against a local listener
// that accepts and closes.
func TestEncryptedDNSAcceptedConnectionIsNoAnswer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	prevDoH, prevDoT := dohPort, dotPort
	dohPort, dotPort = port, port
	t.Cleanup(func() { dohPort, dotPort = prevDoH, prevDoT })

	if _, err := resolveDoTWithServer(context.Background(), "vk.ru", "127.0.0.1", "dns.example"); err == nil || serverReached(err) {
		t.Errorf("DoT: %v read as an answer", err)
	}
	if _, err := resolveDoHWithServer(context.Background(), "vk.ru", "127.0.0.1", "dns.example"); err == nil || serverReached(err) {
		t.Errorf("DoH: %v read as an answer", err)
	}
}

// A cancelled lookup must come out as the cancellation, never as a network that
// answered nothing: the live follower of a shared lookup takes it over only on a
// context error. Here the select nearly always wakes on the cancellation; the
// guard after the loop covers the rarer order — the last result winning the
// select after the context was cancelled — which a host test cannot force, so
// this only keeps the common order honest.
func TestResolveCancellationIsNeverSilence(t *testing.T) {
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		withFakeDNS(t, fakeServers("192.168.1.1"),
			func(context.Context, string, DNSServer) ([]string, error) {
				cancel()
				return nil, errors.New("use of closed network connection")
			})
		_, err := resolveWithOrderedServers(ctx, "internal.api.vk.ru")
		if _, isLookup := dnsLookupOutcome(err); isLookup || !errors.Is(err, context.Canceled) {
			t.Fatalf("round %d: cancelled lookup came out as %v", i, err)
		}
	}
}
