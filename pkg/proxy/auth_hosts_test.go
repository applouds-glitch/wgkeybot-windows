/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// A start that took its credentials from the cache resolved nothing, and the
// VPN got no bypass route for any auth host. Pre-resolution must cover the
// whole list on its own, from an empty cache.
func TestResolveAuthHostsFillsTheBypassList(t *testing.T) {
	var mu sync.Mutex
	want := map[string]string{}
	for i, host := range authHosts {
		want[host] = fmt.Sprintf("198.51.100.%d", i+1)
	}
	asked := map[string]int{}
	withFakeDNS(t, fakeServers("192.0.2.53"), func(_ context.Context, domain string, _ DNSServer) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		asked[domain]++
		return []string{want[domain]}, nil
	})
	ClearCache()
	t.Cleanup(ClearCache)

	ResolveAuthHosts(context.Background())

	got := map[string]bool{}
	for _, ip := range ResolvedHostIPs() {
		got[ip] = true
	}
	for host, ip := range want {
		if !got[ip] {
			t.Errorf("%s (%s) has no bypass address", host, ip)
		}
	}

	// A second pass is served by the cache: reconnect after reconnect does not
	// repeat the lookups.
	ResolveAuthHosts(context.Background())
	mu.Lock()
	defer mu.Unlock()
	for host, n := range asked {
		if n != 1 {
			t.Errorf("%s looked up %d times", host, n)
		}
	}
}

// DNS that does not answer must not hold the connect: the pre-resolution gives
// up with its context, and whatever did resolve is still there.
func TestResolveAuthHostsGivesUpWithItsContext(t *testing.T) {
	withFakeDNS(t, fakeServers("192.0.2.53"), func(ctx context.Context, domain string, _ DNSServer) ([]string, error) {
		if domain == "login.vk.ru" {
			return []string{"198.51.100.1"}, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ClearCache()
	t.Cleanup(ClearCache)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	ResolveAuthHosts(ctx)
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("pre-resolution held the connect for %v", took)
	}
	ips := ResolvedHostIPs()
	if len(ips) != 1 || ips[0] != "198.51.100.1" {
		t.Fatalf("bypass list %v, want the one host that resolved", ips)
	}
}

// The VK dial may connect to any address of an answer, so the bypass routes
// (ResolvedHostIPs) have to cover every A record, not just the preferred one.
func TestResolvedHostIPsCoverEveryARecord(t *testing.T) {
	ClearCache()
	t.Cleanup(ClearCache)
	hostCache.mu.Lock()
	hostCache.ips["api.vk.ru"] = []string{"87.240.129.140", "87.240.137.206"}
	hostCache.ips["login.vk.ru"] = []string{"87.240.137.206", "93.186.225.205"}
	hostCache.mu.Unlock()

	got := map[string]bool{}
	for _, ip := range ResolvedHostIPs() {
		got[ip] = true
	}
	for _, want := range []string{"87.240.129.140", "87.240.137.206", "93.186.225.205"} {
		if !got[want] {
			t.Errorf("%s missing from the bypass IPs %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("bypass IPs %v, want three distinct addresses", got)
	}
}
