/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"sync"
	"time"
)

// authHosts are the VK/OK hosts a credential fetch talks to: the captcha-free
// VK Calls flow (api/internal.api.vk.ru, calls.okcdn.ru), the legacy token
// chain (login/api.vk.ru), and the captcha solver, whose page, API and static
// hosts follow the redirect_uri (id/api/st.vk.ru, or their vk.com twins).
var authHosts = []string{
	"login.vk.ru",
	"api.vk.ru",
	"internal.api.vk.ru",
	"id.vk.ru",
	"st.vk.ru",
	"vk.ru",
	"calls.okcdn.ru",
	"id.vk.com",
	"api.vk.com",
	"vk.com",
}

const (
	// authHostsBudget bounds the whole pre-resolution. It runs on the connect
	// path, and a name that has not resolved by then is resolved on first use
	// like any other — it just gets no bypass route.
	authHostsBudget = 3 * time.Second
	// authHostsParallel keeps the burst of lookups small; each one is already a
	// hedged race over several servers.
	authHostsParallel = 4
)

// ResolveAuthHosts puts every auth host into the bootstrap DNS cache, whose
// addresses become the VPN's bypass routes (ResolvedHostIPs).
//
// The cache used to be filled only by the fetches themselves. StartProxy clears
// it, and a start that finds its credentials cached makes no request to VK — so
// after any reconnect within the credential TTL (the watchdog's, a config
// refresh's) the cache held nothing, no auth host got a bypass route, and the
// next re-fetch went into the tunnel: fine while the tunnel carries traffic,
// and the "creds need the tunnel, the tunnel needs creds" loop when it does
// not — which is exactly when a re-fetch happens. Resolving the fixed list here
// makes the routes independent of whether this start happened to fetch.
func ResolveAuthHosts(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, authHostsBudget)
	defer cancel()

	sem := make(chan struct{}, authHostsParallel)
	var wg sync.WaitGroup
	for _, host := range authHosts {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			turnLog("[DNS] Auth hosts: budget of %v spent before %s", authHostsBudget, host)
			return
		}
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			if _, err := hostCache.Resolve(ctx, host); err != nil {
				turnLog("[DNS] Auth host %s not resolved: %v", host, err)
			}
		}(host)
	}
	wg.Wait()
}
