/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

type recordingRouter struct {
	mu   sync.Mutex
	seen []string
	fail error
}

func (r *recordingRouter) EnsureBypassRoute(ip string) error {
	r.mu.Lock()
	r.seen = append(r.seen, ip)
	r.mu.Unlock()
	return r.fail
}

func (r *recordingRouter) routes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// The route is asked for before the socket is opened, with the bare address:
// the router installs host routes, and a name would be nothing to route.
func TestDialOutsideTunnelRoutesEveryAddressBeforeDialing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	r := &recordingRouter{}
	SetBypassRouter(r)
	t.Cleanup(func() { ClearBypassRouter(r) })

	conn, err := DialOutsideTunnel(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	if got := r.routes(); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("router asked for %v, want the dialled address once", got)
	}
	if err := ensureBypass("relay.example:3478"); err != nil || len(r.routes()) != 1 {
		t.Fatalf("a name was routed or refused: %v %v", err, r.routes())
	}
}

// A route the host cannot install means the dial must not go into the tunnel.
func TestDialOutsideTunnelStopsWhenTheRouteFails(t *testing.T) {
	boom := errors.New("route table busy")
	r := &recordingRouter{fail: boom}
	SetBypassRouter(r)
	t.Cleanup(func() { ClearBypassRouter(r) })

	if _, err := DialOutsideTunnel(context.Background(), "tcp", "127.0.0.1:9"); !errors.Is(err, boom) {
		t.Fatalf("dial went ahead: %v", err)
	}
}

// Without a router (SOCKS mode) the dials are plain; and a Manager clearing
// the router removes only its own.
func TestBypassRouterOwnership(t *testing.T) {
	first, second := &recordingRouter{}, &recordingRouter{}
	SetBypassRouter(first)
	SetBypassRouter(second)
	ClearBypassRouter(first)
	if err := ensureBypass("198.51.100.1:443"); err != nil || len(second.routes()) != 1 || len(first.routes()) != 0 {
		t.Fatalf("the successor's router was taken with the predecessor: %v %v %v", err, first.routes(), second.routes())
	}
	ClearBypassRouter(second)
	if err := ensureBypass("198.51.100.2:443"); err != nil || len(second.routes()) != 1 {
		t.Fatalf("a cleared router was still consulted: %v %v", err, second.routes())
	}
}
