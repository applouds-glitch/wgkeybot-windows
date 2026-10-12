/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wgkeybot/windows/pkg/proxy/srtpwrap"
)

// srtpTestPeer is the far end of an SRTP stream: it completes the handshake of
// whoever dials it through a relay and drains what they send.
func srtpTestPeer(t *testing.T) *net.UDPAddr {
	t.Helper()
	srv, err := srtpwrap.Listen(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("srtp peer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var readers sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		srv.Close()
		readers.Wait()
	})
	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			c, err := srv.Accept(ctx)
			if err != nil {
				return
			}
			// The server closes no session of its own accord, and a reader of one
			// waits for ever.
			stop := context.AfterFunc(ctx, func() { c.Close() })
			readers.Add(1)
			go func() {
				defer readers.Done()
				defer stop()
				defer c.Close()
				buf := make([]byte, 2048)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	return srv.Addr().(*net.UDPAddr)
}

// The blackhole watchdog, over UDP: nothing is wrong with the socket, so no
// read or write of the session's own fails — closing the relay is all that
// ends it, and the session has to end there and then, with the watchdog's
// reason as its error. The SRTP demux used to spin on the closed relay's
// error instead, a core at full load, and the session outlived it.
func TestBlackholedAllocationUnderSRTPEndsTheSessionAtOnce(t *testing.T) {
	resetNetworkAvailabilityForTest()
	resetServerHealth()
	t.Cleanup(resetServerHealth)
	pc, _ := startInitialRefusalServer(t, 0, 0) // refuses nothing
	addr := pc.LocalAddr().String()
	cfg := WorkerGroupConfig{GroupID: 126, Link: "test", UseUDP: true, PeerType: "srtp", PeerAddr: srtpTestPeer(t)}

	s, _ := newNoDTLSTestStream(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, raw, relayConn, rtt, perm, err := dialAndAllocate(ctx, s, t.Name(), "pass", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() {
		ended <- s.runSession(ctx, winner{client: client, raw: raw, relay: relayConn, addr: addr, rtt: rtt, perm: perm}, cfg)
	}()
	waitFor(t, "an SRTP stream over UDP", 5*time.Second, func() bool { return s.ready.Load() })

	perm.markDead("refresh allocation failed: test")
	select {
	case err := <-ended:
		if err == nil || !strings.Contains(err.Error(), "TURN blackhole") {
			t.Fatalf("the session ended with %v, want the watchdog's reason", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the session is still running 3s after the watchdog closed its relay")
	}
}
