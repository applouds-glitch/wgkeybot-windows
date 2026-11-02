//go:build windows

/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The limit has to be on the socket the TURN traffic is written through — and
// the production one, not whatever a test left behind.
func TestRelayTCPConnectionCarriesTheRetransmissionLimit(t *testing.T) {
	if relayTCPUserTimeout != 30*time.Second {
		t.Fatalf("relayTCPUserTimeout is %v, want 30s: the reasoning beside it is for that number", relayTCPUserTimeout)
	}
	ln := listenTCPRelay(t)
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	conn, err := connectRelayTCP(context.Background(), &net.Dialer{}, ln.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	tc := relayTCPConn(conn)
	if tc == nil {
		t.Fatal("no TCP connection under the relay conn")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got time.Duration
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		var ms int
		if ms, optErr = windows.GetsockoptInt(h, windows.IPPROTO_TCP, windows.TCP_MAXRTMS); optErr == nil {
			got = time.Duration(ms) * time.Millisecond
			return
		}
		var s int
		s, optErr = windows.GetsockoptInt(h, windows.IPPROTO_TCP, windows.TCP_MAXRT)
		got = time.Duration(s) * time.Second
	}); err != nil || optErr != nil {
		t.Fatalf("getsockopt: %v / %v", err, optErr)
	}
	if got != relayTCPUserTimeout {
		t.Fatalf("the retransmission limit on the relay connection is %v, want %v", got, relayTCPUserTimeout)
	}
	if relayFlowGaveUp(conn) == nil {
		t.Fatal("the relay connection does not report its flow being given up")
	}
}

// The sampler against a real connection: the counters the summary is built
// from have to be the system's, not zeros that happen to parse.
func TestReadRelaySocketReadsTheSystemCounters(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Less comes back than went out, so that the two directions cannot be
		// mistaken for one another.
		if _, err := io.ReadFull(c, make([]byte, 20<<10)); err == nil {
			c.Write(make([]byte, 5<<10))
		}
		io.Copy(io.Discard, c)
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	const sent, echoed = 20 << 10, 5 << 10
	if _, err := c.Write(make([]byte, sent)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, echoed)); err != nil {
		t.Fatal(err)
	}

	s, ok := readRelaySocket(c.(*net.TCPConn))
	if !ok {
		t.Fatal("the socket could not be sampled: SIO_TCP_INFO refused")
	}
	if !s.episodic || s.acked < sent || s.received < echoed || s.received >= sent || s.sndMSS == 0 || s.timeoutEpisodes != 0 {
		t.Fatalf("after %d bytes out and %d back: %+v", sent, echoed, s)
	}
}
