/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// shortRelayUserTimeout gives the relay connections of one test a timeout the
// test can wait out.
func shortRelayUserTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := relayTCPUserTimeout
	relayTCPUserTimeout = d
	t.Cleanup(func() { relayTCPUserTimeout = prev })
}

// The hole this closes, end to end. A flow hangs while the stream carries
// traffic: the writer blocks in the socket, the keepalive queues up behind it,
// and with it the dead-stream detector — nothing in the client is left to notice.
// Nobody tears the session down here, unlike the close-budget test: the stream
// has to come back by itself, on a new connection, and the relay — which did
// nothing wrong — must not be blamed for the flow. Staged with a peer that stops
// reading, a closed window: Linux's TCP_USER_TIMEOUT gives that up as it gives
// up a lost segment; Windows' retransmission limit does not count probes of a
// closed window, and the client's own watch of its writes does
// (relayFlowConn.stuckFor).
func TestHungTCPFlowUnderLoadIsReplacedByItself(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	front := startStallingFront(t, relay.addr)
	overTCP(t)
	smallRelaySendBuffers(t)
	shortRelayUserTimeout(t, 2*time.Second)

	h := runWorkersAgainst(t, 120, 1, []string{front.addr})
	t.Cleanup(front.close) // before the harness waits for its worker
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })
	s := h.streams[0]

	front.frozen.Store(true)
	waitFor(t, "the writer to block on the full socket", 20*time.Second, func() bool {
		for full := false; !full; {
			select {
			case s.in <- packetPool.Get().([]byte)[:1200]:
			default:
				full = true
			}
		}
		time.Sleep(300 * time.Millisecond)
		return len(s.in) == cap(s.in)
	})
	front.frozen.Store(false) // the hung flow stays hung; the next one will flow

	// The kernel checks the limit when its probe timer fires, and that backs off:
	// a 2s limit is acted on within ~6s. The dead-stream detector, were it not
	// stuck behind the writer, would need 90.
	waitFor(t, "the stream back up on a new connection", 25*time.Second, func() bool {
		return front.accepted.Load() >= 2 && h.ready() == 1
	})

	serverHealthState.Lock()
	failures := healthEntryLocked(front.addr).failures
	serverHealthState.Unlock()
	if failures != 0 {
		t.Fatalf("the relay took %d strike(s) for a flow that timed out", failures)
	}
}

// errConn fails its reads and writes with whatever it was given.
type errConn struct {
	net.Conn
	readErr, writeErr error
}

func (c *errConn) Read([]byte) (int, error)  { return 0, c.readErr }
func (c *errConn) Write([]byte) (int, error) { return 0, c.writeErr }

// timedOutFlow is the error the system gives up a flow with, as this OS spells
// it (relayFlowGaveUpErrnos).
func timedOutFlow(op string) error {
	return &net.OpError{Op: op, Net: "tcp", Err: os.NewSyscallError(op, relayFlowGaveUpErrnos[0])}
}

// The system's verdict arrives once, to whichever call meets it first — pion's
// read loop as often as our writer — so both directions have to note it. And
// only that verdict: a deadline of our own (the close budget) and a plain broken
// pipe or reset are other things.
func TestRelayFlowNotesTheSystemGivingUpOnEitherSide(t *testing.T) {
	others := []error{
		os.ErrDeadlineExceeded,
		&net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", relayResetErrnos[len(relayResetErrnos)-1])},
		&net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", relayResetErrnos[0])},
	}

	for _, side := range []string{"read", "write"} {
		inner := &errConn{readErr: others[0], writeErr: others[0]}
		raw := &splitFirstWriteConn{Conn: &relayFlowConn{Conn: inner, gaveUp: make(chan struct{})}}
		for _, err := range others {
			inner.readErr, inner.writeErr = err, err
			raw.Read(nil)
			raw.Write(nil)
			if relayFlowTimedOut(raw) {
				t.Fatalf("%v was taken for the system giving the flow up", err)
			}
		}
		if side == "read" {
			inner.readErr = timedOutFlow("read")
			raw.Read(nil)
		} else {
			inner.writeErr = timedOutFlow("write")
			raw.Write(nil)
		}
		select {
		case <-relayFlowGaveUp(raw):
		default:
			t.Fatalf("the flow given up on %s went unnoticed", side)
		}
		raw.Read(nil) // and again: the channel is closed once
		raw.Write(nil)
	}

	// Over UDP there is no flow: nothing to wait for, and nothing timed out.
	if relayFlowGaveUp(&net.UDPConn{}) != nil || relayFlowTimedOut(&net.UDPConn{}) {
		t.Fatal("a UDP conn was treated as a flow")
	}
}

// cuedTimeoutConn is a healthy connection whose reads, on cue, report the
// system giving the flow up — once, the way the system does. Its writes keep
// working: what is staged is only who got to hear the verdict.
type cuedTimeoutConn struct {
	net.Conn
	cue   chan struct{}
	fired bool
}

func (c *cuedTimeoutConn) Read(p []byte) (int, error) {
	for {
		if !c.fired {
			select {
			case <-c.cue:
				c.fired = true
				return 0, timedOutFlow("read")
			default:
			}
		}
		c.Conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, err := c.Conn.Read(p)
		if ne, ok := err.(net.Error); ok && ne.Timeout() && n == 0 {
			continue
		}
		return n, err
	}
}

// The verdict can go to pion's read loop, which drops it and stops reading —
// and on an idle tunnel no write of ours follows to break on the dead socket.
// The session must end on the verdict itself, not wait for the dead-stream
// detector a minute and a half later.
func TestFlowGivenUpUnderThePionReaderEndsTheSessionAtOnce(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)

	cue := make(chan struct{})
	prev := dialRelayTCP
	first := true
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
		c, err := prev(ctx, d, addr)
		if err != nil || !first {
			return c, err
		}
		first = false
		return &cuedTimeoutConn{Conn: c, cue: cue}, nil
	}
	t.Cleanup(func() { dialRelayTCP = prev })

	h := runWorkersAgainst(t, 121, 1, []string{relay.addr})
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })

	close(cue)
	waitFor(t, "the stream back up on a new connection", 8*time.Second, func() bool {
		return relay.ln.accepted.Load() >= 2 && h.ready() == 1
	})
}

// A write waiting in the socket is what the client's own watch times: from the
// oldest under way, restarted by any that returns, nothing while none waits —
// and given up, the flow reads as given up by the system and its connection is
// closed under the writer.
func TestAStuckWriteIsTimedAndGivenUp(t *testing.T) {
	block := make(chan struct{})
	inner := &blockingWriteConn{release: block}
	flow := &relayFlowConn{Conn: inner, gaveUp: make(chan struct{})}
	if d := flow.stuckFor(time.Now()); d != 0 {
		t.Fatalf("no write under way, stuck for %v", d)
	}
	done := make(chan error, 1)
	go func() {
		_, err := flow.Write([]byte("x"))
		done <- err
	}()
	waitFor(t, "the write to wait in the socket", time.Second, func() bool {
		return flow.stuckFor(time.Now()) > 0
	})
	if d := flow.stuckFor(time.Now().Add(time.Minute)); d < time.Minute {
		t.Fatalf("a write a minute in the socket: stuck for %v", d)
	}
	flow.giveUp()
	if !relayFlowTimedOut(flow) {
		t.Fatal("the flow given up does not read as given up")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the write under a closed connection succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("giving the flow up left the writer waiting")
	}
	if d := flow.stuckFor(time.Now()); d != 0 {
		t.Fatalf("no write under way after the give-up, stuck for %v", d)
	}
}

// blockingWriteConn's writes wait until it is closed.
type blockingWriteConn struct {
	net.Conn
	release chan struct{}
	once    sync.Once
}

func (c *blockingWriteConn) Write(p []byte) (int, error) {
	<-c.release
	return 0, net.ErrClosed
}

func (c *blockingWriteConn) Close() error {
	c.once.Do(func() { close(c.release) })
	return nil
}
