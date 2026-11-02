/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

// countingListener counts the connections a TCP relay accepted: whether a relay
// was dialed at all is what several tests here turn on.
type countingListener struct {
	net.Listener
	accepted atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

type tcpTestRelay struct {
	addr string
	ln   *countingListener
}

func listenTCPRelay(t *testing.T) *countingListener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return &countingListener{Listener: ln}
}

func startTCPTestRelay(t *testing.T, ln *countingListener) *tcpTestRelay {
	t.Helper()
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "tcp-relay-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "tcp-relay-test", "pass"), true
		},
		ListenerConfigs: []turn.ListenerConfig{{
			Listener:              ln,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return &tcpTestRelay{addr: ln.Addr().String(), ln: ln}
}

// twoTCPRelayListeners returns two listeners in the order the session would
// dial their addresses, like twoRelaySockets does for UDP.
func twoTCPRelayListeners(t *testing.T) (first, second *countingListener) {
	t.Helper()
	a, b := listenTCPRelay(t), listenTCPRelay(t)
	if assignRelays([]string{a.Addr().String(), b.Addr().String()}, 0, time.Now())[0] == a.Addr().String() {
		return a, b
	}
	return b, a
}

// benchOverTCP makes the workers of the bench dial over TCP: the tray's choice
// as the config carries it (relayOverTCP).
var benchOverTCP atomic.Bool

// overTCP runs the bench's workers over TCP for one test.
func overTCP(t *testing.T) {
	t.Helper()
	benchOverTCP.Store(true)
	t.Cleanup(func() { benchOverTCP.Store(false) })
}

// benchUseUDP is the UseUDP the bench's workers run with.
func benchUseUDP() bool { return !benchOverTCP.Load() }

// hangConnectsTo makes the TCP connect to addr hang until it is cancelled or
// times out — a blackholed SYN — and reports the timeout each dial was given.
func hangConnectsTo(t *testing.T, addr string) *atomic.Int64 {
	t.Helper()
	var timeout atomic.Int64
	prev := dialRelayTCP
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, to string) (net.Conn, error) {
		timeout.Store(int64(d.Timeout))
		if to != addr {
			return prev(ctx, d, to)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(d.Timeout):
			return nil, errors.New("i/o timeout")
		}
	}
	t.Cleanup(func() { dialRelayTCP = prev })
	return &timeout
}

// The whole path over TCP: connect, Allocate, and the relay proof — a round trip
// through the relay to the peer and back, framed over the stream.
func TestWorkerReachesTheRelayOverTCP(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t)) // listens on TCP only
	overTCP(t)

	h := runWorkersAgainst(t, 111, 1, []string{relay.addr})
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })
	if n := relay.ln.accepted.Load(); n != 1 {
		t.Fatalf("the relay accepted %d TCP connection(s), want 1", n)
	}
	if !h.streams[0].overTCP.Load() {
		t.Fatal("the stream does not know its session runs over TCP")
	}
}

// The config decides, and nothing else: a running proxy's transport changes
// only by restarting it.
func TestRelayTransportIsTheConfigs(t *testing.T) {
	if relayOverTCP(WorkerGroupConfig{UseUDP: true}) {
		t.Fatal("UseUDP dials over TCP")
	}
	if !relayOverTCP(WorkerGroupConfig{UseUDP: false}) {
		t.Fatal("a config without UseUDP dials over UDP")
	}
}

// Over TCP a dark relay is silent a step earlier than over UDP: the connect
// hangs, and no Allocate is ever sent. The connect has to have a head start of
// its own, or the attempt sits out the whole connect timeout before the
// answering relay is even dialed.
func TestSilentTCPConnectIsRacedAfterTheHeadStart(t *testing.T) {
	first, second := twoTCPRelayListeners(t)
	live := startTCPTestRelay(t, second)
	dark := first.Addr().String()
	overTCP(t)
	timeout := hangConnectsTo(t, dark)

	started := time.Now()
	h := runWorkersAgainst(t, 112, 1, []string{dark, live.addr})

	waitFor(t, "a stream on the answering relay", relayHeadStart+3*time.Second, func() bool { return h.ready() == 1 })
	if took := time.Since(started); took < relayHeadStart {
		t.Fatalf("up after %v: the second relay was dialed before the head start ran out", took)
	}
	if got := h.streams[0].serverAddr; got != live.addr {
		t.Fatalf("session runs on %s, want the answering relay %s", got, live.addr)
	}
	if got := time.Duration(timeout.Load()); got != relayTCPConnectTimeout {
		t.Fatalf("TCP connect was given %v, want %v", got, relayTCPConnectTimeout)
	}
}

// silentTCPRelay takes the connections ln is given and reads what they are
// sent, and answers nothing: a relay whose Allocate goes unanswered over a flow
// it accepted.
func silentTCPRelay(ln *countingListener) {
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
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
}

// The Allocate over a flow the relay accepted has its own head start: past it
// the rest are raced, and the silent Allocate runs on — not cut short by the
// race, which would leave a ghost if its answer were on the way — to its own
// end, where it is held against the relay that stayed silent while another
// answered.
func TestSilentTCPAllocateIsRacedAfterTheHeadStart(t *testing.T) {
	prev := relayTCPAllocateTimeout
	relayTCPAllocateTimeout = 2 * relayHeadStart
	t.Cleanup(func() { relayTCPAllocateTimeout = prev })
	first, second := twoTCPRelayListeners(t)
	silentTCPRelay(first)
	silent := first.Addr().String()
	live := startTCPTestRelay(t, second)
	overTCP(t)

	started := time.Now()
	h := runWorkersAgainst(t, 117, 1, []string{silent, live.addr})
	waitFor(t, "a stream on the answering relay", relayHeadStart+3*time.Second, func() bool { return h.ready() == 1 })
	if took := time.Since(started); took < relayHeadStart {
		t.Fatalf("up after %v: the second relay was dialed before the head start ran out", took)
	}
	if got := h.streams[0].serverAddr; got != live.addr {
		t.Fatalf("session runs on %s, want the answering relay %s", got, live.addr)
	}
	waitFor(t, "the silent relay's strike", relayTCPAllocateTimeout+2*time.Second, func() bool {
		serverHealthState.Lock()
		defer serverHealthState.Unlock()
		e := serverHealthState.byAddr[silent]
		return e != nil && e.failures > 0
	})
}

// An Allocate over TCP that goes unanswered gives its slot up past the head
// start, the request running on: the slots are the process's, and a first
// relay that connected after the race had fanned out started no clock of it
// (Codex review of the Windows port, 2026-10-23).
func TestATCPAllocateGivesItsSlotUpPastTheHeadStart(t *testing.T) {
	prev := relayTCPAllocateTimeout
	relayTCPAllocateTimeout = 3 * relayHeadStart
	t.Cleanup(func() { relayTCPAllocateTimeout = prev })
	hole := listenTCPRelay(t)
	silentTCPRelay(hole)
	if n := len(allocSemaphore); n != 0 {
		t.Fatalf("%d Allocate slot(s) taken before the test", n)
	}

	done := make(chan error, 1)
	go func() {
		_, _, _, _, _, err := dialAndAllocate(context.Background(), &stream{}, t.Name(), "pass", hole.Addr().String(),
			WorkerGroupConfig{UseUDP: false}, dialOpts{})
		done <- err
	}()
	waitFor(t, "the Allocate to take its slot", 2*time.Second, func() bool { return len(allocSemaphore) == 1 })
	time.Sleep(relayHeadStart + 300*time.Millisecond)
	if n := len(allocSemaphore); n != 0 {
		t.Fatalf("an Allocate past its head start still holds %d slot(s)", n)
	}
	select {
	case err := <-done:
		t.Fatalf("the Allocate was cut short with its slot: %v", err)
	default:
	}
	if err := <-done; !errors.Is(err, errAllocateSilent) {
		t.Fatalf("the silent Allocate ended with %v, want its own deadline", err)
	}
	if n := len(allocSemaphore); n != 0 {
		t.Fatalf("%d slot(s) left taken after the Allocate ended", n)
	}
}

// A healthy first relay wins alone over TCP as well.
func TestHealthyTCPRelayIsNotRaced(t *testing.T) {
	first, second := twoTCPRelayListeners(t)
	a := startTCPTestRelay(t, first)
	b := startTCPTestRelay(t, second)
	overTCP(t)

	h := runWorkersAgainst(t, 113, 1, []string{a.addr, b.addr})
	waitFor(t, "a stream on the first relay", 3*time.Second, func() bool { return h.ready() == 1 })
	time.Sleep(relayHeadStart + 300*time.Millisecond)

	if n := b.ln.accepted.Load(); n != 0 {
		t.Fatalf("the second relay was dialed %d time(s) although the first answered at once", n)
	}
}

// Over UDP there is no head start: the first relay's Allocate has its own
// deadline, and the others are dialed once it fails (allocateSilenceTimeout).
func TestNoHeadStartOverUDP(t *testing.T) {
	first, second := twoRelaySockets(t)
	// Two round trips (the challenge, then the authenticated request) of 700ms:
	// past the head start, inside the deadline.
	slow := startTestRelay(t, first, 700*time.Millisecond)
	live := startTestRelay(t, second, 0)

	h := runWorkersAgainst(t, 118, 1, []string{slow.addr, live.addr})
	waitFor(t, "a stream", allocateSilenceTimeout+3*time.Second, func() bool { return h.ready() == 1 })
	if got := h.streams[0].serverAddr; got != slow.addr {
		t.Fatalf("session runs on %s, want the first relay %s: an Allocate answered within its deadline was raced", got, slow.addr)
	}
	if n := live.seen.count(); n != 0 {
		t.Fatalf("the second relay was dialed %d time(s) although the first answered within its deadline", n)
	}
}

// The line has to say which of the three it was: the relay that "has not
// accepted the TCP connection" had, in Android's field logs, often accepted it.
func TestHeadStartExpiredSaysWhatTheRelayHadNotDone(t *testing.T) {
	const relay = "relay-a:19302"
	for _, tc := range []struct {
		allocating, connected bool
		want                  string
	}{
		{true, true, "has not answered Allocate"},
		{false, true, "still queued for an Allocate slot"},
		{false, false, "has not accepted the TCP connection"},
	} {
		if got := headStartExpired(relay, tc.allocating, tc.connected); !strings.Contains(got, tc.want) || !strings.HasPrefix(got, relay) {
			t.Errorf("allocating=%v connected=%v: %q, want %q", tc.allocating, tc.connected, got, tc.want)
		}
	}
}

// What the line is told: the dial reports its connect.
func TestDialReportsItsTCPConnect(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))

	var connected atomic.Bool
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, raw, relayConn, _, _, err := dialAndAllocate(ctx, &stream{}, t.Name(), "pass", relay.addr,
		WorkerGroupConfig{UseUDP: false}, dialOpts{connected: connected.Store})
	if err != nil {
		t.Fatal(err)
	}
	relayConn.Close()
	client.Close()
	raw.Close()
	if !connected.Load() {
		t.Fatal("a dial that connected over TCP never said so")
	}
}

// A refused connect is an answer: fan out at once, and hold it against the
// relay the way a failed Allocate is held.
func TestRefusedTCPConnectCountsAgainstTheRelay(t *testing.T) {
	first, second := twoTCPRelayListeners(t)
	live := startTCPTestRelay(t, second)
	refusing := first.Addr().String()
	first.Close() // nothing listens there any more
	overTCP(t)

	started := time.Now()
	h := runWorkersAgainst(t, 114, 1, []string{refusing, live.addr})
	waitFor(t, "a stream on the answering relay", 3*time.Second, func() bool { return h.ready() == 1 })
	if took := time.Since(started); took >= relayHeadStart {
		t.Fatalf("up after %v: a refusal waited out the head start", took)
	}

	serverHealthState.Lock()
	entry := serverHealthState.byAddr[refusing]
	serverHealthState.Unlock()
	if entry == nil || entry.failures == 0 {
		t.Fatal("the refused connect was not counted against the relay")
	}
}

// recordingWriteConn keeps every Write as its own record, which is how segments
// are told apart here.
type recordingWriteConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *recordingWriteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return len(p), nil
}

func TestFirstWriteToTheRelayIsSplitAheadOfTheMagicCookie(t *testing.T) {
	rec := &recordingWriteConn{}
	conn := &splitFirstWriteConn{Conn: rec}

	request := bytes.Repeat([]byte{0xAB}, 28)
	if n, err := conn.Write(request); err != nil || n != len(request) {
		t.Fatalf("first write: n=%d err=%v, want %d", n, err, len(request))
	}
	second := bytes.Repeat([]byte{0xCD}, 40)
	if n, err := conn.Write(second); err != nil || n != len(second) {
		t.Fatalf("second write: n=%d err=%v, want %d", n, err, len(second))
	}

	if len(rec.writes) != 3 {
		t.Fatalf("%d writes reached the socket, want 3 (the first one split, the second whole)", len(rec.writes))
	}
	// The STUN magic cookie sits at bytes 4..8: the cut has to fall before its end.
	if got := len(rec.writes[0]); got != firstWriteSplit || got >= 8 {
		t.Fatalf("first segment is %d bytes, want %d (< 8)", got, firstWriteSplit)
	}
	if !bytes.Equal(append(append([]byte(nil), rec.writes[0]...), rec.writes[1]...), request) {
		t.Fatal("the two segments do not add up to the request")
	}
	if !bytes.Equal(rec.writes[2], second) {
		t.Fatal("a later write was not passed through whole")
	}
}

// The wrapper is no use unless the connection TURN is written through is the
// wrapped one: what reaches the socket first must be the short segment, and the
// relay must get the request whole. Told by the writes into the socket, not by
// the relay's reads: TCP is free to hand both segments to one read (Codex
// review of the Windows port, 2026-10-23).
func TestRelayTCPConnectionSplitsItsFirstWrite(t *testing.T) {
	ln := listenTCPRelay(t)
	request := bytes.Repeat([]byte{0xAB}, 28)
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, len(request))
		if _, err := io.ReadFull(c, buf); err == nil {
			got <- buf
		}
	}()
	var sock *passRecordingConn
	prev := dialRelayTCP
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
		c, err := prev(ctx, d, addr)
		if err != nil {
			return nil, err
		}
		sock = &passRecordingConn{Conn: c}
		return sock, nil
	}
	t.Cleanup(func() { dialRelayTCP = prev })

	conn, err := connectRelayTCP(context.Background(), &net.Dialer{}, ln.Addr().String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write: %v", err)
	}
	if w := sock.sizes(); len(w) != 2 || w[0] != firstWriteSplit || w[0]+w[1] != len(request) {
		t.Fatalf("writes into the socket: %v, want the request cut at %d", w, firstWriteSplit)
	}
	select {
	case b := <-got:
		if !bytes.Equal(b, request) {
			t.Fatal("the relay got the request garbled")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the relay never got the request")
	}
}

// passRecordingConn passes every Write through and keeps its size.
type passRecordingConn struct {
	net.Conn
	mu     sync.Mutex
	writes []int
}

func (c *passRecordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, len(p))
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *passRecordingConn) sizes() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.writes...)
}

// The dialer's own control still runs on the relay's socket, and its refusal
// still keeps the socket from connecting: the hooks connectRelayTCP adds go on
// after it, not instead.
func TestRelayTCPConnectKeepsTheDialersControl(t *testing.T) {
	ln := listenTCPRelay(t)
	refused := errors.New("not on this socket")
	d := &net.Dialer{Control: func(_, _ string, _ syscall.RawConn) error { return refused }}
	conn, err := connectRelayTCP(context.Background(), d, ln.Addr().String())
	if err == nil {
		conn.Close()
		t.Fatal("connected through a socket the dialer's control refused")
	}
	if !errors.Is(err, refused) {
		t.Fatalf("the control's error was lost: %v", err)
	}
}

// The relay's SYN-ACK, and its RST, are the relay heard (relay_silence.go); a
// connect that nobody answers is not.
func TestARelaysAnswerToTheConnectIsTheRelayHeard(t *testing.T) {
	ln := listenTCPRelay(t)
	mark := relayHeardMark()
	conn, err := connectRelayTCP(context.Background(), &net.Dialer{}, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if relayHeardMark() == mark {
		t.Fatal("an accepted connect was not the relay heard")
	}

	closed := listenTCPRelay(t)
	addr := closed.Addr().String()
	closed.Close()
	mark = relayHeardMark()
	if _, err := connectRelayTCP(context.Background(), &net.Dialer{}, addr); err == nil {
		t.Fatal("connected to a port nothing listens on")
	}
	if relayHeardMark() == mark {
		t.Fatal("a refused connect was not the relay heard")
	}

	silent := listenTCPRelay(t)
	hangConnectsTo(t, silent.Addr().String())
	mark = relayHeardMark()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := connectRelayTCP(ctx, &net.Dialer{}, silent.Addr().String()); err == nil {
		t.Fatal("a hung connect connected")
	}
	if relayHeardMark() != mark {
		t.Fatal("a connect nobody answered was the relay heard")
	}
}
