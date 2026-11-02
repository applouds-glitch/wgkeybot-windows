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
	"sync/atomic"
	"syscall"
	"time"
)

// Reaching the relay over TCP.
//
// UDP is the transport everywhere it works: one relay allocation per datagram
// socket, no head-of-line blocking under WireGuard. TCP to the relay is here for
// the networks where UDP to it does not carry a session at all. The known one is
// Rostelecom's mobile network behind a whitelist (field reports from another
// client of the same relays, July–August 2026): the replies to Allocate and
// CreatePermission come back over UDP, but nothing the relay forwards down to
// the client ever arrives, so no stream gets through its data-plane handshake.
// TURN over TCP to the very same relay address works there. On Windows that is
// a laptop on a phone's hotspot with such a SIM in it.
//
// Only the client↔relay leg changes. The allocation is still a UDP relay and the
// relay↔server leg is UDP either way, so the server side needs nothing. VK's
// relays take TURN over TCP on the same port as UDP (checked 2026-09-19: Allocate
// over TCP to :19302 draws the same 401 challenge, realm okcdn.ru); they speak no
// TLS there, and 443/3478/5349 are closed.
//
// The cost is WireGuard inside TCP streams — a lost segment stalls the whole
// stream until it is retransmitted — which is why it is a choice and not the
// default.
//
// Port of Android 81d76f97 (with dcff7fac, b690830d, 8dfb92c4), one transport
// per proxy: Android reads the network's choice at every dial and moves the
// sessions of a running proxy across, with every per-path record kept per
// transport. Here the choice is the tray's, made into the config's UseUDP
// (Tunnel.SetRelayTransport), and a change of it restarts the transport under
// the live WireGuard: every session of one proxy runs over the same transport,
// and the records of the path — the relays heard, the dark — start over with
// the proxy that runs over the other one.

// relayOverTCP reports whether cfg's dials reach the relay over TCP.
func relayOverTCP(cfg WorkerGroupConfig) bool { return !cfg.UseUDP }

// relayTCPConnectTimeout bounds the TCP connect to a relay. The dialer's 30s was
// never meant for it (a UDP "dial" sends nothing); on the network this exists
// for, connects to a relay were seen hanging by the hundred, and every hung one
// holds its worker. A kernel gives up a SYN after a few retransmissions anyway
// (Linux 1+2+4s, Windows 3+6s) — 6s keeps the first two and drops the wait for
// the third's answer.
const relayTCPConnectTimeout = 6 * time.Second

// dialRelayTCP is the seam tests replace to make a relay's connect hang: a
// blackholed SYN cannot be staged on loopback.
var dialRelayTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
	return d.DialContext(ctx, "tcp", addr)
}

// connectRelayTCP connects to a relay and returns the connection all TURN
// traffic to it is written through.
func connectRelayTCP(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
	d.Timeout = relayTCPConnectTimeout
	// Before the connect: the limit has to be in the SYN for the relay to keep to
	// it (see relayTCPMaxSegment). After whatever the dialer already does there.
	before := d.Control
	d.Control = func(network, address string, c syscall.RawConn) error {
		if before != nil {
			if err := before(network, address, c); err != nil {
				return err
			}
		}
		if err := setTCPMaxSegment(c, relayTCPMaxSegment); err != nil {
			maxSegmentRefused.Do(func() {
				turnLog("[NETWORK] TCP_MAXSEG refused (%v) — segments to and from a relay stay as large as the interface allows", err)
			})
		}
		return nil
	}
	c, err := dialRelayTCP(ctx, d, addr)
	if err != nil {
		if errnoIn(err, relayRefusedErrnos) {
			// The relay's RST: heard, if not welcome (relay_silence.go).
			noteRelayHeard()
		}
		return nil, err
	}
	// The relay's SYN-ACK: the relay heard (relay_silence.go).
	noteRelayHeard()
	// After the connect, so the SYN keeps its own, shorter limit above.
	if tc, ok := c.(*net.TCPConn); ok {
		if err := setTCPUserTimeout(tc, relayTCPUserTimeout); err != nil {
			userTimeoutRefused.Do(func() {
				turnLog("[NETWORK] TCP retransmission limit refused (%v) — a hung flow to a relay is left to the system's default", err)
			})
		}
	}
	return &splitFirstWriteConn{Conn: &relayFlowConn{Conn: c, gaveUp: make(chan struct{})}}, nil
}

// relayTCPMaxSegment caps the TCP segments between the client and a relay, in
// both directions: set before the connect it is the MSS our SYN announces, which
// the relay may not exceed, and the ceiling on our own.
//
// Over UDP the size of what crosses this leg follows the tunnel MTU (the config's,
// the bot issues 1280: up to ~1390 B on the wire). Over TCP the tunnel MTU does
// nothing for this leg: the relay writes ChannelData into a byte stream and the
// kernels cut it by MSS, not by packet — under load that is full segments,
// 1460-byte packets on an interface that says 1460 (Android field log 19.09),
// over cellular paths whose real MTU is commonly ~1350-1400, with ICMP filtered
// so that nobody learns. A lost full-size segment is retransmitted at the same
// size for ever; everything behind it in the stream waits, the keepalive echo
// included, and the relay's TCP eventually gives up. It would look like what the
// field showed: flows going deaf under load and reset half a minute later, idle
// ones and small transactions fine — "only text goes through".
//
// Windows sets no MSS per socket (TCP_MAXSEG can only be read there), so on
// Windows this stays what the interface allows. Behind a phone's hotspot the
// phone's own tethering clamps the MSS of what it forwards; a modem in the
// laptop has nobody to do it, and the line below says so once.
const relayTCPMaxSegment = 1240

var maxSegmentRefused sync.Once

// relayTCPUserTimeout is how long a connection to a relay may make no progress
// — data the relay has not acknowledged — before the system gives it up
// (TCP_USER_TIMEOUT; on Windows TCP_MAXRTMS, the limit on retransmission). And
// how long a write may wait in it before the client gives it up itself
// (relayFlowConn.stuckFor): Windows' limit is on retransmissions only, and a
// relay that stops reading — its receive window closed, its kernel answering
// the probes of it — keeps a connection alive that takes nothing for ever,
// where Linux's TCP_USER_TIMEOUT gives it up (Codex review of the Windows port,
// 2026-10-23; iOS sets a persist timeout for the same).
//
// Without it the system keeps retransmitting for many minutes, and nothing
// above it cuts that short for a flow that hangs while it carries traffic: the
// stream's writer is blocked in the socket, its keepalive queues up behind the
// writer on the same socket, and the dead-stream detector lives in the
// keepalive's loop — so the one stream that most needs replacing is the one
// that cannot notice. It stays "ready", is skipped as stale after 35s, and the
// pool is a stream short for good. On the network TCP is here for, flows hang
// one by one (Android field log 19.09: four of ten within a minute of coming
// up).
//
// 30s, from both sides. The hangs seen to clear on their own there lasted 2-8s,
// so this is four times clear of them. And past ~25s waiting stops being worth
// it even for a path that comes back: the retransmission timer doubles each
// time, so a flow silent for 30s will not try again for another half minute,
// while a redial takes a second or a few. It also lands before
// dispatchStaleAfter: the stream is replaced rather than parked.
//
// A var for the host tests, which cannot wait 30s.
var relayTCPUserTimeout = 30 * time.Second

var userTimeoutRefused sync.Once

// relayFlowConn is the TCP connection to a relay with one thing added: it notes
// the system giving the flow up. That verdict is delivered once, to whichever
// call meets it first — pion's read loop, which swallows it, as often as the
// stream's writer — and every call after that sees only a broken connection.
// runSession needs to know either way: to end the session at once rather than
// at the next failed write, and to keep the relay out of the blame (see
// there). A deadline of our own expiring is a different error and is not this.
type relayFlowConn struct {
	net.Conn
	gaveUp chan struct{}
	once   sync.Once

	// The writes under way, and since when the socket has taken nothing: the
	// oldest of them began, or the last to return did (stuckFor).
	mu      sync.Mutex
	writing int
	since   time.Time
}

func (c *relayFlowConn) note(err error) {
	if errnoIn(err, relayFlowGaveUpErrnos) {
		c.once.Do(func() { close(c.gaveUp) })
	}
}

// stuckFor is how long a write has been waiting in the socket with none
// returning meanwhile, as of now; zero while none waits. A sleep inside that
// time is not the relay's: the clock starts over from now (hostFrozeSince).
func (c *relayFlowConn) stuckFor(now time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writing == 0 {
		return 0
	}
	if hostFrozeSince(c.since) {
		c.since = now
	}
	return now.Sub(c.since)
}

// giveUp is the client's own verdict on a flow that has taken nothing for
// relayTCPUserTimeout: booked as the system's would be (relayFlowGaveUp), and
// the connection closed under the writers waiting in it.
func (c *relayFlowConn) giveUp() {
	c.once.Do(func() { close(c.gaveUp) })
	c.Conn.Close()
}

func (c *relayFlowConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.note(err)
	}
	return n, err
}

func (c *relayFlowConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.writing == 0 {
		c.since = time.Now()
	}
	c.writing++
	c.mu.Unlock()
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.writing--
	c.since = time.Now()
	c.mu.Unlock()
	if err != nil {
		c.note(err)
	}
	return n, err
}

// relayFlow finds the flow under a dialed relay conn; nil over UDP.
func relayFlow(c net.Conn) *relayFlowConn {
	if split, ok := c.(*splitFirstWriteConn); ok {
		c = split.Conn
	}
	flow, _ := c.(*relayFlowConn)
	return flow
}

// relayTCPConn finds the TCP connection under a dialed relay conn; nil over UDP,
// or for a conn a test put in its place.
func relayTCPConn(c net.Conn) *net.TCPConn {
	if split, ok := c.(*splitFirstWriteConn); ok {
		c = split.Conn
	}
	if flow, ok := c.(*relayFlowConn); ok {
		c = flow.Conn
	}
	tc, _ := c.(*net.TCPConn)
	return tc
}

// relayFlowGaveUp is closed when the system gives the relay's flow up. Over UDP
// it is nil, which a select waits on for ever.
func relayFlowGaveUp(c net.Conn) <-chan struct{} {
	if flow := relayFlow(c); flow != nil {
		return flow.gaveUp
	}
	return nil
}

func relayFlowTimedOut(c net.Conn) bool {
	select {
	case <-relayFlowGaveUp(c):
		return true
	default:
		return false
	}
}

// errRelayFlowTimedOut is a session's end on a flow the system gave up
// (relayTCPUserTimeout): one of the silences pathWideFailure and silentFailure
// read.
var errRelayFlowTimedOut = errors.New("TCP flow to the relay timed out")

// firstWriteSplit is where the first write to a relay over TCP is cut in two:
// inside the STUN header, ahead of the magic cookie at bytes 4..8, so that no
// single segment opens with a complete STUN header. A shallow DPI rule that
// classifies a flow by its first segment does not see TURN there. Whether
// Rostelecom's filter needs this is not known; the client that works there does
// it, the relays answer a split request exactly as a whole one (checked
// 2026-09-19), and it costs one extra segment per connection.
const (
	firstWriteSplit      = 6
	firstWriteSplitPause = 20 * time.Millisecond
)

// splitFirstWriteConn sends the first write as two segments (Go sets
// TCP_NODELAY, so two writes are two segments) and is transparent after that.
type splitFirstWriteConn struct {
	net.Conn
	done atomic.Bool
}

func (c *splitFirstWriteConn) Write(p []byte) (int, error) {
	if len(p) <= firstWriteSplit || !c.done.CompareAndSwap(false, true) {
		return c.Conn.Write(p)
	}
	n, err := c.Conn.Write(p[:firstWriteSplit])
	if err != nil {
		return n, err
	}
	time.Sleep(firstWriteSplitPause)
	m, err := c.Conn.Write(p[firstWriteSplit:])
	return n + m, err
}

// relayCloseWriteBudget is how long closing a relay over TCP may spend writing.
//
// Closing the relay conn is how every teardown here starts — the transports do
// it to unblock their reads, the blackhole watchdog to recycle an allocation,
// runSession on the way out — and pion's Close makes one synchronous write, the
// Refresh(lifetime=0) that releases the allocation. Over UDP a write never
// waits. Over TCP it waits for room in the socket's send buffer, and a flow
// that has stopped moving (Android field log 19.09, Rostelecom: flows to a
// relay hang for seconds at a time, some for good) has none to give: the
// stream's writer is already blocked in that socket with the buffer full
// behind it, the release queues up behind the writer, the transport waits for
// the writer, and runSession's raw.Close() — the one call that would free them
// all — is a defer that never runs. The worker is held until the system gives
// the connection up; a stop leaves it behind. pion's relay conn has no write
// deadline to set (its SetWriteDeadline is a stub), so the deadline goes on the
// socket beneath it: it frees the blocked writer and bounds the release at
// once. vk-turn-proxy-ios found the same hang on a real allocation (2026-09-06)
// and bounds it the same way, with the same half second.
//
// A release that does not make it out in time fails Close with a timeout, which
// trackedRelay already reads as "this relay still holds our quota".
const relayCloseWriteBudget = 500 * time.Millisecond

// boundedCloseRelay is a relay allocated over a TCP connection: its first Close
// puts relayCloseWriteBudget on that connection's writes before pion makes its
// own. Later Closes (pion answers them "already closed" without writing) leave
// the deadline where the first one put it.
type boundedCloseRelay struct {
	net.PacketConn
	sock net.Conn
	once sync.Once
}

func boundRelayClose(relay net.PacketConn, sock net.Conn) net.PacketConn {
	return &boundedCloseRelay{PacketConn: relay, sock: sock}
}

func (r *boundedCloseRelay) Close() error {
	r.once.Do(func() {
		_ = r.sock.SetWriteDeadline(time.Now().Add(relayCloseWriteBudget))
	})
	return r.PacketConn.Close()
}
