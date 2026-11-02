/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2023 The Pion community <https://pion.ly>
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/wgkeybot/windows/pkg/proxy/srtpwrap"
)

func init() {
	// Pure-Go DNS resolver (без cgo getaddrinfo) — экономит память и FDs,
	// а главное даёт детерминированное поведение в extension-sandbox.
	os.Setenv("GODEBUG", "netdns=go")
}

// clearTransientState resets the DNS cache without touching credential caches.
// Called on every tunnel start so stale DNS is flushed, but credentials earned
// in a prior session are reused if still valid. No HTTP pool is flushed here:
// the VK cred fetch builds a per-fetch tlsclient and closes its idle
// connections when done, and the DoH resolver does the same — there is no
// long-lived shared client to reset.
func clearTransientState() {
	ClearCache()
	turnLog("[PROXY] Transient state cleared (DNS; creds preserved)")
}

// NotifyNetworkChange — внешний API (вызывается Tunnel.OnNetworkChange).
// Credentials are preserved across a network change — VK tokens and TURN
// username/password are not tied to the local IP, so only the DNS cache and
// the transport path proof are reset: what the old path proved says nothing
// about the new one (see network_availability.go). The error-driven
// WorkerGroup re-fetches creds only if its streams actually fail after the
// change, so a healthy session survives a network switch.
func NotifyNetworkChange() {
	// First, so that no retry heads for a relay the allocations left on the old
	// network fill (orphaned_allocations.go).
	orphanLiveAllocations(time.Now())
	noteNetworkLeft()
	clearNetworkPathProof()
	resetDarkPaths() // another network: the dark was the old one's (dark_scout.go)
	// Every session on the new network redials at once; the first connect to
	// each relay goes at once too (relay_connect_pacing.go).
	resetRelayConnectPacing()
	ClearCache()
	turnLog("[NETWORK] Network change: path proof and DNS cache reset (creds preserved)")
}

// ─────────────────────────────────────────────────────────────────────────────
// stream — single TURN connection
// ─────────────────────────────────────────────────────────────────────────────

type stream struct {
	ctx context.Context // set to the global tunnel context

	id       int
	in       chan []byte
	priority chan []byte // bounded small-packet queue, used on TCP sessions (stream_queue.go)
	out      net.PacketConn

	peer   atomic.Pointer[net.Addr]
	ready  atomic.Bool
	okFunc func() // called once when stream becomes ready

	sessionID       []byte
	cert            *tls.Certificate
	watchdogTimeout int

	// serverAddr is the TURN server this attempt runs on, set by runSession
	// before the transport starts. The transports use it to report their own
	// handshake verdict to turn_server_health.go; it is rewritten on every
	// attempt and read only by the single goroutine driving this stream.
	serverAddr string
	// allocateRTT is the Dial→Allocate latency of the session on serverAddr
	// (winner.rtt), set alongside it and read the same way: the relay proof
	// sizes its window by it (udpRelayProofLimit).
	allocateRTT time.Duration
	// overTCP says the session runs over a TCP connection to its relay
	// (relay_transport.go), set by runSession before the transport starts.
	overTCP atomic.Bool

	// attempt is the worker attempt the stream is running, for the judge of
	// relay loss to move it off a rested relay (relay_rest.go), and relays the
	// TURN servers of its link the attempt dials from, for the judge to tell
	// whether it has another to go to. Set and cleared by runWorker.
	attempt atomic.Pointer[relayAttempt]
	relays  atomic.Pointer[[]string]
	// user is the TURN username the attempt dials with, for a move off a
	// rested relay to tell where the credential has room (relay_move.go). Set
	// and cleared by runWorker.
	user atomic.Pointer[string]
	// flowFails is the stream's run of handshakes failed on one relay others
	// were hearing (relay_heard_by_others.go); from flowFailsBeforeAvoid on it
	// dials that relay last.
	flowFails atomic.Pointer[flowFailRun]
	// pathProofs counts the sessions of this stream that carried a round trip
	// through their relay, for its worker to tell whether a proof since its
	// attempt began was its own (path_revival.go).
	pathProofs atomic.Uint64
	// move is set when the stream's session is moved off a rested relay: the
	// relay its next attempt dials first and the relays losing downlink at the
	// time, which it dials last (relay_move.go).
	move atomic.Pointer[relayMove]

	// wrapKey is an optional 32-byte ChaCha20 key for WRAP obfuscation.
	// When non-nil, raw UDP packets to/from the TURN relay are encrypted with
	// wrapPacket / unwrapPacket before any DTLS processing.
	// nil = WRAP disabled (plain mode).
	wrapKey []byte

	// kaPhase is this stream's offset within the shared keepalive grid window,
	// derived from id and the total stream count at startup (see keepalivePhase).
	// Constant for the stream's life, so its NAT-hold gap stays exactly one
	// keepaliveInterval.
	kaPhase time.Duration

	// activity is the liveness clock of the session currently running on this
	// stream, published by the transport before it flips ready. The dispatcher
	// reads it to keep chunks off a stream whose relay has gone quiet (see
	// dispatchStale); the transports own it and replace it per session.
	activity atomic.Pointer[streamActivity]

	// sendStalled says the TCP connection under this stream's session has stopped
	// taking what we send: its head segment has timed out unanswered
	// relayStallSkipTimeouts times in a row. The relay can still be heard — the
	// field log of 22.09 showed the direction up dying alone — so dispatchStale
	// never sees it. Kept by relaySockets (relay_tcp_watch.go); false over UDP.
	sendStalled atomic.Bool

	// control is the downlink-feedback (WGH1) state of the transport attempt
	// running now; nil when feedback is off or between attempts. See
	// downlink_feedback.go.
	control         atomic.Pointer[clientStreamControl]
	feedbackEnabled bool

	// wrapTx carries this stream's outbound WRAP SSRC and counter. Both are
	// per-stream, so each stream (and each device) uses a distinct keystream
	// even at the same counter, and its RTP sequence advances one step per
	// packet. Created in StartTunnelGroups; see wrapTxState.
	wrapTx *wrapTxState

	// allocCheck asks the relay, at a thaw or a wake, whether this session's
	// allocation still exists (alloc_check.go); nil between sessions.
	allocCheck atomic.Pointer[allocCheck]

	// networkGeneration is the proxy generation this stream belongs to (see
	// beginNetworkPathGeneration): proof of a working path is only credited to
	// the generation that produced it, so a stream of a cancelled session
	// cannot vouch for the network on behalf of the one that replaced it.
	networkGeneration uint64
}

// stunBindingIndication is a minimal STUN Binding Indication (RFC 5389, 20 bytes).
// Sent periodically to keep TURN relay allocations and NAT mappings alive.
// Peers that don't handle STUN will safely drop it.
var stunBindingIndication = []byte{
	0x00, 0x11, // type: Binding Indication
	0x00, 0x00, // message length: 0 attributes
	0x21, 0x12, 0xA4, 0x42, // magic cookie
	0x00, 0x00, 0x00, 0x00, // transaction ID (12 bytes, all zero)
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

// isStunKeepalive reports whether b is a 20-byte STUN message with the magic
// cookie at offset 4 — i.e. the server's echoed keepalive. These are used
// purely as a relay-liveness signal and must not be forwarded to WireGuard.
func isStunKeepalive(b []byte) bool {
	return len(b) == 20 && b[4] == 0x21 && b[5] == 0x12 && b[6] == 0xA4 && b[7] == 0x42
}

// sameRelayPeer reports whether from is the expected relay peer. The obvious
// from.String() != peer.String() costs two string allocations on every single
// received packet; pion's relay conn always hands back a *net.UDPAddr (both the
// Data-indication and the ChannelData path construct one), so the fast path is
// the only one taken in practice. peerStr — precomputed once by the caller —
// preserves the old semantics for any other net.Addr implementation.
func sameRelayPeer(from net.Addr, peer *net.UDPAddr, peerStr string) bool {
	if ua, ok := from.(*net.UDPAddr); ok {
		return ua.Port == peer.Port && ua.IP.Equal(peer.IP)
	}
	return from.String() == peerStr
}

// dispatchStale reports whether the stream's relay has been silent for longer
// than dispatchStaleAfter — or, under load, for silentUnderLoadAfter while its
// siblings were heard (silent_under_load.go) — and so should be skipped by the
// dispatcher while a fresher sibling exists (see dispatchPacket). Only ready
// streams are asked; a session that has not published its clock yet counts as
// fresh — the ready flag is the gate there, not this.
//
// It reads the last packet that really arrived (heardAge), not the detector's
// clock (rxAge): a thaw resets that clock for every stream at once, and for
// the next 35 s a stream whose mapping died in the freeze looked exactly like
// one that had just echoed. Now a thaw leaves every stream stale until it
// echoes — and while none has, the dispatcher uses them all (staleWatch's
// "every ready stream is silent"), so the first packet after a thaw still
// goes out at once; from the first echo on, only proven streams are used.
func (s *stream) dispatchStale(now time.Time) bool {
	a := s.activity.Load()
	return a != nil && a.stale(now)
}

const iPacketBuffMaxSize = 2048

// deadStreamError ends a session whose relay has been silent for
// deadStreamTimeout. It carries the length of the silence, which the health
// accounting takes off the session's length (see sessionOutcome).
type deadStreamError struct {
	silent time.Duration
	// probe: the post-wake probe's verdict (wake_probe.go) rather than the
	// periodic detector's; listened is what it listened through.
	probe    bool
	listened time.Duration
	// froze: a host freeze (a sleep) fell inside the silence — the liveness
	// clock was reset for one after the relay was last heard (relay_deaf.go).
	froze bool
}

func (e *deadStreamError) Error() string {
	if e.probe {
		return fmt.Sprintf("dead-stream: no echo to the post-wake probe in %v of listening (relay silent for %v)",
			e.listened.Round(time.Second), e.silent.Round(time.Second))
	}
	return fmt.Sprintf("dead-stream: no RX for %v", e.silent.Round(time.Second))
}

// runKeepalive is the single per-stream NAT-hold and liveness loop shared by
// all transports. Connections are established with a safety stagger, but every
// ready stream sends its normal keepalive on the same 25s wall-clock grid so the
// packets and their echoes occupy one short wake window — staggered inside that
// window by the stream's phase (see keepalivePhase), so one lost burst cannot
// starve every sibling's liveness clock at the same instant. A failed write may
// retry early; after success the stream rejoins the grid. Only a validated
// inbound packet proves liveness, except after a host freeze, where a stale
// clock says nothing about the path and is reset (see freezeSlack) — and the
// relay is then asked whether the stream survived the freeze at all (the
// post-wake probe, wake_probe.go).
//
// probe writes one sequenced ping (stunProbe) for that probe; nil disables it,
// and the loop is then the periodic detector alone. Returns when ctx is
// cancelled, the dead-stream detector fires or the probe finds the relay gone.
func (s *stream) runKeepalive(ctx context.Context, activity *streamActivity, reportErr func(error), send func(tick int) error, probe func(seq uint64) error) {
	var retryAt time.Time
	// echoAt is when the keepalive sent at echoFor goes out again unless
	// something has arrived by then (keepaliveEchoRetry); zero = none pending.
	// retriedAt is when one went out again, for the line at the next wake.
	var echoAt, echoFor, retriedAt time.Time
	tick := 0
	var probeSeq uint64
	var lastProbeAt time.Time
	wake := newWakeWatch()
	// runProbe asks the relay whether this stream is still there; false means
	// the stream is dead and has been reported.
	runProbe := func(now time.Time, why string) (alive bool) {
		if probe == nil {
			return true
		}
		alive, covered, err := s.runWakeProbe(ctx, activity, &probeSeq, probe, why)
		if err != nil {
			// A probe that could not even write still takes its turn of the
			// throttle. Left uncounted, the wake it was for stayed pending, the
			// top of the loop probed again at once, and a socket that cannot
			// write kept the loop in failed probes for good — off its retry
			// path and out of reach of the dead-stream detector (Android audit
			// 2026-10-16: 6 probes and 31 pings in 800ms on one wake). The
			// throttle serves that wake and the burst behind it; the next wake
			// past it asks again. Counted from when the probe gave up, not from
			// `now`, its start: a probe may listen through most of its window
			// before its writes begin to fail, or sleep through a freeze, and
			// the throttle would be spent by the time it returns (codex review).
			lastProbeAt = time.Now()
			if ctx.Err() == nil {
				turnLog("[STREAM %d] post-wake probe given up on send errors: %v", s.id, err)
				retryAt = time.Now().Add(keepaliveSendRetry)
			}
			return true
		}
		lastProbeAt = now
		wake.served = covered
		if !alive {
			reportErr(&deadStreamError{silent: activity.heardAge(wakeProbeClock()), probe: true, listened: wakeProbeWindow,
				froze: activity.frozeSinceHeard()})
		}
		return alive
	}
	for {
		// The wake channel is read before the epoch is compared: a wake that
		// came earlier is in the epoch, one that comes later closes this channel.
		// The epoch is read ONCE, before the throttle decides: a wake broadcast
		// between the decision and the bookkeeping must stay pending.
		wakeCh := hostWakeChannel()
		if epoch := hostWakeEpoch(); epoch != wake.served {
			now := time.Now()
			if wakeProbeDue(activity, lastProbeAt, now) {
				s.runAllocCheck("wake")
				if !wakeProbeSpread(ctx) {
					return
				}
				if !runProbe(time.Now(), "wake") {
					return
				}
			} else {
				wake.served = epoch
			}
			continue
		}

		start := time.Now()
		deadline, wakeReason := activity.nextDeadline(start, retryAt, echoAt)
		// The grid point due at the end of this wait or after it: a wake for
		// anything else that comes only past it serves it first (below).
		gridAt := nextKeepaliveGrid(start, activity.phase)
		before := time.Now()
		woke, ok := keepaliveWait(ctx, deadline, wakeCh)
		if !ok {
			return
		}

		now := time.Now()
		rxAge := activity.rxAge(now)

		// nextDeadline never returns a point further out than the shared grid, so
		// a sleep this long means the host froze us rather than that the path went
		// quiet. Reset the liveness clock and re-stimulate the path; tearing the
		// stream down here would mass-reconnect every stream on thaw.
		if slept := now.Sub(before); slept > keepaliveInterval+freezeSlack {
			turnLog("[STREAM %d] keepalive: slept %v (freeze) — resetting liveness clock", s.id, slept.Round(time.Second))
			activity.resetLiveness(now)
			// A repeat pending from before the freeze is stale: the keepalive and
			// the probe below ask for themselves.
			echoAt = time.Time{}
			// The relay's own answer comes within a round trip, and pion
			// retransmits what the radio drops (alloc_check.go).
			s.runAllocCheck("thaw")
			// Every stream's loop fires in this same instant: spread the whole
			// burst that follows over wakeProbeJitter (wakeProbeSpread).
			if !wakeProbeSpread(ctx) {
				return
			}
			now = time.Now()
			// A thawed host must re-stimulate both layers in the same wake
			// window: one WireGuard keepalive for this grid, then this stream's
			// TURN liveness probe.
			sendWireGuardKeepaliveOnSharedGrid(now)
			err := send(tick)
			tick++
			if err != nil {
				turnLog("[STREAM %d] keepalive send error: %v", s.id, err)
				retryAt = now.Add(keepaliveSendRetry)
				continue
			}
			retryAt = time.Time{}
			// The thaw is a wake nobody announces: ask the relay now whether the
			// stream survived it (a mapping lost in the silence answers nothing).
			if !runProbe(now, "thaw") {
				return
			}
			continue
		}
		if woke {
			continue // a wake ended the wait early; the top of the loop serves it
		}

		if rxAge >= deadStreamTimeout {
			turnLog("[STREAM %d] dead-stream detector: no RX for %v — closing", s.id, rxAge.Round(time.Second))
			// heardAge, not rxAge: a freeze reset restarts the detector's clock,
			// not the silence the relay is answerable for.
			reportErr(&deadStreamError{silent: activity.heardAge(now), froze: activity.frozeSinceHeard()})
			return
		}
		// A wake for the repeat, a write retry or the dead-stream check that
		// came only after the grid point it was due before — the process held
		// up past it, short of a freeze — serves that grid point first: left
		// to the next turn, the grid is counted again from now and the next
		// point is a whole interval away, ~50 s without a keepalive and the
		// stream benched from the 35th (codex review of the Android port,
		// 2026-10-22). The grid's keepalive arms its own repeat.
		if wakeReason != keepaliveGridWake && !now.Before(gridAt) {
			wakeReason = keepaliveGridWake
			echoAt = time.Time{}
		}
		// An RX that arrived after the timer was armed may make an old liveness
		// deadline harmless. Recalculate instead of emitting an off-grid packet.
		if wakeReason == keepaliveDeadCheckWake {
			continue
		}
		if !retriedAt.IsZero() {
			// What the repeat did, told at the next wake: the RX goroutine keeps
			// the clock, this loop only reads it. A repeat goes out only when
			// nothing arrived for keepaliveEchoRetry, so what is heard next is
			// its echo as often as not; nothing heard is told by the dispatcher
			// and the detector.
			if heard := atomicTimestamp(&activity.lastHeard); heard.After(retriedAt) {
				turnLog("[STREAM %d] keepalive sent again %v after one that drew no echo — heard %v after that",
					s.id, keepaliveEchoRetry, heard.Sub(retriedAt).Round(time.Millisecond))
			}
			retriedAt = time.Time{}
		}
		if wakeReason == keepaliveEchoRetryWake {
			echoAt = time.Time{}
			if !activity.echoMissed(echoFor) {
				continue // its echo, or data: the path answered
			}
			// The grid's WireGuard keepalive went out with the first one; only
			// the TURN keepalive is repeated, and only this once (keepaliveEchoRetry).
			if err := send(tick); err != nil {
				turnLog("[STREAM %d] keepalive send error: %v", s.id, err)
				retryAt = now.Add(keepaliveSendRetry)
				continue
			}
			tick++
			retriedAt = now
			continue
		}
		if wakeReason == keepaliveGridWake {
			// Every stream reaches this shared bucket within keepaliveSpread.
			// The coordinator lets only the first one enqueue a WireGuard
			// keepalive, coalescing it with the TURN/STUN burst below.
			sendWireGuardKeepaliveOnSharedGrid(now)
		}
		err := send(tick)
		tick++
		if err != nil {
			turnLog("[STREAM %d] keepalive send error: %v", s.id, err)
			retryAt = now.Add(keepaliveSendRetry)
			echoAt = time.Time{}
			continue
		}
		retryAt = time.Time{}
		// Sent again in keepaliveEchoRetry unless something arrives
		// (keepalive_policy.go).
		echoFor, echoAt = now, now.Add(keepaliveEchoRetry)
	}
}

// sendSessionHSBurst sends the 17-byte session header burstCount times
// with burstGap between sends. The redundancy survives UDP loss and gives
// the server multiple chances to receive the header before the first WG
// packet arrives — without it, a single race or drop costs a full 5s WG
// handshake retry (and with 3 hashes commonly compounds to ~15s).
func (s *stream) sendSessionHSBurst(relayConn net.PacketConn, peer net.Addr, sessionHS []byte, hasWrap bool) error {
	const burstCount = 3
	const burstGap = 50 * time.Millisecond
	for i := 0; i < burstCount; i++ {
		var payload []byte
		if hasWrap {
			enc, err := wrapPacket(s.wrapKey, sessionHS, s.wrapTx)
			if err != nil {
				return fmt.Errorf("session handshake wrap #%d: %w", i+1, err)
			}
			payload = enc
		} else {
			payload = sessionHS
		}
		if _, err := relayConn.WriteTo(payload, peer); err != nil {
			return fmt.Errorf("session handshake send #%d: %w", i+1, err)
		}
		if i < burstCount-1 {
			time.Sleep(burstGap)
		}
	}
	return nil
}

var packetPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, iPacketBuffMaxSize)
	},
}

// Metrics
var (
	dtlsTxDropCount    atomic.Uint64
	dtlsRxErrorCount   atomic.Uint64
	relayTxErrorCount  atomic.Uint64
	relayRxErrorCount  atomic.Uint64
	noDtlsTxDropCount  atomic.Uint64
	noDtlsRxErrorCount atomic.Uint64
)

// ─────────────────────────────────────────────────────────────────────────────
// runNoDTLS — direct relay, no DTLS
// ─────────────────────────────────────────────────────────────────────────────

// errRelayNeverAnswered is the relay proof's verdict on a relay whose path
// carried no echo inside its window (awaitRelayProof): the silence it is, kept
// in the chain under errDataPlaneHandshake.
var errRelayNeverAnswered = errors.New("relay never answered")

const (
	// relayProofTimeout bounds the wait for the relay to answer (see runNoDTLS).
	// Short enough that a bad relay is out of the way with room for WireGuard's
	// own retries inside the connect budget, long enough to survive a slow RTT
	// plus a lost probe — a full DTLS-SRTP handshake over these relays measures
	// 130-220ms, so a single round trip has an order of magnitude of headroom
	// here.
	//
	// On a path that answers in the usual time, that is: a probe not answered
	// was lost. On one measured slower it is late, and the window grows with
	// that path; this is its floor (udpRelayProofLimit).
	relayProofTimeout = 2 * time.Second

	// relayProofRTTs is how many of the session's measured round trips the
	// relay proof waits (udpRelayProofLimit). The proof needs one: the probe
	// out through the relay to the server and the echo back, the leg between
	// relay and server being short next to a congested uplink. The second is
	// for the queue the probe waits in, which keeps growing while it waits: on
	// Android 20.10 three permissions on one stream in a row took 1.6s, 2.3s
	// and 2.6s.
	//
	// The sample is the larger of the Allocate and the CreatePermission
	// (runNoDTLS), and the Allocate is two round trips on its own — pion sends
	// it unauthenticated, takes the 401 challenge and sends it again. So the
	// window is at least two round trips at the latest pace, and four at the
	// Allocate's: for 20.10's 3.0-3.3s Allocates, 6.0-6.6s.
	relayProofRTTs = 2

	// relayProbeInterval re-sends the probe (and the session header with it, in
	// case that is what was lost) while waiting. UDP loses packets; one silent
	// drop must not read as a dead relay.
	relayProbeInterval = 400 * time.Millisecond

	// dataPlaneHandshakeTimeout bounds the DTLS and DTLS-SRTP handshakes through
	// the relay — those transports' counterpart of relayProofTimeout. pion/dtls
	// retransmits a flight on a doubling timer (1s, 2s, 4s, ...), so within this
	// window the ClientHello goes out four times; a relay that swallowed all
	// four is not going to answer a fifth. It used to be 30s: on the default
	// proxy_v2 peer type a blackholed relay failed its handshake — and was
	// demoted, see turn_server_demotion.go — only half a minute in, with half
	// the streams pinned to a dead host for that long while WaitReady's budget
	// ran, so the demotion effectively worked promptly only for peerType
	// "wireguard". A healthy handshake over these relays measures 130-220ms, so
	// the window keeps an order of magnitude of headroom for a bad RTT plus a
	// lost flight or two.
	dataPlaneHandshakeTimeout = 8 * time.Second
)

// runNoDTLS carries WireGuard straight over the relay, optionally WRAP-obfuscated.
//
// Unlike DTLS and SRTP this transport has no handshake of its own — the server
// answers the 17-byte session header with nothing — so readiness used to be a
// blind 200ms sleep. That made a relay which allocates and then swallows
// everything look exactly like a working one: the dispatcher kept feeding the
// dead stream (init_groups.go sends eight consecutive packets through one
// stream, and before the tunnel is up those eight are all of WireGuard's
// handshake retries), and the tunnel was torn down at its handshake deadline —
// long before the 90s dead-stream detector had said a word. Allocate had
// succeeded, so nothing counted against the server either, and the next attempt
// went back to the same dead host.
//
// The proof was already on the wire: the server echoes a STUN keepalive back
// through the stream once it has registered the session header, and that echo is
// a full round trip through the relay. So probe with one and wait for it, and
// fail the stream if it never comes.
func (s *stream) runNoDTLS(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr) error {
	// The relay this session runs on, for the downlink loss per relay
	// (relay_loss.go). Set by runSession before the transport starts.
	relayAddr := s.serverAddr
	sCtx, sCancel := context.WithCancel(ctx)
	ready := newSessionReadiness(sCtx, sCancel, s)
	defer ready.end()

	// firstErr captures the root cause when a goroutine fails and calls ready.end().
	// See runDTLS for full rationale.
	firstErr := make(chan error, 1)
	reportErr := func(err error) {
		select {
		case firstErr <- err:
		default:
		}
	}

	hasWrap := s.wrapKey != nil

	// Closed by the RX goroutine on the first packet the relay hands back that
	// survives the peer and WRAP checks. That packet is the whole proof this
	// transport gets that the relay round trip works.
	proofCh := make(chan struct{})
	var proofOnce sync.Once
	proven := func() { proofOnce.Do(func() { close(proofCh) }) }

	// Session handshake: 17-byte header (sessionID + streamID). Kept in
	// sessionHS so the keepalive goroutine can re-announce it periodically.
	// Sent in a small burst so a single UDP drop or server-side scheduling
	// race doesn't push the first WG packet ahead of the registered stream.
	var sessionHS []byte
	if s.sessionID != nil {
		sessionHS = make([]byte, 17)
		copy(sessionHS[:16], s.sessionID)
		sessionHS[16] = byte(s.id)
		if hErr := s.sendSessionHSBurst(relayConn, peer, sessionHS, hasWrap); hErr != nil {
			return fmt.Errorf("%w: %w", errDataPlaneHandshake, hErr)
		}
	}

	// Cancelling sCtx (watchdog, error, parent stop) closes the relay conn so
	// the RX goroutine's blocking ReadFrom unblocks immediately instead of
	// waiting out its 60s deadline.
	context.AfterFunc(sCtx, func() {
		ready.end()
		relayConn.Close()
	})

	// activity is the liveness clock of this session — only a real packet from
	// the peer (WG data or the server's keepalive echo) advances it, in the RX
	// goroutine. A keepalive *send* must never refresh it: a dead TURN
	// allocation still accepts WriteTo (SEND indications are fire-and-forget),
	// so "sent OK" proves nothing. runKeepalive tears the stream down once the
	// clock goes stale past deadStreamTimeout.
	activity := newStreamActivity(time.Now(), s.kaPhase)
	s.activity.Store(activity)
	// Downlink feedback (WGH1) for this attempt only: a fresh nonce, and no
	// capability until this very transport hears a matching ACK.
	control := s.newFeedbackControl()
	defer s.control.CompareAndSwap(control, nil)

	var wg sync.WaitGroup
	wg.Add(3)

	// TX: WireGuard → relay
	go func() {
		defer wg.Done()
		defer ready.end()
		// Scratch buffer for WRAP encryption, owned by this goroutine alone.
		// relayConn.WriteTo copies the payload into its own STUN/ChannelData
		// message, so the buffer is free to be reused on the next packet.
		var txBuf []byte
		if hasWrap {
			txBuf = make([]byte, iPacketBuffMaxSize+wrapMaxOverhead)
		}
		reader := outboundReader{s: s}
		for {
			b, ok := reader.next(sCtx)
			if !ok {
				return
			}
			var payload []byte
			if hasWrap {
				n, wrapErr := wrapPacketInto(txBuf, s.wrapKey, b, s.wrapTx)
				if wrapErr != nil {
					packetPool.Put(b[:cap(b)])
					noDtlsTxDropCount.Add(1)
					turnLog("[STREAM %d] WRAP TX error: %v", s.id, wrapErr)
					reportErr(fmt.Errorf("WRAP TX: %w", wrapErr))
					return
				}
				payload = txBuf[:n]
			} else {
				payload = b
			}
			_, err := relayConn.WriteTo(payload, peer)
			packetPool.Put(b[:cap(b)])
			if err != nil {
				noDtlsTxDropCount.Add(1)
				if isTransientSendErr(err) {
					// Transient Windows send-buffer pressure (WSAENOBUFS):
					// drop this packet (WireGuard retransmits) and keep the
					// stream rather than storm-reconnecting every stream at once.
					continue
				}
				turnLog("[STREAM %d] TX error: %v", s.id, err)
				reportErr(fmt.Errorf("relay TX: %w", err))
				return
			}
		}
	}()

	// RX: relay → WireGuard
	go func() {
		defer wg.Done()
		defer ready.end()
		wire := make([]byte, iPacketBuffMaxSize)
		plain := make([]byte, iPacketBuffMaxSize)
		peerStr := peer.String()
		for {
			n, from, err := relayConn.ReadFrom(wire)
			if err != nil {
				noDtlsRxErrorCount.Add(1)
				reportErr(fmt.Errorf("relay RX: %w", err))
				return
			}
			if !sameRelayPeer(from, peer, peerStr) {
				continue
			}
			// The peer lookup happens per branch, below the proof: at startup
			// s.peer is still nil until WireGuard's source address is known, and
			// bailing out up here would throw away the very echo awaitRelayProof
			// is waiting for.
			if hasWrap {
				m, unwrapErr := unwrapPacket(s.wrapKey, wire[:n], plain)
				if unwrapErr != nil {
					turnLog("[STREAM %d] WRAP RX skip: %v", s.id, unwrapErr)
					continue
				}
				// Only a successfully parsed WRAP packet is inbound liveness
				// evidence. A valid cover packet has no WG payload but still proves
				// that the relay path works in both directions.
				activity.noteRx(time.Now())
				markNetworkPathProven(s.networkGeneration)
				proven()
				if m == 0 {
					continue
				}
				if control.receive(plain[:m]) {
					continue
				}
				if isStunKeepalive(plain[:m]) {
					// Liveness already recorded; don't feed it to WG. The echo
					// names the ping it answers (wake_probe.go).
					activity.noteProbeEcho(plain[:m])
					continue
				}
				a := s.peer.Load()
				if a == nil {
					continue
				}
				downlinkRelayLoss.observe(plain[:m], relayAddr, time.Now())
				if _, err := s.out.WriteTo(plain[:m], *a); err != nil {
					noDtlsRxErrorCount.Add(1)
					reportErr(fmt.Errorf("TUN write: %w", err))
					return
				}
			} else {
				if n == 0 {
					continue
				}
				activity.noteRx(time.Now())
				markNetworkPathProven(s.networkGeneration)
				proven()
				if control.receive(wire[:n]) {
					continue
				}
				if isStunKeepalive(wire[:n]) {
					// Liveness already recorded; don't feed it to WG. The echo
					// names the ping it answers (wake_probe.go).
					activity.noteProbeEcho(wire[:n])
					continue
				}
				a := s.peer.Load()
				if a == nil {
					continue
				}
				downlinkRelayLoss.observe(wire[:n], relayAddr, time.Now())
				if _, err := s.out.WriteTo(wire[:n], *a); err != nil {
					noDtlsRxErrorCount.Add(1)
					reportErr(fmt.Errorf("TUN write: %w", err))
					return
				}
			}
		}
	}()

	// Keepalive + cover traffic + dead-stream detection (one coalesced loop; see
	// runKeepalive). Sends the STUN Indication (liveness stimulus + NAT hold),
	// paces WRAP cover traffic every 3rd tick, and re-announces the 17-byte
	// session header so a restarted server re-adopts this stream within one tick
	// without a reconnect. A send never refreshes the liveness clock — only the
	// server's echo (in the RX goroutine) proves the path.
	go func() {
		defer wg.Done()
		defer ready.end()
		s.runKeepalive(sCtx, activity, reportErr, func(tick int) error {
			var sendErr error
			if hasWrap {
				if enc, err := wrapPacket(s.wrapKey, control.keepalive(), s.wrapTx); err == nil {
					_, sendErr = relayConn.WriteTo(enc, peer)
				} else {
					sendErr = err
				}
				if tick%3 == 0 {
					if cover, cErr := wrapCoverPacket(s.wrapKey, s.wrapTx); cErr == nil {
						relayConn.WriteTo(cover, peer)
					}
				}
			} else {
				_, sendErr = relayConn.WriteTo(control.keepalive(), peer)
			}
			if sessionHS != nil {
				if hasWrap {
					if enc, wErr := wrapPacket(s.wrapKey, sessionHS, s.wrapTx); wErr == nil {
						relayConn.WriteTo(enc, peer)
					}
				} else {
					relayConn.WriteTo(sessionHS, peer)
				}
			}
			return sendErr
		}, func(seq uint64) error {
			p := stunProbe(seq)
			if hasWrap {
				enc, err := wrapPacket(s.wrapKey, p, s.wrapTx)
				if err != nil {
					return err
				}
				p = enc
			}
			_, err := relayConn.WriteTo(p, peer)
			return err
		})
	}()

	if sessionHS != nil {
		// The round trips this session has already timed on its relay, which the
		// proof's window grows with (udpRelayProofLimit): its Allocate, and the
		// CreatePermission the header burst above waited on.
		pathRTT := max(s.allocateRTT, permissionGrantedIn(relayConn))
		if err := s.awaitRelayProof(sCtx, proofCh, pathRTT, func() error {
			return s.probeRelay(relayConn, peer, sessionHS, hasWrap)
		}); err != nil {
			// A goroutine that already failed knows better than the timeout why
			// nothing came back; either way the stream never carried traffic.
			//
			// What it said is taken here, before ready.end, and not after wg.Wait:
			// the cancel closes relayConn, the RX goroutine's ReadFrom then fails
			// with "use of closed network connection" — our own teardown — and
			// that took the empty slot in place of the verdict. A relay that never
			// answered failed its stream as if the socket had broken, without
			// errRelayNeverAnswered in the chain (Android host test, 20.10), and a
			// probe the socket refused lost its errno the same way, so
			// relayNotToBlame never saw the machine's own network refuse it. A
			// goroutine that failed first has its error in the slot by now: it
			// reports before its deferred ready.end, and that cancel is what ended
			// the wait.
			var cause error
			select {
			case cause = <-firstErr:
			default:
			}
			ready.end()
			wg.Wait()
			if ctx.Err() != nil {
				// Our own teardown, not the relay's silence.
				return err
			}
			if cause != nil {
				err = cause
			}
			return fmt.Errorf("%w: %w", errDataPlaneHandshake, err)
		}
		noteServerHandshakeOK(s.serverAddr)
		s.notePathProven()
		// The only line this transport prints on success. Without it a live
		// noDTLS stream is invisible in the log — its server can be recovered
		// only by pairing "Dial TURN" with the absence of a later worker error.
		turnLog("[STREAM %d] Relay proof OK on %s", s.id, s.serverAddr)
	} else {
		// Without a session header the server never registers this stream and so
		// never echoes: there is nothing to wait for. Keep the old optimistic
		// readiness on that path rather than failing a stream we cannot judge.
		// The burst above already gives the server 3 chances spread across
		// ~100ms; only a short tail wait is needed for the last one to land.
		time.Sleep(200 * time.Millisecond)
	}

	if ready.publish() {
		// The judge of silence under load takes this stream's row now, not on
		// the next packet anyone hears (silent_under_load.go).
		wakeSilentUnderLoadJudge()
		// Ask right away rather than at the next grid tick, so the reporter can
		// use this stream as soon as the server has answered.
		if control != nil {
			s.enqueueControl(control.keepalive())
		}
		s.okFunc()
	}
	wg.Wait()
	select {
	case err := <-firstErr:
		return err
	default:
		return nil
	}
}

// probeRelay sends one liveness probe: the session header first, so a server
// that lost the opening burst registers the stream before it sees the STUN it is
// meant to echo, then the STUN itself.
func (s *stream) probeRelay(relayConn net.PacketConn, peer net.Addr, sessionHS []byte, hasWrap bool) error {
	if hasWrap {
		if enc, err := wrapPacket(s.wrapKey, sessionHS, s.wrapTx); err == nil {
			relayConn.WriteTo(enc, peer)
		}
		enc, err := wrapPacket(s.wrapKey, stunBindingIndication, s.wrapTx)
		if err != nil {
			return fmt.Errorf("WRAP probe: %w", err)
		}
		_, err = relayConn.WriteTo(enc, peer)
		return err
	}
	relayConn.WriteTo(sessionHS, peer)
	_, err := relayConn.WriteTo(stunBindingIndication, peer)
	return err
}

// relayProofLimit is how long this stream waits for its relay proof. pathRTT is
// the slowest round trip the session has already timed on its relay, 0 if none
// (see runNoDTLS).
//
// Over TCP the probe sits in a byte stream: it arrives, late, or the connection
// dies — and on the network that needs TCP "late" is the usual case, flows hang
// for 2-8s and then move (Android field log 19.09). Two seconds there ruled
// against flows about to work, and each ruling costs more than the wait it
// saves: the release of an allocation cannot leave through a hung flow either,
// so it stays on the relay for 600s, counted against the credential's quota of
// ten. The limit over TCP is the one DTLS and SRTP already have on the same
// path, dataPlaneHandshakeTimeout — past the hangs that were seen to clear,
// and still a third of the connect budget. Over UDP the window grows with the
// round trip the session measured (udpRelayProofLimit).
func (s *stream) relayProofLimit(pathRTT time.Duration) time.Duration {
	if s.overTCP.Load() {
		return relayProofTimeoutTCP
	}
	return udpRelayProofLimit(pathRTT)
}

// A var for the host tests that wait it out.
var relayProofTimeoutTCP = dataPlaneHandshakeTimeout

// udpRelayProofLimit is the relay proof window for a session whose slowest timed
// round trip to its relay was pathRTT: relayProofRTTs of them, no less than
// relayProofTimeout and no more than dataPlaneHandshakeTimeout.
//
// An unanswered probe is usually lost, and relayProbeInterval sends another —
// but on a congested path it is late. Android field log 20.10 (cellular,
// wireguard with WRAP, ten streams on two relays): just after a reconnect, with
// the apps catching up behind it, Allocate took 3.0-3.3s (once 7.4s), and
// stream 8 failed its proof three times in a row, the relay having granted the
// permission in 1.6s, 2.3s and 2.6s — a single round trip that took most of the
// 2s window, or more than all of it. Those failures stood both relays down for
// five minutes while the other nine streams were carrying traffic over them.
// A loaded home uplink or a tethered phone is the same path here.
//
// The floor keeps a fast path as fast as it was: an Allocate on a good path
// answers in about 200ms (see dialAndAllocate and relayWriteProbe), so the
// window moves off relayProofTimeout only once the round trip passes a second,
// and a relay that allocates and swallows everything is still out of the way in
// 2s. The ceiling is the window DTLS and SRTP already have on the same path, a
// third of the connect budget; a longer one is the regression
// dataPlaneHandshakeTimeout describes, the verdict on a dead relay coming after
// the tunnel had been torn down. A round trip not timed (0) gets the floor.
func udpRelayProofLimit(pathRTT time.Duration) time.Duration {
	// Compared before multiplying, so no round trip can overflow into a short
	// window.
	if pathRTT >= dataPlaneHandshakeTimeout/relayProofRTTs {
		return dataPlaneHandshakeTimeout
	}
	return max(relayProofTimeout, relayProofRTTs*pathRTT)
}

// awaitRelayProof probes until the relay answers, the context dies, or the
// window for pathRTT (udpRelayProofLimit) runs out. Returning an error means the
// stream never proved its data path and must not be offered to the dispatcher.
func (s *stream) awaitRelayProof(ctx context.Context, proof <-chan struct{}, pathRTT time.Duration, probe func() error) error {
	if err := probe(); err != nil {
		return err
	}
	limit := s.relayProofLimit(pathRTT)
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	ticker := time.NewTicker(relayProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-proof:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("%w in %v", errRelayNeverAnswered, limit.Round(time.Millisecond))
		case <-ticker.C:
			if err := probe(); err != nil {
				return err
			}
		}
	}
}

func (s *stream) runDTLS(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr, sendHandshake bool) error {
	// The relay this session runs on, for the downlink loss per relay
	// (relay_loss.go). Set by runSession before the transport starts.
	relayAddr := s.serverAddr
	sCtx, sCancel := context.WithCancel(ctx)
	ready := newSessionReadiness(sCtx, sCancel, s)
	defer ready.end()

	// firstErr captures the root cause when a goroutine fails and calls ready.end().
	// Without this, any internal failure (watchdog, RX error, TX error) would
	// return nil, which WorkerGroup misinterprets as "server closed stream,
	// rotate credentials" — causing an infinite stream creation/destruction loop
	// when DPI blocks traffic through an otherwise healthy DTLS tunnel.
	firstErr := make(chan error, 1)
	reportErr := func(err error) {
		select {
		case firstErr <- err:
		default:
		}
	}

	c1, c2 := connutil.AsyncPacketPipe()
	defer c1.Close()
	defer c2.Close()

	dtlsConn, err := dtls.Client(c1, peer, &dtls.Config{
		Certificates:         []tls.Certificate{*s.cert},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		// Connection ID lets the DTLS session survive a client-side NAT
		// rebind (mobile network switch, NAT timeout) without a fresh
		// handshake. The server negotiates CID too; if a peer doesn't,
		// pion silently falls back to no-CID.
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	})
	if err != nil {
		return fmt.Errorf("DTLS client creation failed: %w", err)
	}
	defer dtlsConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	context.AfterFunc(sCtx, func() {
		ready.end()
		relayConn.Close()
		c1.Close()
	})

	// Dead-stream detection lives in runKeepalive below: it watches the liveness
	// clock (advanced by the DTLS→WireGuard RX goroutine on every decrypted
	// packet, including the server's keepalive echo) and, when it goes stale,
	// cancels sCtx — which the AfterFunc above turns into relayConn.Close(),
	// unblocking this relay RX.

	// ── Pipe → Relay (TX) ────────────────────────────────────────────────────
	// When WRAP is enabled, each outgoing DTLS record is encrypted with
	// wrapPacket before being sent to the relay over UDP.
	go func() {
		defer wg.Done()
		defer ready.end()
		buf := make([]byte, iPacketBuffMaxSize)
		// Scratch buffer for WRAP encryption, owned by this goroutine alone
		// (see runNoDTLS TX for why reuse is safe).
		var txBuf []byte
		if s.wrapKey != nil {
			txBuf = make([]byte, iPacketBuffMaxSize+wrapMaxOverhead)
		}
		for {
			n, _, err := c2.ReadFrom(buf)
			if err != nil {
				return
			}

			var payload []byte
			if s.wrapKey != nil {
				wrapped, wrapErr := wrapPacketInto(txBuf, s.wrapKey, buf[:n], s.wrapTx)
				if wrapErr != nil {
					turnLog("[STREAM %d] WRAP TX error: %v", s.id, wrapErr)
					relayTxErrorCount.Add(1)
					reportErr(fmt.Errorf("WRAP TX: %w", wrapErr))
					return
				}
				payload = txBuf[:wrapped]
			} else {
				payload = buf[:n]
			}

			if _, err := relayConn.WriteTo(payload, peer); err != nil {
				relayTxErrorCount.Add(1)
				if isTransientSendErr(err) {
					// Transient Windows send-buffer pressure (WSAENOBUFS): drop
					// this DTLS record (DTLS/WireGuard retransmits) and keep the
					// stream rather than storm-reconnecting every stream at once.
					continue
				}
				turnLog("[STREAM %d] relay TX error: %v", s.id, err)
				reportErr(fmt.Errorf("relay TX: %w", err))
				return
			}
		}
	}()

	// ── Relay → Pipe (RX) ────────────────────────────────────────────────────
	// When WRAP is enabled, incoming UDP datagrams are decrypted with
	// unwrapPacket before being fed into the DTLS pipe.
	go func() {
		defer wg.Done()
		defer ready.end()
		wire := make([]byte, iPacketBuffMaxSize)
		plain := make([]byte, iPacketBuffMaxSize)
		peerStr := peer.String()
		for {
			n, from, err := relayConn.ReadFrom(wire)
			if err != nil {
				relayRxErrorCount.Add(1)
				turnLog("[STREAM %d] relay RX error: %v", s.id, err)
				reportErr(fmt.Errorf("relay RX: %w", err))
				return
			}
			if sameRelayPeer(from, peer, peerStr) {
				var data []byte
				if s.wrapKey != nil {
					m, unwrapErr := unwrapPacket(s.wrapKey, wire[:n], plain)
					if unwrapErr != nil {
						// Corrupted or unrecognised packet — skip silently.
						turnLog("[STREAM %d] WRAP RX skip: %v", s.id, unwrapErr)
						continue
					}
					data = plain[:m]
				} else {
					data = wire[:n]
				}
				if _, err := c2.WriteTo(data, peer); err != nil {
					relayTxErrorCount.Add(1)
					reportErr(fmt.Errorf("pipe write: %w", err))
					return
				}
			}
		}
	}()

	// The handshake FSM watches this context between flights, so the timeout
	// cuts a blackholed relay off at dataPlaneHandshakeTimeout wherever it is
	// in the retransmit schedule.
	hsCtx, hsCancel := context.WithTimeout(sCtx, dataPlaneHandshakeTimeout)
	err = dtlsConn.HandshakeContext(hsCtx)
	hsCancel()
	if err != nil {
		return fmt.Errorf("%w: DTLS handshake failed: %w", errDataPlaneHandshake, err)
	}
	turnLog("[STREAM %d] DTLS handshake OK", s.id)
	noteServerHandshakeOK(s.serverAddr)
	s.notePathProven()
	markNetworkPathProven(s.networkGeneration)

	// Session + stream ID handshake (proxy_v2 only). Sent as a small burst
	// for the same reason as runNoDTLS — even though DTLS is ordered, the
	// server's handleConn does the session-ID parse on the first record only,
	// so a missed/delayed first record can stall the stream. Duplicates after
	// the first are skipped server-side (17-byte filter).
	if sendHandshake {
		dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 17)
		copy(buf[:16], s.sessionID)
		buf[16] = byte(s.id)
		const burstCount = 3
		const burstGap = 50 * time.Millisecond
		for i := 0; i < burstCount; i++ {
			if _, err := dtlsConn.Write(buf); err != nil {
				return fmt.Errorf("session handshake send #%d: %w", i+1, err)
			}
			if i < burstCount-1 {
				time.Sleep(burstGap)
			}
		}
		dtlsConn.SetWriteDeadline(time.Time{})
	}

	// Published before ready, so the dispatcher never judges this session by
	// the previous one's liveness clock (see dispatchStale).
	activity := newStreamActivity(time.Now(), s.kaPhase)
	s.activity.Store(activity)
	// Downlink feedback (WGH1) for this attempt only: a fresh nonce, and no
	// capability until this very transport hears a matching ACK.
	control := s.newFeedbackControl()
	defer s.control.CompareAndSwap(control, nil)

	wg.Add(3)

	// WireGuard → DTLS (TX)
	go func() {
		defer wg.Done()
		defer ready.end()
		reader := outboundReader{s: s}
		for {
			b, ok := reader.next(sCtx)
			if !ok {
				return
			}
			_, err := dtlsConn.Write(b)
			packetPool.Put(b[:cap(b)])
			if err != nil {
				dtlsTxDropCount.Add(1)
				reportErr(fmt.Errorf("DTLS write: %w", err))
				return
			}
		}
	}()

	// DTLS → WireGuard (RX)
	go func() {
		defer wg.Done()
		defer ready.end()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, err := dtlsConn.Read(buf)
			if err != nil {
				dtlsRxErrorCount.Add(1)
				reportErr(fmt.Errorf("DTLS read: %w", err))
				return
			}
			// dtlsConn.Read only returns authenticated application data, so this
			// is valid inbound liveness evidence.
			activity.noteRx(time.Now())
			markNetworkPathProven(s.networkGeneration)
			if control.receive(buf[:n]) {
				continue
			}
			if isStunKeepalive(buf[:n]) {
				// Keepalive echo: liveness recorded, don't feed it to WG. The
				// echo names the ping it answers (wake_probe.go).
				activity.noteProbeEcho(buf[:n])
				continue
			}
			if n == 0 {
				continue
			}
			if a := s.peer.Load(); a != nil {
				downlinkRelayLoss.observe(buf[:n], relayAddr, time.Now())
				if _, err := s.out.WriteTo(buf[:n], *a); err != nil {
					dtlsRxErrorCount.Add(1)
					reportErr(fmt.Errorf("TUN write: %w", err))
					return
				}
			}
		}
	}()

	// Keepalive + dead-stream detection (one coalesced loop; see runKeepalive).
	// The STUN Indication goes via dtlsConn.Write so the server receives a valid
	// DTLS ApplicationData record (refreshing its 5-min read deadline) and echoes
	// the 20 bytes straight back through this stream; the echo advances the
	// liveness clock in the DTLS→WireGuard RX goroutine — the only proof of a
	// live path (a dead allocation still accepts the write). runKeepalive tears
	// the stream down when the clock goes stale past deadStreamTimeout,
	// replacing the former relay read-deadline and watchdog.
	go func() {
		defer wg.Done()
		defer ready.end()
		s.runKeepalive(sCtx, activity, reportErr, func(int) error {
			_, err := dtlsConn.Write(control.keepalive())
			return err
		}, func(seq uint64) error {
			_, err := dtlsConn.Write(stunProbe(seq))
			return err
		})
	}()

	if ready.publish() {
		// The judge of silence under load takes this stream's row now, not on
		// the next packet anyone hears (silent_under_load.go).
		wakeSilentUnderLoadJudge()
		// Ask right away rather than at the next grid tick, so the reporter can
		// use this stream as soon as the server has answered.
		if control != nil {
			s.enqueueControl(control.keepalive())
		}
		s.okFunc()
	}
	wg.Wait()
	select {
	case err := <-firstErr:
		return err
	default:
		return nil
	}
}

// runSRTP — DTLS-SRTP transport (peer-type "srtp", VP8-mimic).
//
// Structurally a sibling of runDTLS, but the relay TX/RX + DTLS pipework is
// owned by srtpwrap.Client: it terminates a DTLS-SRTP session over the TURN
// relay and returns a net.Conn where each Write frames one payload as an
// RTP+SRTP packet (PayloadType 100 — looks like VP8 WebRTC video to VK's
// content classifier) and each Read returns one decrypted payload. WRAP is
// not used here — SRTP already encrypts. The session/stream multiplexing
// model is preserved exactly: the 17-byte session header is sent first, so
// the server aggregates this stream's sibling SRTP sessions onto one
// WireGuard backend conn.
func (s *stream) runSRTP(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr) error {
	// The relay this session runs on, for the downlink loss per relay
	// (relay_loss.go). Set by runSession before the transport starts.
	relayAddr := s.serverAddr
	sCtx, sCancel := context.WithCancel(ctx)
	ready := newSessionReadiness(sCtx, sCancel, s)
	defer ready.end()

	// firstErr captures the root cause when a goroutine fails and calls ready.end().
	// See runDTLS for the full rationale (nil return would be misread by
	// WorkerGroup as "server closed stream, rotate credentials").
	firstErr := make(chan error, 1)
	reportErr := func(err error) {
		select {
		case firstErr <- err:
		default:
		}
	}

	// srtpwrap.Client owns the relayConn read loop internally; closing the
	// relay on ctx cancel unblocks it so the session tears down cleanly.
	context.AfterFunc(sCtx, func() {
		ready.end()
		relayConn.Close()
	})

	hsCtx, hsCancel := context.WithTimeout(sCtx, dataPlaneHandshakeTimeout)
	srtpConn, err := srtpwrap.Client(hsCtx, relayConn, peer)
	hsCancel()
	if err != nil {
		return fmt.Errorf("%w: SRTP handshake failed: %w", errDataPlaneHandshake, err)
	}
	defer srtpConn.Close()
	context.AfterFunc(sCtx, func() {
		ready.end()
		srtpConn.Close()
	})
	turnLog("[STREAM %d] SRTP handshake OK", s.id)
	noteServerHandshakeOK(s.serverAddr)
	s.notePathProven()
	markNetworkPathProven(s.networkGeneration)

	// Session + stream ID handshake (proxy_v2 model). Sent as a small burst
	// for the same reason as runDTLS — the server parses the session ID on the
	// first payload; duplicates after the first are skipped server-side
	// (17-byte filter).
	{
		srtpConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 17)
		copy(buf[:16], s.sessionID)
		buf[16] = byte(s.id)
		const burstCount = 3
		const burstGap = 50 * time.Millisecond
		for i := 0; i < burstCount; i++ {
			if _, err := srtpConn.Write(buf); err != nil {
				return fmt.Errorf("session handshake send #%d: %w", i+1, err)
			}
			if i < burstCount-1 {
				time.Sleep(burstGap)
			}
		}
		srtpConn.SetWriteDeadline(time.Time{})
	}

	// Published before ready, so the dispatcher never judges this session by
	// the previous one's liveness clock (see dispatchStale).
	activity := newStreamActivity(time.Now(), s.kaPhase)
	s.activity.Store(activity)
	// Downlink feedback (WGH1) for this attempt only: a fresh nonce, and no
	// capability until this very transport hears a matching ACK.
	control := s.newFeedbackControl()
	defer s.control.CompareAndSwap(control, nil)

	var wg sync.WaitGroup
	wg.Add(3)

	// WireGuard → SRTP (TX)
	go func() {
		defer wg.Done()
		defer ready.end()
		reader := outboundReader{s: s}
		for {
			b, ok := reader.next(sCtx)
			if !ok {
				return
			}
			srtpConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_, err := srtpConn.Write(b)
			packetPool.Put(b[:cap(b)])
			if err != nil {
				dtlsTxDropCount.Add(1)
				reportErr(fmt.Errorf("SRTP write: %w", err))
				return
			}
		}
	}()

	// SRTP → WireGuard (RX)
	go func() {
		defer wg.Done()
		defer ready.end()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, err := srtpConn.Read(buf)
			if err != nil {
				dtlsRxErrorCount.Add(1)
				reportErr(fmt.Errorf("SRTP read: %w", err))
				return
			}
			// srtpConn.Read has already authenticated and decrypted this packet.
			activity.noteRx(time.Now())
			markNetworkPathProven(s.networkGeneration)
			if control.receive(buf[:n]) {
				continue
			}
			if isStunKeepalive(buf[:n]) {
				// Keepalive echo: liveness recorded, don't feed it to WG. The
				// echo names the ping it answers (wake_probe.go).
				activity.noteProbeEcho(buf[:n])
				continue
			}
			if n == 0 {
				continue
			}
			if a := s.peer.Load(); a != nil {
				downlinkRelayLoss.observe(buf[:n], relayAddr, time.Now())
				if _, err := s.out.WriteTo(buf[:n], *a); err != nil {
					dtlsRxErrorCount.Add(1)
					reportErr(fmt.Errorf("TUN write: %w", err))
					return
				}
			}
		}
	}()

	// Keepalive + dead-stream detection (one coalesced loop; see runKeepalive).
	// The STUN Indication goes through the SRTP pipe; the server echoes it back
	// through this stream and the echo advances the liveness clock in the
	// SRTP→WireGuard RX goroutine — the only proof of a live path. runKeepalive
	// tears the stream down when the clock goes stale. (srtpwrap owns the relay
	// read loop, so this per-stream detector is the only dead-path signal SRTP
	// has.)
	go func() {
		defer wg.Done()
		defer ready.end()
		s.runKeepalive(sCtx, activity, reportErr, func(int) error {
			_, err := srtpConn.Write(control.keepalive())
			return err
		}, func(seq uint64) error {
			_, err := srtpConn.Write(stunProbe(seq))
			return err
		})
	}()

	if ready.publish() {
		// The judge of silence under load takes this stream's row now, not on
		// the next packet anyone hears (silent_under_load.go).
		wakeSilentUnderLoadJudge()
		// Ask right away rather than at the next grid tick, so the reporter can
		// use this stream as soon as the server has answered.
		if control != nil {
			s.enqueueControl(control.keepalive())
		}
		s.okFunc()
	}
	wg.Wait()
	select {
	case err := <-firstErr:
		return err
	default:
		return nil
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Global state
// ─────────────────────────────────────────────────────────────────────────────

var currentTurnCancel context.CancelFunc
var currentTurnDone <-chan struct{}

// currentListener — loopback-слушатель текущего поколения прокси. StopProxy
// закрывает его синхронно, чтобы перезапуск транспорта (Tunnel.RestartTransport)
// мог занять тот же порт — WireGuard продолжает слать на него.
var currentListener net.PacketConn
var turnMutex sync.Mutex
var globalGetCreds getCredsFunc

// SetNetworkAvailable — внешний API: хост сообщает, есть ли у машины путь в
// интернет (на Windows — физический дефолтный шлюз, см. winbridge). Пока его
// нет, воркеры не ходят в VK и не делают Allocate, а ждут у гейта
// (network_availability.go) — иначе отвал Wi-Fi жёг креды и квоту Allocate, а
// это прямая дорога к капче. Пропажа шлюза (переход «есть → нет») закрывает
// гейт сразу, вместе с доказательством пути от потоков. Если же шлюза не было
// с самого начала (маршрут по умолчанию без шлюза — PPPoE, модем), гейт держат
// открытым свежее доказательство пути и проба раз в минуту. Хост может дёргать
// это на каждом опросе — в лог попадают только переходы.
func SetNetworkAvailable(available bool) {
	wasValidated, _, _, _ := networkAvailabilitySnapshot()
	setNetworkAvailable(available)
	if wasValidated == available {
		return
	}
	// The network gone or back: a dark found on the path before says nothing
	// about the one after (dark_scout.go).
	resetDarkPaths()
	validated, proven, effective, remaining := networkAvailabilitySnapshot()
	turnLog("[PROXY] hostValidated=%t transportProven=%t effectiveAvailable=%t proofTTL=%v",
		validated, proven, effective, remaining.Round(time.Second))
}

// ─────────────────────────────────────────────────────────────────────────────
// Link parsing helpers
// ─────────────────────────────────────────────────────────────────────────────

func parseLinks(raw string, maxLinks int) []string {
	raw = strings.ReplaceAll(raw, "|", ",")
	var links []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			links = append(links, p)
		}
	}
	if len(links) == 0 {
		return []string{""}
	}
	if len(links) > maxLinks {
		links = links[:maxLinks]
	}
	return links
}

// StartProxyParams — параметры для StartProxy.
type StartProxyParams struct {
	PeerAddr   string // WireGuard peer endpoint (host:port)
	VKLink     string // VK link(s), comma- или pipe-separated
	Mode       string // "dtls" | "nodtls"
	StreamNum  int    // желаемое общее количество стримов
	UseUDP     bool
	ListenAddr string // loopback listener (например 127.0.0.1:0)
	// Parent — контекст поколения прокси. Его отмена останавливает старт даже
	// раньше, чем StartProxy зарегистрировал свой cancel: Tunnel.Stop во время
	// перезапуска транспорта не оставляет прокси-сироту. nil — Background.
	Parent context.Context
	// OnListen получает фактический адрес слушателя (порт :0 разрешён ОС) до
	// пре-фетча кредов — так капча и WireGuard видят настоящий порт.
	OnListen func(addr string)
	// KeepDNSCache — не сбрасывать DNS-кеш при старте: перезапуск транспорта
	// идёт под поднятым VPN, где у старых адресов уже есть bypass-маршруты, а
	// новый резолв через публичный резолвер ушёл бы в мёртвый туннель.
	KeepDNSCache    bool
	TurnIP          string // pre-resolved TURN server IP
	TurnPort        int
	ExtraRelays     string // #@wgt:ExtraRelays, unparsed (relay_extra.go)
	PeerType        string // "VK" | "WB"
	StreamsPerCred  int
	WatchdogTimeout int      // seconds
	WrapKey         string   // base64 или "" чтобы отключить WRAP
	SystemDNS       []string // системные DNS-резолверы (опционально)
}

// StartProxy запускает TURN-прокси. Возвращает 0 при первом готовом стриме,
// -1 при ошибке/таймауте, -2 при CALL_REQUIRES_AUTH, -4 при CALL_UNAVAILABLE
// (звонок завершён/удалён или ссылка недействительна — ретраи бессмысленны),
// -5 при таймауте без кредов и без единого байта от VK (startVKUnreachable).
// -6 при таймауте, когда креды были и релеи выдали аллокации, но ни один поток
// не провёл через релей ни одного круга (startRelaysCarryNothing).
func StartProxy(p StartProxyParams) int32 {
	parent := p.Parent
	if parent == nil {
		parent = context.Background()
	}

	if len(p.SystemDNS) > 0 {
		InitSystemDns(p.SystemDNS)
	}

	listenAddr := p.ListenAddr
	mode := p.Mode
	peerType := p.PeerType
	watchdogTimeout := p.WatchdogTimeout
	extraRelays, badRelays := parseExtraRelays(p.ExtraRelays)
	if len(badRelays) > 0 {
		turnLog("[PROXY] ExtraRelays: skipping %v — not an IP address with an optional port", badRelays)
	}
	if len(extraRelays) > 0 {
		turnLog("[PROXY] Extra relays on top of each link's own: %v", extraRelays)
	}

	// ── WRAP key parsing ──────────────────────────────────────────────────────
	var wrapKey []byte
	if p.WrapKey != "" {
		decoded, err := decodeWrapKey(true, p.WrapKey)
		if err != nil {
			turnLog("[PROXY] Invalid wrapKey: %v", err)
			return -1
		}
		wrapKey = decoded
		turnLog("[PROXY] WRAP obfuscation enabled")
	}

	turnMutex.Lock()
	// A generation cancelled before its goroutine got here — a transport
	// restart, then another, with the next one up already — claims nothing: it
	// would cancel the running proxy and close its listener (Codex review of
	// the Windows port, 2026-10-23). The restart that started the next one
	// cancelled this one first, so under the lock it either comes first or
	// sees the cancel.
	if parent.Err() != nil {
		turnMutex.Unlock()
		turnLog("[PROXY] Startup cancelled before it began")
		return -1
	}
	if currentTurnCancel != nil {
		currentTurnCancel()
	}
	// The previous generation's listener goes now, not when its context's
	// AfterFunc gets to it: this start may bind the same port.
	if currentListener != nil {
		currentListener.Close()
		currentListener = nil
	}
	ctx, cancel := context.WithCancel(parent)
	currentTurnCancel = cancel
	turnMutex.Unlock()

	// The process-wide state the running proxy keeps, from here on this
	// one's: not before the claim above, or a start cancelled before it began
	// would reset the running one's — its streams' path proofs among it.
	networkGeneration := beginNetworkPathGeneration()
	if !p.KeepDNSCache {
		clearTransientState() // flush DNS + HTTP without clearing credential caches
	}
	// Credentials, and usually the server list itself, are new for this session.
	resetServerHealth()
	// Drop the previous session's terminal verdict before anything can poll it:
	// WaitReady reads it ahead of the bootstrap result, so a stale reason would
	// mask this session's own outcome. total=0 also makes it inert until
	// StartTunnelGroups re-arms it with the real worker count.
	resetWorkerFatalState(0)

	// A new proxy, a new path: whatever the last one found dark is not this
	// one's (dark_scout.go). After the previous proxy has been cancelled, so
	// that none of its workers finds it again. Nor do its connects pace this
	// one's (relay_connect_pacing.go).
	resetDarkPaths()
	resetRelayConnectPacing()

	// Reset the captcha lockout and its escalation only after the previous proxy
	// has been cancelled: its workers unwind through the "solve ladder exhausted"
	// path, and each such exit arms the lockout. Resetting before the cancel let
	// a dying session hand its lockout to the session starting here — and since
	// the streak only clears on a successful fetch, a single unsolvable-captcha
	// episode would then make every later reconnect give up on its first error.
	resetCaptchaLockout()

	// ── Credential mode setup ─────────────────────────────────────────────────
	turnLog("[PROXY] VK Link credential mode")
	rawLinks := parseLinks(p.VKLink, 8)
	links := make([]string, len(rawLinks))
	for i, raw := range rawLinks {
		links[i] = joinHash(raw) // the same reduction the link check applies
	}
	// What the startup timeout below reports (startTimeoutCode): whether any
	// credential reached this start — a cache hit counts — and whether VK sent a
	// byte back over any connection since it began.
	evidence := beginStartEvidence()
	globalGetCreds = func(ctx context.Context, lk string, streamID int) (string, string, []string, error) {
		u, p, a, err := getCredsCached(ctx, lk, streamID, fetchVkCreds)
		if err == nil {
			evidence.creds.Store(true)
		}
		return u, p, a, err
	}

	// ── Apply StreamNum cap / expand ─────────────────────────────────────────
	// Keep every link: below the configured capacity, split n evenly over the
	// links (at least one stream each). Above it, add groups by cycling links
	// and let the last group take the remainder. Credential slots are keyed by
	// groupID: fetchCreds uses groupID*streamsPerCred, not a live stream's ID.
	// Keep the configured capacity for that mapping, even with unequal groups,
	// and publish it once so departing workers never see intermediate values.
	// Splitting the capacity itself instead (n/links each) dropped the
	// remainder: three links of four at StreamNum=10 ran 9 streams.
	perCred := clampStreamsPerCred(p.StreamsPerCred)
	counts := groupStreamCounts(len(links), perCred, p.StreamNum)
	if len(counts) > len(links) {
		origLinks := links
		links = make([]string, len(counts))
		for i := range links {
			links[i] = origLinks[i%len(origLinks)]
		}
	}
	totalStreams := 0
	for _, count := range counts {
		totalStreams += count
	}
	setStreamsPerCred(perCred)

	// Peer and WRAP are said once here rather than on every stream session:
	// they cannot change until the next start.
	turnLog("[PROXY] Starting: listen=%s StreamNum=%d groups=%v links=%d actualTotal=%d mode=%s peerType=%s peer=%s wrap=%v watchdog=%ds",
		listenAddr, p.StreamNum, counts, len(links), totalStreams, mode, peerType, p.PeerAddr, wrapKey != nil, watchdogTimeout)

	// ── DNS resolution ────────────────────────────────────────────────────────
	peer, err := resolvePeer(p.PeerAddr)
	if err != nil {
		turnLog("[PROXY] Cannot resolve peer %s: %v", p.PeerAddr, err)
		return -1
	}

	// ── Local listener ────────────────────────────────────────────────────────
	lc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		turnLog("[PROXY] ListenPacket failed: %v", err)
		return -1
	}
	context.AfterFunc(ctx, func() { lc.Close() })
	turnMutex.Lock()
	currentListener = lc
	turnMutex.Unlock()
	if p.OnListen != nil {
		p.OnListen(lc.LocalAddr().String())
	}

	sessionID, _ := uuid.New().MarshalBinary()
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		turnLog("[PROXY] DTLS cert generation failed: %v", err)
		return -1
	}

	var packetLc net.PacketConn = lc

	// ── Pre-fetch credentials for all groups ─────────────────────────────────
	// Done before VPN tunnel is established so any captcha WebView runs over
	// the physical network. vkSemaphore(2) allows pairs of groups to fetch in
	// parallel — taken by the fetch itself (getCredsCached), so a group whose
	// credential is cached is not held behind two that go to VK. WorkerGroups
	// will get cache hits on their first cycle and start streams immediately
	// without waiting for another VK round-trip.
	turnLog("[PROXY] Pre-fetching credentials for %d group(s)...", len(links))
	var prefetchWg sync.WaitGroup
	var callRequiresAuth int32
	var prefetchOk int32      // set to 1 if any group succeeds
	var callUnavailable int32 // set to 1 if any group's call is dead/deleted/invalid link
	for i, lk := range links {
		prefetchWg.Add(1)
		go func(groupID int, link string) {
			defer prefetchWg.Done()
			_, _, _, prefetchErr := fetchCreds(ctx, link, groupID)
			if prefetchErr != nil {
				if ctx.Err() == nil {
					if strings.Contains(prefetchErr.Error(), "CALL_REQUIRES_AUTH") {
						atomic.StoreInt32(&callRequiresAuth, 1)
						turnLog("[PROXY] Pre-fetch group %d: CALL_REQUIRES_AUTH — aborting", groupID)
					} else if strings.Contains(prefetchErr.Error(), "CALL_UNAVAILABLE") {
						atomic.StoreInt32(&callUnavailable, 1)
						turnLog("[PROXY] Pre-fetch group %d: CALL_UNAVAILABLE (call ended/deleted or invalid link)", groupID)
					} else {
						turnLog("[PROXY] Pre-fetch group %d failed: %v (WorkerGroup will retry)", groupID, prefetchErr)
					}
				}
			} else {
				atomic.StoreInt32(&prefetchOk, 1)
				turnLog("[PROXY] Pre-fetch group %d OK", groupID)
			}
		}(i, lk)
	}
	prefetchWg.Wait()
	if ctx.Err() != nil {
		// Stopped or rebuilt while it prefetched: the next proxy may be up
		// already, and this one claims nothing of it (runningProxyMu).
		turnLog("[PROXY] Startup cancelled during the pre-fetch")
		return -1
	}
	if atomic.LoadInt32(&callRequiresAuth) == 1 {
		cancel()
		return -2
	}
	if atomic.LoadInt32(&prefetchOk) == 0 && atomic.LoadInt32(&callUnavailable) == 1 {
		turnLog("[PROXY] All pre-fetches failed: call unavailable (ended/deleted or invalid link) — aborting startup")
		cancel()
		return -4 // distinct code: dead call — no retry/captcha can recover it
	}

	// ── Launch groups ─────────────────────────────────────────────────────────
	_, okChan, done, err := StartTunnelGroups(ctx, packetLc, TunnelGroupsConfig{
		Links:             links,
		PeerAddr:          peer,
		PeerType:          peerType,
		UseUDP:            p.UseUDP,
		TurnIP:            p.TurnIP,
		TurnPort:          p.TurnPort,
		ExtraRelays:       extraRelays,
		GroupStreams:      counts,
		Cert:              &cert,
		SessionID:         sessionID,
		WatchdogTimeout:   watchdogTimeout,
		WrapKey:           wrapKey,
		NetworkGeneration: networkGeneration,
		Start:             evidence,
	})
	if err != nil {
		turnLog("[PROXY] StartTunnelGroups failed: %v", err)
		cancel()
		return -1
	}
	// Publish the done channel so StopProxy can wait for every group (and
	// thus every relayConn.Close() / allocation-delete) to drain — unless this
	// proxy has been cancelled since its groups started: the next one's may be
	// published already, and StopProxy would wait on this one's instead.
	turnMutex.Lock()
	if ctx.Err() == nil {
		currentTurnDone = done
	}
	turnMutex.Unlock()

	// Startup timeout: if no stream proves its data plane within this window,
	// the server is unreachable or the transport is being blocked. Bail out so
	// the UI can surface a "failed to connect" state instead of spinning forever.
	// 30s covers a handshake that times out on one relay
	// (dataPlaneHandshakeTimeout) plus the reconnect onto the other; if neither
	// carries a round trip in that time, further worker retries are wasted at
	// startup.
	const startupTimeout = 30 * time.Second
	select {
	case <-okChan:
		turnLog("[PROXY] First stream ready — tunnel is up")
		return 0
	case <-ctx.Done():
		turnLog("[PROXY] Startup cancelled")
		return -1
	case <-time.After(startupTimeout):
		code := startTimeoutCode(evidence.creds.Load(), evidence.vkHeard(), evidence.relaysCarriedNothing())
		switch code {
		case startVKUnreachable:
			turnLog("[PROXY] Startup timeout — no credentials, and VK never sent a byte back over this network since the start began")
		case startRelaysCarryNothing:
			turnLog("[PROXY] Startup timeout — the relays granted allocations, and no stream carried a round trip through one within %v", startupTimeout)
		default:
			turnLog("[PROXY] Startup timeout — no stream proved its data plane within %v", startupTimeout)
		}
		cancel()
		return code
	}
}

// allocationDrainTimeout bounds how long StopProxy waits for worker
// goroutines to unwind (and flush their TURN allocation-delete packets).
const allocationDrainTimeout = 3 * time.Second

// StopProxy — внешний API (вызывается Tunnel.Stop).
func StopProxy() {
	resetNetworkPathProof()
	turnMutex.Lock()
	cancel := currentTurnCancel
	done := currentTurnDone
	lc := currentListener
	currentTurnCancel = nil
	currentTurnDone = nil
	currentListener = nil
	turnMutex.Unlock()

	if cancel != nil {
		turnLog("[PROXY] Stopping TURN proxy")
		cancel()
		// Wait (bounded) for worker goroutines to unwind so each stream's
		// relayConn.Close() runs and sends TURN Refresh(lifetime=0) — this frees
		// the server-side allocation now instead of letting it linger until its
		// lifetime expires (which would otherwise eat the per-credential quota
		// on a quick reconnect).
		if done != nil {
			select {
			case <-done:
			case <-time.After(allocationDrainTimeout):
				turnLog("[PROXY] Stop: allocation drain timed out")
			}
		}
	}
	// Synchronously, so the port is free by the time this returns: a transport
	// rebuild binds it again at once.
	if lc != nil {
		lc.Close()
	}
	// Credential caches are intentionally preserved across stops so an immediate
	// reconnect gets a cache hit and avoids a fresh VK API round-trip (and captcha).
	// If old TURN allocations lingered (drain timed out) and the quota is exhausted,
	// a worker's 486 handler calls refreshGroupCreds → throttled re-fetch automatically.
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func resolvePeer(peerAddr string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(peerAddr)
	if err != nil {
		return net.ResolveUDPAddr("udp", peerAddr)
	}
	if net.ParseIP(host) == nil {
		resolvedIP, err := hostCache.Resolve(context.Background(), host)
		if err != nil {
			turnLog("[DNS] Peer resolution warning: %v — using original", err)
		} else {
			peerAddr = net.JoinHostPort(resolvedIP, port)
		}
	}
	return net.ResolveUDPAddr("udp", peerAddr)
}
