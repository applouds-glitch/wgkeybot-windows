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
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/turn/v5"
)

// errDataPlaneHandshake marks the one failure the static assignment used to be
// blind to: Allocate succeeded, so the control plane and the credential are
// fine, and the transport handshake through the relay still never completed.
// Every transport wraps its handshake failure with this so runSession can tell
// it apart from a session that ran and then broke.
var errDataPlaneHandshake = errors.New("data-plane handshake failed")

// sessionVerdict is what a finished session says about the server it ran on.
type sessionVerdict int

const (
	// verdictNone: the session says nothing — we tore it down ourselves, it ended
	// cleanly without lasting long enough to prove anything, or its relay went
	// silent on it before it had (see sessionOutcome).
	verdictNone sessionVerdict = iota
	verdictSuccess
	verdictFailure
	// verdictHandshakeFailure: allocated, then never completed the transport
	// handshake. Acted on immediately rather than through the streak.
	verdictHandshakeFailure
)

func (v sessionVerdict) String() string {
	switch v {
	case verdictSuccess:
		return "success"
	case verdictFailure:
		return "failure"
	case verdictHandshakeFailure:
		return "handshake-failure"
	default:
		return "none"
	}
}

// sessionOutcome grades a finished session for the health accounting in
// turn_server_health.go.
//
// A blackholed allocation is the clearest verdict there is: the control plane
// answered, so the credential and the path are fine, and the host still ate the
// traffic. Otherwise a session that ran for a while proves the server works, and
// a short one that ended in an error counts against it. Teardowns are excluded —
// cancelled means cancelled by us, not by the server.
//
// "Ran" is counted up to the last packet the relay delivered, not to the end of
// the session's existence. The dead-stream detector ends a session only after
// deadStreamTimeout of silence, which is longer than healthySessionDuration: a
// relay that completed the handshake and never delivered another packet was
// booked as a success every time — each round of it wiped the strikes the relay
// had, and lifted a stand-down. The silence at the end (counted from the last
// packet that really arrived, freezes included) is taken off before the length
// is judged.
//
// What is left of such a session, if it is short, is no verdict at all rather
// than a failure. One stream going deaf does not say whose fault it was — its
// allocation, its path, the server behind the relay or the relay — and telling
// them apart takes a witness: over UDP every stream shares the one relay, so
// three deaf ones would stand it down under those still running. Android tried
// both ways of picking the witness and dropped them on 2026-09-21: any
// neighbour heard lately lets streams that reconnect in turn vouch for one
// another on the strength of their handshakes alone, and only a neighbour with
// traffic since its handshake leaves a healthy relay without witnesses for half
// a minute after every reconnect. A relay that is really gone still earns its
// strikes where the evidence is its own: on the redial, at the Allocate or the
// handshake.
//
// A blackhole is graded by what the watchdog ended the session for (hole). The
// relay going silent on the session — ChannelBind, a refresh unanswered — is
// the failure above. The relay answering that it no longer knows this socket
// (blackholeOutOfReach, a 400) is not: it answered within a round trip, and
// what it lost track of is ours to have lost — a mapping the translator forgot
// while the machine slept, an allocation that lapsed meanwhile. That is the
// fact the post-wake probe finds too, and its verdict is graded as any deaf
// session is: by how long the relay was heard. So is this one, silent being
// how long the relay had been silent when the session ended. It used to be a
// failure, whatever the session had carried — an hour-long one cut by a 400 at
// a thaw added a strike instead of clearing them, and three thaws stood a
// working relay down (iOS field, 2026-10).
func sessionOutcome(cancelled bool, hole blackholeKind, dur, silent time.Duration, err error) sessionVerdict {
	var dead *deadStreamError
	deaf := errors.As(err, &dead)
	if deaf {
		dur -= dead.silent
	}
	switch {
	case cancelled:
		return verdictNone
	case hole == blackholeOutOfReach:
		if !deaf {
			dur -= silent
		}
		if dur >= healthySessionDuration {
			return verdictSuccess
		}
		return verdictNone
	case hole == blackholeRelay:
		return verdictFailure
	case dur >= healthySessionDuration:
		return verdictSuccess
	case errors.Is(err, errDataPlaneHandshake):
		return verdictHandshakeFailure
	case deaf:
		return verdictNone
	case err != nil:
		return verdictFailure
	default:
		return verdictNone
	}
}

// sessionSilence is how long the relay had been silent when the session that
// began at started ended at now — what an out-of-reach end is graded by
// (sessionOutcome); a is the stream's clock. A session whose transport never
// published its own leaves the last session's, older than this one, and that
// grades it as having carried nothing, which is so.
//
// So does a stream's first session, which leaves none. DTLS and SRTP publish
// the clock only after their handshake, and a first handshake that slept past
// healthySessionDuration, then was cut by a 400 at the thaw (alloc_check.go),
// was graded on its whole length: a success, which wipes the relay's strikes,
// for a session that never carried a packet (Codex review of the iOS port,
// 23.10).
func sessionSilence(a *streamActivity, started, now time.Time) time.Duration {
	if a == nil {
		return now.Sub(started)
	}
	return a.heardAge(now)
}

// blackholeKind is what, if anything, the control-plane watchdog (permWatch)
// ended a session for.
type blackholeKind int

const (
	noBlackhole blackholeKind = iota
	// blackholeRelay: the relay went silent on the session — a ChannelBind or
	// a refresh nothing answered.
	blackholeRelay
	// blackholeOutOfReach: the relay answered that it has no allocation for
	// this socket, a 400 on CreatePermission (permWatch.unreachable).
	blackholeOutOfReach
)

// sessionBlackhole is the kind of blackhole perm ended its session for.
//
// Fired first, then the kind: the kind is stored before dead is closed, so a
// watchdog seen fired shows its kind. Asked the other way round, a 400 the
// allocation check latched between the two reads came out as a silent relay
// (Codex review, 23.10). runSession takes it once and grades the session and
// marks its seat (sessionOutOfReach) off that one reading.
func sessionBlackhole(perm *permWatch) blackholeKind {
	switch {
	case !perm.fired():
		return noBlackhole
	case perm.unreachable.Load():
		return blackholeOutOfReach
	default:
		return blackholeRelay
	}
}

// winner holds a successfully allocated TURN session from the race in
// runWithCreds. The fields are the live resources handed off to the session:
// runSession owns them and is responsible for closing them.
type winner struct {
	client *turn.Client
	raw    net.Conn       // underlying dialed UDP/TCP conn
	relay  net.PacketConn // relay allocation from client.Allocate()
	addr   string         // TURN server the session runs on
	rtt    time.Duration  // Dial → Allocate latency
	perm   *permWatch     // control-plane blackhole detector for this session
	user   string         // the TURN username it was allocated with
}

// runWithCreds establishes one TURN session with pre-fetched credentials on the
// stream's own server, addrs[0] (see assignRelays). There is no latency
// race: only if that server fails to Allocate are the remaining candidates
// dialed, all at once, and the first of those to complete Allocate takes the
// session while the others are cancelled/closed. The assignment is per attempt,
// so the next reconnect goes back to the stream's own server. Retry and
// credential rotation are managed by the calling WorkerGroup.
func (s *stream) runWithCreds(ctx context.Context, user, pass string, addrs []string, cfg WorkerGroupConfig) error {
	s.ready.Store(false)
	// Not ready first, so the dispatcher stops adding; then what it had added for
	// the session that just ended goes (see drainOutbound).
	defer func() {
		s.ready.Store(false)
		if n := s.drainOutbound(); n > 0 {
			turnLog("[STREAM %d] dropped %d packet(s) still queued for the session that ended", s.id, n)
		}
	}()

	// raceCtx is cancelled the moment a winner is chosen (or ctx dies) so the
	// losing failover candidates stop dialing / abort their semaphore wait
	// promptly.
	raceCtx, cancelRace := context.WithCancel(ctx)
	defer cancelRace()

	var once sync.Once
	winCh := make(chan winner, 1)
	errCh := make(chan relayAttemptError, len(addrs))
	var wg sync.WaitGroup

	// Over TCP the first relay has a head start (relayHeadStart): allocating
	// carries the release of its Allocate slot to the loop below at the moment
	// its request goes out, and connecting the start of its connect — the
	// relay can be silent a step earlier there. Over UDP neither fires.
	overTCP := relayOverTCP(cfg)
	allocating := make(chan func(), 1)
	connecting := make(chan struct{}, 1)
	// Only for the log line when the head start runs out: whether the first
	// relay had taken the TCP connection by then (headStartExpired).
	var headConnected atomic.Bool

	launch := func(addr string) {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			opts := dialOpts{session: ctx}
			if overTCP && addr == addrs[0] {
				opts.allocating = func(release func()) { allocating <- release }
				opts.connecting = func() { connecting <- struct{}{} }
				opts.connected = headConnected.Store
			}
			client, raw, relay, rtt, perm, err := dialAndAllocate(raceCtx, s, user, pass, addr, cfg, opts)
			if err != nil {
				errCh <- relayAttemptError{addr: addr, err: err, at: time.Now()}
				return
			}
			claimed := false
			once.Do(func() {
				claimed = true
				cancelRace()
				winCh <- winner{client: client, raw: raw, relay: relay, addr: addr, rtt: rtt, perm: perm, user: user}
			})
			if !claimed {
				// Another failover candidate got there first: log this
				// server's RTT, then release the surplus allocation
				// (relayConn.Close → Refresh(lifetime=0) deallocates server-side).
				turnLog("[STREAM %d] Failover candidate %s lost rtt=%v (group %d)", s.id, addr, rtt, cfg.GroupID)
				relay.Close()
				client.Close()
				raw.Close()
			}
		}(addr)
	}

	launch(addrs[0])
	launchedCount := 1
	fannedOut := len(addrs) == 1

	fanOut := func() {
		if fannedOut {
			return
		}
		for _, a := range addrs[1:] {
			launch(a)
			launchedCount++
		}
		fannedOut = true
	}

	var headRelease func()
	var headStart <-chan time.Time
	var headStartTimer *time.Timer
	defer func() {
		if headStartTimer != nil {
			headStartTimer.Stop()
		}
	}()
	// One clock, restarted per step: the TCP connect, then the Allocate. A relay
	// that took its time over the connect has still answered, and its Allocate
	// gets a full head start of its own.
	startHeadStart := func() {
		if headStartTimer != nil {
			headStartTimer.Stop()
		}
		headStartTimer = time.NewTimer(relayHeadStart)
		headStart = headStartTimer.C
	}

	var failed []relayAttemptError
	for {
		select {
		case w := <-winCh:
			return s.runSession(ctx, w, cfg)
		case <-connecting:
			if !fannedOut {
				startHeadStart()
			}
		case headRelease = <-allocating:
			if !fannedOut {
				startHeadStart()
			}
		case <-headStart:
			headStart = nil
			if fannedOut {
				continue
			}
			// Silent, not refused: race the rest now, and let the next dial
			// waiting for an Allocate slot have this one's. The Allocate itself
			// runs on — see relayHeadStart. A TCP connect that is still hanging
			// holds no slot yet; it runs on as well, and is closed if it loses.
			turnLog("[STREAM %d] %s — racing %v (group %d)",
				s.id, headStartExpired(addrs[0], headRelease != nil, headConnected.Load()), addrs[1:], cfg.GroupID)
			if headRelease != nil {
				headRelease()
			}
			fanOut()
		case attempt := <-errCh:
			failed = append(failed, attempt)
			err := attempt.err
			if !fannedOut {
				// The assigned server failed: try the failover candidates. Say
				// why before moving on — a failover that succeeds swallows this
				// error otherwise (only "all servers failed" ever surfaces it),
				// and a stream's own server refusing Allocate on every reconnect was
				// invisible in the log except as a second Dial line one RTT later.
				turnLog("[STREAM %d] %s failed (%v) — fanning out to %v (group %d)",
					s.id, addrs[0], err, addrs[1:], cfg.GroupID)
				fanOut()
			} else if len(failed) == launchedCount {
				raced := newRaceError(failed)
				if spoke := raced.spokesman(); raced.overrulesLast() {
					turnLog("[STREAM %d] all %d servers failed; acting on what %s answered (%v), not on the last to fail, %s (%v) (group %d)",
						s.id, len(failed), spoke.addr, spoke.err, failed[len(failed)-1].addr, failed[len(failed)-1].err, cfg.GroupID)
				}
				return raced
			}
		case <-ctx.Done():
			cancelRace()
			// A racer may still win after we leave; reap it so the allocation
			// and sockets don't leak.
			go reapRace(&wg, winCh)
			return ctx.Err()
		}
	}
}

// relayAttemptError is one relay's failure within an attempt.
type relayAttemptError struct {
	addr string
	err  error
	at   time.Time // when the relay's answer, or the end of its silence, came in
}

// raceError is an attempt every relay of which failed.
//
// It used to be the last failure to arrive, wrapped — and what arrives last is
// usually what says least. A relay answering 486 does so in one round trip; a
// dark one next to it takes the Allocate deadline to time out, and its timeout
// then stood for the whole attempt: no credential rotation, no quota backoff,
// the worker back on the same full credential after a plain reconnect delay,
// for as long as the second relay stayed dark. So the attempt speaks through
// the first answer to come in that calls for new credentials
// (classifyCredError), if there is one, and through the last failure as before
// otherwise. Between two such answers the order still decides — a 401 ahead of
// a 486 is a 401 — but both rotate the credential, which is what matters. Only
// that error is in the chain and in the text — the others' text carries
// addresses and ports that must not reach the substring fallback of
// classifyCredError (see isTransportError) — but each relay's own answer is
// kept for whoever needs to know which one said what (quotaAnsweredBy).
type raceError struct {
	attempts []relayAttemptError // in the order they failed
	speaks   int
}

func newRaceError(attempts []relayAttemptError) *raceError {
	e := &raceError{attempts: attempts, speaks: len(attempts) - 1}
	for i, a := range attempts {
		if classifyCredError(a.err) {
			e.speaks = i
			break
		}
	}
	return e
}

func (e *raceError) spokesman() relayAttemptError { return e.attempts[e.speaks] }

// overrulesLast reports whether the answer that speaks changes what the attempt
// would have been read as: it is not the last failure, and the last failure
// does not call for new credentials itself. Two relays both answering 486 —
// every reconnect onto orphaned quota, ten workers at a time (Android device,
// 21.09) — read the same either way and are not worth a line each.
func (e *raceError) overrulesLast() bool {
	last := len(e.attempts) - 1
	return e.speaks != last && !classifyCredError(e.attempts[last].err)
}

func (e *raceError) Error() string {
	return fmt.Sprintf("TURN allocate: all %d servers failed: %v", len(e.attempts), e.spokesman().err)
}

func (e *raceError) Unwrap() error { return e.spokesman().err }

// quotaAnswer is one relay's 486 and when it came in; a zero time means the
// error did not say.
type quotaAnswer struct {
	addr string
	at   time.Time
}

// quotaAnsweredBy narrows addrs to the relays that answered err's attempt with
// 486. An error that does not say which relay said what leaves addrs as it is.
func quotaAnsweredBy(err error, addrs []string) []quotaAnswer {
	var out []quotaAnswer
	var raced *raceError
	if !errors.As(err, &raced) {
		for _, addr := range addrs {
			out = append(out, quotaAnswer{addr: addr})
		}
		return out
	}
	for _, a := range raced.attempts {
		if isQuotaError(a.err) && slices.Contains(addrs, a.addr) {
			out = append(out, quotaAnswer{addr: a.addr, at: a.at})
		}
	}
	return out
}

// quotaBesideSilence reports whether err is an attempt in which a 486 speaks
// while another relay's Allocate ended without a TURN answer — a transport
// failure or a timeout, whatever it had answered before that. It names the two.
//
// That attempt asks for new credentials, and new credentials mean a trip to VK,
// which may cost the user a captcha. The relay that did not answer might well
// have on the very same credential: its quota is its own (486 is per credential
// per relay), and the usual reason for the 486 next to it is our own orphans on
// the first relay right after a network drop — exactly when a dial to the second
// is most likely to be lost to the same flaky path. It gets one more try before
// this worker gives the credential up (quotaGraceApplies). A relay that stays
// dark costs that one attempt; it used to cost every attempt until the orphans
// expired, ten minutes.
func quotaBesideSilence(err error) (quota, silent string, ok bool) {
	var raced *raceError
	if !errors.As(err, &raced) || !isQuotaError(raced) {
		return "", "", false
	}
	for _, a := range raced.attempts {
		if _, answered := turnErrorCode(a.err); !answered {
			return raced.spokesman().addr, a.addr, true
		}
	}
	return "", "", false
}

// quotaGraceApplies decides the one more try: once per credential per worker
// (used is the credential that has had it), and not on a credential a sibling
// has already replaced — there the 486 takes its usual fast path to the new
// one, which is in the cache or being fetched already.
func quotaGraceApplies(err error, user, used string, replaced bool) (quota, silent string, ok bool) {
	if user == used || replaced {
		return "", "", false
	}
	return quotaBesideSilence(err)
}

// relayHeadStart is how long the attempt's first relay has over TCP — to take
// the connection, then to answer Allocate — before the rest are dialed
// alongside it; the first to allocate takes the session and the others are
// released.
//
// Over UDP the first relay's Allocate has a deadline of its own
// (allocateSilenceTimeout), and the others are dialed once it has failed.
// Over TCP that is not enough: a dark relay is silent a step earlier, on the
// connect, which is given relayTCPConnectTimeout — six seconds of an attempt
// sat out before the answering relay is even dialed. And the Allocate over a
// connected flow is not cut at two seconds (relayTCPAllocateTimeout): on the
// network TCP is here for, flows hang for seconds and then move. So the clock
// of Android's head start (2ba1b62c, 81d76f97): 1.2s leaves a healthy relay
// room for a retransmission or two and still costs a dark one a second
// instead of six — two round trips are 180-200ms on LTE, 290-410ms on a slow
// Wi-Fi.
//
// The clock starts with the connect and is restarted when the Allocate goes
// out, not while it queues for a slot: after a network return every worker
// dials at once, and a healthy relay must not lose the race to its own queue.
// When the head start runs out the hanging Allocate gives up its slot — the
// next dial in the queue can go — but is not aborted: cutting an Allocate short
// is how ghost allocations were made (a reply still on its way allocates on the
// relay with nobody left to release it). If the relay does answer late, the
// loser path releases that allocation properly.
const relayHeadStart = 1200 * time.Millisecond

// headStartExpired says what the first relay had not done when its head start
// ran out: answered its Allocate, taken the connection but left the dial
// queued for an Allocate slot — the clock that started with the connect goes
// on running through that wait, or there would be no limit on it but the
// context — or taken the connection at all. connected is read without a
// snapshot of the select it sits next to: it words a log line and decides
// nothing.
func headStartExpired(relay string, allocating, connected bool) string {
	switch {
	case allocating:
		return fmt.Sprintf("%s has not answered Allocate for %v", relay, relayHeadStart)
	case connected:
		return fmt.Sprintf("%s took the TCP connection, but this dial is still queued for an Allocate slot %v after the connect began", relay, relayHeadStart)
	default:
		return fmt.Sprintf("%s has not accepted the TCP connection for %v", relay, relayHeadStart)
	}
}

// dialOpts is what only runWithCreds needs from a dial; the zero value is a
// plain dial.
type dialOpts struct {
	// session is the attempt's own context. An Allocate over TCP runs on
	// under it once the race was won elsewhere, and is judged while it is
	// alive: what it reports is the relay's answer, or its silence. nil means
	// ctx.
	session context.Context
	// allocating is called once the dial holds its Allocate slot, just before
	// the request goes out, with the call that gives the slot back.
	allocating func(release func())
	// connecting is called just before a TCP connect to the relay starts.
	connecting func()
	// connected is called with true once that connect has succeeded.
	connected func(bool)
}

// relayTCPAllocateTimeout bounds an Allocate over TCP. Not allocateSilenceTimeout:
// over a connected flow a lost segment waits for a retransmission, and flows
// to the relays hang for seconds and then move (Android field log 19.09); the
// head start races the others meanwhile. What ends it is pion's own schedule
// (~7.8s), as on Android; dataPlaneHandshakeTimeout is only the backstop. A
// var for the host tests that wait it out.
var relayTCPAllocateTimeout = dataPlaneHandshakeTimeout

// dialAndAllocate dials one TURN server and performs the Allocate handshake,
// measuring the Dial→Allocate latency — the network part only, not the time
// spent queued on allocSemaphore, which said nothing about the server and once
// booked a 6s "rtt" against a relay that answered in 230ms. On any error it
// closes whatever it opened and returns. On success the caller owns
// client/raw/relay. Uses ctx for the dial, the allocSemaphore wait and the
// Allocate itself so a cancelled race aborts promptly.
//
// Each attempt gets its own permWatch, wired into the pion logger factory
// before NewClient so it sees the allocation's whole lifecycle. Losing failover
// candidates simply drop theirs — a permWatch owns no goroutine, so an unwatched
// one costs nothing.
func dialAndAllocate(ctx context.Context, s *stream, user, pass, addr string, cfg WorkerGroupConfig, opts dialOpts) (*turn.Client, net.Conn, net.PacketConn, time.Duration, *permWatch, error) {
	overTCP := relayOverTCP(cfg)
	session := opts.session
	if session == nil {
		session = ctx
	}
	// Ahead of everything that is timed or logged below: the wait is our own
	// queue, not the relay's silence, so neither the head start nor the rtt may
	// count it (see relay_connect_pacing.go).
	if overTCP && !awaitRelayConnectSlot(ctx, addr) {
		return nil, nil, nil, 0, nil, ctx.Err()
	}
	// The credential's tag says which generation this dial runs on — the one
	// fact the per-stream cache-hit line used to carry.
	if overTCP {
		turnLog("[STREAM %d] Dial TURN %s over TCP (group %d, creds %s)", s.id, addr, cfg.GroupID, credsTag(user))
	} else {
		turnLog("[STREAM %d] Dial TURN %s (group %d, creds %s)", s.id, addr, cfg.GroupID, credsTag(user))
	}
	dialStart := time.Now()
	perm := newPermWatch(s.id)
	// Where the count of relays heard stood when this candidate began to wait on
	// its relay (relay_silence.go): at the connect over TCP, at the Allocate
	// over UDP.
	var heard uint64

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
		Control: protectControl,
	}

	// In VPN mode the relay's address has to leave through the physical
	// gateway before the first packet does (bypass.go): a relay dialled into
	// the tunnel loops back through this very proxy.
	if err := ensureBypass(addr); err != nil {
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN bypass route: %w", err)
	}

	var turnConn net.PacketConn
	var raw net.Conn
	if !overTCP {
		c, err := dialer.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, nil, nil, 0, nil, fmt.Errorf("TURN UDP dial: %w", err)
		}
		raw = c
		turnConn = &connectedUDPConn{c.(*net.UDPConn)}
	} else {
		if opts.connecting != nil {
			opts.connecting()
		}
		heard = relayHeardMark()
		c, err := connectRelayTCP(ctx, dialer, addr)
		if err != nil {
			// Over TCP the connect is the relay's first chance to be silent or to
			// refuse, so it counts against the server on the same terms as a
			// failed Allocate below. A connect that our own race cancelled does
			// not: it says nothing about the host. Nor one the machine's own
			// network failed, one whose timeout ran out across a sleep, an
			// isolated flow's failure while another stream is receiving from
			// this same relay (relay_heard_by_others.go), or a silence no relay
			// broke (relay_silence.go).
			if session.Err() == nil && ctx.Err() == nil && !relayNotToBlame(err, dialStart) && !hostFrozeSince(dialStart) &&
				!tcpAttemptFailureIsIsolated(addr, s, err) && !silenceNotToBlame(err, heard, addr) {
				noteServerFailure(addr)
			}
			return nil, nil, nil, 0, nil, fmt.Errorf("TURN TCP dial: %w", err)
		}
		raw = c
		turnConn = turn.NewSTUNConn(c)
		if opts.connected != nil {
			opts.connected(true)
		}
	}
	// Everything the relay's socket delivers is the relay heard (relay_silence.go).
	responses := &allocateResponseConn{PacketConn: relayHeardConn{turnConn}, remote: raw.RemoteAddr().String()}

	// This socket is only used for TURN, never STUN Binding discovery. With
	// STUNServerAddr set, pion ends its receive loop on the first datagram from
	// that address that is neither STUN nor ChannelData (client.go HandleInbound:
	// errNonSTUNMessage → "Exiting loop"), and on a connected socket every
	// datagram comes from that address. From then on nothing is read: Allocate
	// replies are lost, and later refreshes and channel binds fail as if the relay
	// had gone dark. With only TURNServerAddr such packets are ignored.
	client, err := newTURNClient(&turn.ClientConfig{
		TURNServerAddr: addr,
		Username:       user,
		Password:       pass,
		Conn:           responses,
		// pion refreshes the peer permission every 120s by default. That is
		// twice as often as it needs to be: the permission's lifetime is a
		// fixed 300s (RFC 8656 section 9), so 240s renews it with a full 60s of
		// margin while halving the transactions this costs — they are per stream
		// and never coalesced with the 25s keepalive grid.
		//
		// Not disabled outright (free-turn-proxy sets 24h) because after the
		// first WriteTo the data path never re-sends CreatePermission —
		// createPermission short-circuits on permStatePermitted
		// (internal/client/udp_conn.go:169) — leaving ChannelBind refresh as
		// the only thing that reinstalls the permission. pion fires that at
		// 300-330s (bindingRefreshInterval 5m, checked every 30s, condition is
		// a strict >, and refreshedAt is stamped after the transaction), i.e.
		// *after* the 300s permission has already lapsed. That would open a
		// ~30s window every 5 minutes in which the relay may drop inbound —
		// too short for the 90s dead-stream detector to catch, so it would
		// surface as unexplained downstream loss rather than a failed stream.
		// bindingRefreshInterval is unexported in ClientConfig, so the window
		// cannot be closed from here.
		//
		// permWatch still sees this class of failure, just at 2x240s instead of
		// 2x120s (~8 min). The faster detectors are unaffected: ChannelBind
		// latches in ~60s and allocation refresh on a single failure.
		PermissionRefreshInterval: 240 * time.Second,
		LoggerFactory:             pionLogFactory{streamID: s.id, watch: perm},
	})
	if err != nil {
		raw.Close()
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN client: %w", err)
	}

	if err := client.Listen(); err != nil {
		client.Close()
		raw.Close()
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN listen: %w", err)
	}

	dialed := time.Since(dialStart)

	select {
	case allocSemaphore <- struct{}{}:
	case <-ctx.Done():
		client.Close()
		raw.Close()
		return nil, nil, nil, 0, nil, ctx.Err()
	}
	var releaseOnce sync.Once
	releaseSlot := func() { releaseOnce.Do(func() { <-allocSemaphore }) }
	if opts.allocating != nil {
		opts.allocating(releaseSlot)
	}
	if overTCP {
		// An Allocate over TCP may wait up to relayTCPAllocateTimeout, and the
		// slots are the whole process's (allocSemaphore; Android's are per
		// relay): past the head start it gives its slot up whatever the race
		// is doing — a first relay that connected after the others were raced
		// started no clock of the race's, and three of them held every slot
		// for eight seconds (Codex review of the Windows port, 2026-10-23).
		// The request itself runs on.
		slotTimer := time.AfterFunc(relayHeadStart, releaseSlot)
		defer slotTimer.Stop()
	}
	if !overTCP {
		// Over UDP nothing has gone to the relay before this request: a relay
		// heard from here on is heard while this Allocate runs
		// (silenceNotToBlame). Over TCP the window opened with the connect,
		// which, accepted, was the relay heard.
		heard = relayHeardMark()
	}
	// Over UDP the race's context ends the Allocate with the race: the others
	// are dialed only once it has failed, and a loser is one of those. Over TCP
	// it runs on under the attempt, to the relay's answer or its silence — see
	// relayHeadStart.
	allocCtx, allocTimeout := ctx, allocateSilenceTimeout
	if overTCP {
		allocCtx, allocTimeout = session, relayTCPAllocateTimeout
	}
	allocStart := time.Now()
	relay, err := allocateWithDeadline(allocCtx, allocTimeout, func() (net.PacketConn, error) {
		relay, err := client.Allocate()
		if err != nil {
			return nil, err
		}
		// Counted live until closed, so that losing it without a release marks
		// this relay as still holding our quota (orphaned_allocations.go). Inside
		// the closure, so that an allocation answered after the deadline — which
		// allocateWithDeadline closes on the spot — books its release too.
		return trackAllocation(relay, user, addr), nil
	}, func() {
		client.Close()
		raw.Close()
	})
	err = responses.allocationError(err)
	releaseSlot()
	if err != nil {
		client.Close()
		raw.Close()
		// Only a genuine refusal counts against the server. A losing failover
		// candidate over UDP — or any dial during a teardown — fails because we
		// cancelled its context, which says nothing about the host. Over TCP
		// losing the race does not excuse it: nothing cancels that Allocate, so
		// a relay that was still silent when another one won has earned the
		// strike (dialOpts.session).
		//
		// Nor does 486. The quota is per credential on this relay, and what fills
		// it is our own allocations — usually ghosts of sockets that died with
		// the path. The relay answered; the fix is the credential rotation that
		// 486 already triggers (refreshGroupCreds), not a five-minute stand-down.
		// On Android on 18.09 a run of 486s on the old credential stood down the
		// one relay that had just proved an SRTP session, and the fresh
		// credential had only the relay that never carried a byte left to go to.
		//
		// Nor an Allocate the machine's own network failed: a write the local
		// stack refused, or silence while the network was leaving
		// (relayNotToBlame). Nor a silence no relay broke while it lasted
		// (relay_silence.go). Nor an Allocate whose deadline ran out across a
		// sleep: Go's clocks run on through one on Windows, and the relay never
		// got those seconds (hostFrozeSince; iOS host_freeze.go, Codex review of
		// the Windows port, 2026-10-23). Over TCP a live sibling on the relay
		// also excuses a transport failure or silence; explicit TURN refusals
		// keep their handling (tcpAttemptFailureIsIsolated).
		if allocCtx.Err() == nil && !isQuotaError(err) && !isAllocateMismatch(err) && !relayNotToBlame(err, dialStart) &&
			!hostFrozeSince(dialStart) && (!overTCP || !tcpAttemptFailureIsIsolated(addr, s, err)) &&
			!silenceNotToBlame(err, heard, addr) {
			noteServerFailure(addr)
		}
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN allocate: %w", err)
	}
	if overTCP {
		// Outermost, so the deadline is on the socket before the release is
		// written; trackedRelay beneath it books a release that timed out.
		relay = boundRelayClose(relay, raw)
	}
	cfg.start.noteAllocated() // start_outcome.go

	return client, raw, relay, dialed + time.Since(allocStart), perm, nil
}

// allocateSilenceTimeout bounds one Allocate. pion retransmits on its own
// schedule (0.2/0.4/0.8/1.6/1.6/1.6/1.6s — 7.8s to "all retransmissions
// failed"), which is built for a lossy path where the next copy may get
// through. The failure seen in the field is not loss: on the same relay, in the
// same second, one socket's Allocate got no answer to any of its seven copies
// while its siblings' were answered in one round trip — a 5-tuple the server
// (or a balancer in front of it) had blackholed, and retransmitting on it buys
// nothing. Meanwhile that socket held one of the three allocSemaphore slots
// for the whole 7.8s, queueing the healthy dials behind it: with two blackholed
// first, streams 8 and 9 waited 5.5s for a slot, and a stream whose two
// servers both drew a dead tuple spent 16s before its first retry.
//
// A normal Allocate is two round trips (401 challenge, then the authenticated
// request), well under a second even on a slow path; 2s still leaves three of
// pion's retransmits for genuine loss. Same figure as relayProofTimeout, the
// data-plane verdict: the control plane is allowed no longer than the data
// plane to prove the path.
const allocateSilenceTimeout = 2 * time.Second

var errAllocateSilent = errors.New("no answer to Allocate")

// allocateWithDeadline runs allocate, giving up after timeout or when ctx is
// cancelled. abort must make a pending allocate return promptly — for pion
// that is Client.Close (fails the transaction being waited on) plus closing
// the conn (fails a retransmit or a follow-up transaction that was racing the
// close). A relay that allocate hands back after the deadline is closed here,
// so the server-side allocation is released rather than leaked.
func allocateWithDeadline(ctx context.Context, timeout time.Duration, allocate func() (net.PacketConn, error), abort func()) (net.PacketConn, error) {
	type result struct {
		relay net.PacketConn
		err   error
	}
	done := make(chan result, 1)
	go func() {
		relay, err := allocate()
		done <- result{relay, err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.relay, r.err
	case <-timer.C:
	case <-ctx.Done():
	}

	abort()
	if r := <-done; r.relay != nil {
		r.relay.Close()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w within %v", errAllocateSilent, timeout)
}

// runSession runs the relay session on the connected server and owns its
// lifecycle: it closes the relay, client and underlying conn on exit.
func (s *stream) runSession(ctx context.Context, w winner, cfg WorkerGroupConfig) error {
	defer w.raw.Close()
	defer w.client.Close()
	defer w.relay.Close()

	// Whatever reached the queues while the stream was reconnecting, before any
	// transport starts its writer — runNoDTLS starts it ahead of the relay proof.
	if n := s.drainOutbound(); n > 0 {
		turnLog("[STREAM %d] dropped %d packet(s) queued while the stream was reconnecting", s.id, n)
	}

	// Over TCP the socket is watched for as long as the session runs
	// (relay_tcp_watch.go). Deferred last, so it is let go before anything above
	// closes it.
	if tc := relayTCPConn(w.raw); tc != nil {
		relaySockets.register(s, w.addr, tc)
		defer func() { relaySockets.unregister(tc, time.Now()) }()
	}

	turnLog("[STREAM %d] TURN %s rtt=%v (group %d), relayed address %s", s.id, w.addr, w.rtt, cfg.GroupID, w.relay.LocalAddr())

	// Blackhole watchdog. When permWatch declares the allocation dead, close the
	// relay: that is the one handle all three transports block on, so whichever
	// loop owns this stream unwinds immediately instead of writing into a dead
	// allocation until the 90s no-RX detector eventually notices — or never
	// notices, because a shaped-but-alive path keeps the liveness clock fresh.
	// Closing here also sends Refresh(lifetime=0), releasing the server-side
	// allocation instead of leaving it to eat the credential's quota.
	//
	// The same goes for a TCP flow the system has given up (relayTCPUserTimeout).
	// Its one error may have gone to pion's read loop, which drops it, and the
	// session would then linger until its next write broke — or, on an idle
	// tunnel, until the dead-stream detector. Over UDP the channel is nil.
	//
	// And for pion's read loop ending on any other error than our own close
	// (permWatch.readerStopped) — over TCP, a reset or a close from the far
	// side. Nothing can arrive on this session any more, whatever its writes
	// report.
	//
	// Over TCP a write that has waited in the socket for relayTCPUserTimeout is
	// given up here as well (relayFlowConn.stuckFor): the system's limit does
	// not cover a relay that stopped reading.
	sessCtx, sessCancel := context.WithCancel(ctx)
	defer sessCancel()
	flow := relayFlow(w.raw)
	var stuckCheck <-chan time.Time
	if flow != nil {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		stuckCheck = tick.C
	}
	go func() {
		for {
			select {
			case <-w.perm.deadCh():
				turnLog("[STREAM %d] Recycling allocation after blackhole", s.id)
				w.relay.Close()
			case <-relayFlowGaveUp(w.raw):
				turnLog("[STREAM %d] TCP flow to %s given up by the system: no progress for %v — reconnecting",
					s.id, w.addr, relayTCPUserTimeout)
				w.relay.Close()
			case now := <-stuckCheck:
				stuck := flow.stuckFor(now)
				if stuck < relayTCPUserTimeout {
					continue
				}
				turnLog("[STREAM %d] TCP flow to %s has taken nothing for %v — given up, reconnecting",
					s.id, w.addr, stuck.Round(time.Second))
				flow.giveUp()
				w.relay.Close()
			case <-w.perm.readerGoneCh():
				turnLog("[STREAM %d] nothing reads from %s any more (%v) — reconnecting",
					s.id, w.addr, w.perm.readerStoppedBy())
				w.relay.Close()
			case <-sessCtx.Done():
			}
			return
		}
	}()

	// The transports report their own handshake success against this address
	// (noteServerHandshakeOK), which is what lets a sibling's success vouch for
	// the uplink when another server fails its handshake in the same window.
	s.serverAddr = w.addr
	s.allocateRTT = w.rtt
	// Whether this session's flow has a fate of its own (relay_transport.go).
	s.overTCP.Store(relayFlow(w.raw) != nil)
	// Booked on the relay for as long as it runs: the judge of relay loss
	// counts the sessions per relay and moves them off one it rests.
	defer trackLiveSession(w.addr, s)()

	// The allocation check for this session (alloc_check.go): the peer the
	// permission is asked for is the one every transport sends to.
	s.allocCheck.Store(newAllocCheck(s.id, w.client, cfg.PeerAddr, w.perm))
	defer s.allocCheck.Store(nil)

	// For the log line below: which side of the relay a failed data-plane
	// handshake died on (see relayWriteProbe). And for the relay proof of the
	// noDTLS transport, whose window grows with the time the permission took
	// (udpRelayProofLimit).
	relay := newRelayWriteProbe(w.relay)

	started := time.Now()
	var err error
	switch cfg.PeerType {
	case "wireguard":
		err = s.runNoDTLS(ctx, relay, cfg.PeerAddr)
	case "srtp":
		err = s.runSRTP(ctx, relay, cfg.PeerAddr)
	default:
		err = s.runDTLS(ctx, relay, cfg.PeerAddr, true)
	}

	// Health accounting for the static assignment (see turn_server_health.go).
	//
	// A TCP flow that timed out is not held against the relay. On the network
	// that needs TCP, flows die one at a time while their neighbours to the very
	// same address carry on (Android field log 19.09: both relays hit alike, a
	// flow hung next to one answering in 200ms), so the death says nothing about
	// the host — and three of them, young, would stand a working relay down for
	// five minutes. A relay that really is gone earns its strikes on the redial,
	// where the connect or the Allocate fails.
	//
	// The same goes for a flow that ended under pion's reader — reset or closed
	// from the far side. In the field those came singly too (19.09: thirteen,
	// spread over both relays, usually half a minute after the flow had gone
	// deaf, with the neighbours carrying on).
	flowTimedOut := relayFlowTimedOut(w.raw)
	readerErr := w.perm.readerStoppedBy()
	flowEnded := flowTimedOut || (readerErr != nil && relayFlow(w.raw) != nil)
	// How long the relay had been silent when the session ended: what an
	// out-of-reach end is graded by (sessionOutcome, sessionSilence).
	ended := time.Now()
	silent := sessionSilence(s.activity.Load(), started, ended)
	hole := sessionBlackhole(w.perm) // once, for the grade and the seat
	verdict := sessionOutcome(ctx.Err() != nil, hole, ended.Sub(started), silent, err)
	if flowEnded && verdict == verdictFailure {
		verdict = verdictNone
	}
	// Whatever ended with the machine's own network is not the relay's: every
	// session on it dies at that moment, on every relay alike, and a handshake
	// that was under way times out for the same reason (local_network_failure.go).
	if (verdict == verdictFailure || verdict == verdictHandshakeFailure) && relayNotToBlame(err, started) {
		turnLog("[STREAM %d] %s is not held to account for this session: the machine's own network failed under it", s.id, w.addr)
		verdict = verdictNone
	}
	// Nor whatever timed out across a sleep: Go's clocks run on through one on
	// Windows — the handshake's 8s with them — and the relay never got those
	// seconds (hostFrozeSince; iOS host_freeze.go, Codex review of the Windows
	// port, 2026-10-23).
	if (verdict == verdictFailure || verdict == verdictHandshakeFailure) && hostFrozeSince(started) {
		turnLog("[STREAM %d] %s is not held to account for this session: the machine slept during it", s.id, w.addr)
		verdict = verdictNone
	}
	// A handshake failed while another stream on this relay hears it is the
	// flow's failure (relay_heard_by_others.go). Weighed after the excuses
	// above: a handshake cut short by the machine's own network or by a sleep
	// is no failure of the flow either, and counted here it sent a working
	// relay to the end of this stream's list after two such sessions (Codex
	// review of the iOS port, 22.10).
	if verdict == verdictHandshakeFailure && relayHeardByOthers(w.addr, s, time.Now()) {
		avoid := ""
		if n := s.noteFlowFailure(w.addr); n == flowFailsBeforeAvoid {
			avoid = fmt.Sprintf("; %d in a row on it for this stream, which dials it last until a session of its own gets through", n)
		}
		turnLog("[STREAM %d] %s handshake: %s — a flow's failure, not the relay's: other streams are hearing it%s",
			s.id, w.addr, relay.describe(time.Now()), avoid)
		verdict = verdictNone
	}
	switch verdict {
	case verdictSuccess:
		noteServerSuccess(w.addr)
	case verdictHandshakeFailure:
		turnLog("[STREAM %d] %s handshake: %s", s.id, w.addr, relay.describe(time.Now()))
		noteServerHandshakeFailure(w.addr, started)
	case verdictFailure:
		noteServerFailure(w.addr)
	}
	// A session the relay no longer knew may have left its allocation seated
	// there (orphaned_allocations.go), read off the same reading of the
	// watchdog as the grade above. Before the deferred closes: the mark is set
	// first, and a release that then fails only extends it.
	if outOfReachSeated(hole, relayFlow(w.raw) != nil, err) {
		noteOutOfReach(w.user, w.addr, trackedAllocation(w.relay), time.Now())
	}
	// A session that went deaf while a stream on another relay kept hearing its
	// own counts toward resting this relay (relay_deaf.go). Not one the
	// blackhole watchdog ended: a silent relay is graded above as the failure it
	// is, and a relay that no longer knew the socket did not go deaf on it.
	if hole == noBlackhole {
		noteDeafSession(s, w.addr, cfg.PeerAddr.String(), ctx.Err() != nil, err, started, time.Now())
	}

	// A blackhole teardown surfaces as "use of closed network connection", which
	// carries no diagnosis and — more importantly — no auth/quota wording for
	// classifyCredError to act on. Restate it with pion's own message so a
	// blackhole that was really a stale credential still rotates the credential.
	// A nil err means the loops exited cleanly, which WorkerGroup would read as
	// "server closed the stream": override it too, this was a failure.
	//
	// The cause is folded in with %s, not %w. classifyCredError is code-driven and
	// bails out early on any error whose chain contains a *net.OpError (see
	// isTransportError), and the relay we just closed ourselves puts exactly that
	// in the chain. Wrapping would therefore route every blackhole down the
	// "transport, not credential" branch and never rotate — which is the whole
	// reason this restatement exists. Flattening to text keeps pion's wording
	// ("error 401: Unauthorized") reachable by the substring fallback; nothing
	// downstream matches on this error's chain.
	if w.perm.fired() {
		if err == nil {
			return fmt.Errorf("TURN blackhole: %s", w.perm.why())
		}
		return fmt.Errorf("TURN blackhole: %s (%s)", w.perm.why(), err)
	}
	// Likewise for a flow the system gave up: what the transport returns is the
	// closed relay, or nil if its loops simply wound down — and nil would be read
	// as "the server closed the stream". No credential wording can hide in this
	// one, so the cause is kept in the chain.
	if flowTimedOut {
		if err == nil {
			return fmt.Errorf("%w: no progress for %v", errRelayFlowTimedOut, relayTCPUserTimeout)
		}
		return fmt.Errorf("%w: no progress for %v: %w", errRelayFlowTimedOut, relayTCPUserTimeout, err)
	}
	// And for a reader that stopped: the transport's own error is again only the
	// relay we closed, or nil. The reader's error is a transport error and stays
	// in the chain as one — its text carries addresses and ports, which must not
	// reach the substring fallback of classifyCredError (see isTransportError).
	if readerErr != nil {
		return fmt.Errorf("the relay connection is no longer read: %w", readerErr)
	}
	return err
}

// reapRace drains any late-arriving winner (after the caller has given up on
// ctx cancellation) and closes its resources so they don't leak. winCh holds at
// most one winner (guarded by sync.Once), so a single non-blocking drain after
// all dialers have exited is sufficient.
func reapRace(wg *sync.WaitGroup, winCh chan winner) {
	wg.Wait()
	select {
	case w := <-winCh:
		w.relay.Close()
		w.client.Close()
		w.raw.Close()
	default:
	}
}
