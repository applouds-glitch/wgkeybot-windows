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
func sessionOutcome(cancelled, blackholed bool, dur time.Duration, err error) sessionVerdict {
	var dead *deadStreamError
	deaf := errors.As(err, &dead)
	if deaf {
		dur -= dead.silent
	}
	switch {
	case cancelled:
		return verdictNone
	case blackholed:
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
}

// runWithCreds establishes one TURN session with pre-fetched credentials on the
// stream's assigned server, addrs[0] (see assignServers). There is no latency
// race: only if that server fails to Allocate are the remaining candidates
// dialed, all at once, and the first of those to complete Allocate takes the
// session while the others are cancelled/closed. The assignment is per attempt,
// so the next reconnect goes back to the stream's own server. Retry and
// credential rotation are managed by the calling WorkerGroup.
func (s *stream) runWithCreds(ctx context.Context, user, pass string, addrs []string, cfg WorkerGroupConfig) error {
	s.ready.Store(false)
	defer s.ready.Store(false)

	// raceCtx is cancelled the moment a winner is chosen (or ctx dies) so the
	// losing failover candidates stop dialing / abort their semaphore wait
	// promptly.
	raceCtx, cancelRace := context.WithCancel(ctx)
	defer cancelRace()

	var once sync.Once
	winCh := make(chan winner, 1)
	errCh := make(chan relayAttemptError, len(addrs))
	var wg sync.WaitGroup

	launch := func(addr string) {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			client, raw, relay, rtt, perm, err := dialAndAllocate(raceCtx, s, user, pass, addr, cfg)
			if err != nil {
				errCh <- relayAttemptError{addr: addr, err: err, at: time.Now()}
				return
			}
			claimed := false
			once.Do(func() {
				claimed = true
				cancelRace()
				winCh <- winner{client: client, raw: raw, relay: relay, addr: addr, rtt: rtt, perm: perm}
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

	var failed []relayAttemptError
	for {
		select {
		case w := <-winCh:
			return s.runSession(ctx, w, cfg)
		case attempt := <-errCh:
			failed = append(failed, attempt)
			err := attempt.err
			if !fannedOut {
				// The assigned server failed: try the failover candidates. Say
				// why before moving on — a failover that succeeds swallows this
				// error otherwise (only "all servers failed" ever surfaces it),
				// and an elected server refusing Allocate on every reconnect was
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
func dialAndAllocate(ctx context.Context, s *stream, user, pass, addr string, cfg WorkerGroupConfig) (*turn.Client, net.Conn, net.PacketConn, time.Duration, *permWatch, error) {
	// The credential's tag says which generation this dial runs on — the one
	// fact the per-stream cache-hit line used to carry.
	turnLog("[STREAM %d] Dial TURN %s (group %d, creds %s)", s.id, addr, cfg.GroupID, credsTag(user))
	dialStart := time.Now()
	perm := newPermWatch(s.id)

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
	if cfg.UseUDP {
		c, err := dialer.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, nil, nil, 0, nil, fmt.Errorf("TURN UDP dial: %w", err)
		}
		raw = c
		turnConn = &connectedUDPConn{c.(*net.UDPConn)}
	} else {
		c, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, nil, nil, 0, nil, fmt.Errorf("TURN TCP dial: %w", err)
		}
		raw = c
		turnConn = turn.NewSTUNConn(c)
	}
	responses := &allocateResponseConn{PacketConn: turnConn, remote: raw.RemoteAddr().String()}

	// This socket is only used for TURN, never STUN Binding discovery. With
	// STUNServerAddr set, pion ends its receive loop on the first datagram from
	// that address that is neither STUN nor ChannelData (client.go HandleInbound:
	// errNonSTUNMessage → "Exiting loop"), and on a connected socket every
	// datagram comes from that address. From then on nothing is read: Allocate
	// replies are lost, and later refreshes and channel binds fail as if the relay
	// had gone dark. With only TURNServerAddr such packets are ignored.
	client, err := turn.NewClient(&turn.ClientConfig{
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
	allocStart := time.Now()
	relay, err := allocateWithDeadline(ctx, allocateSilenceTimeout, func() (net.PacketConn, error) {
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
	<-allocSemaphore
	if err != nil {
		client.Close()
		raw.Close()
		// Only a genuine refusal counts against the server. A losing failover
		// candidate — or any dial during a teardown — fails because we cancelled
		// its context, which says nothing about the host.
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
		// (relayNotToBlame).
		if ctx.Err() == nil && !isQuotaError(err) && !relayNotToBlame(err, dialStart) {
			noteServerFailure(addr)
		}
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN allocate: %w", err)
	}

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

	turnLog("[STREAM %d] TURN %s rtt=%v (group %d), relayed address %s", s.id, w.addr, w.rtt, cfg.GroupID, w.relay.LocalAddr())

	// Blackhole watchdog. When permWatch declares the allocation dead, close the
	// relay: that is the one handle all three transports block on, so whichever
	// loop owns this stream unwinds immediately instead of writing into a dead
	// allocation until the 90s no-RX detector eventually notices — or never
	// notices, because a shaped-but-alive path keeps the liveness clock fresh.
	// Closing here also sends Refresh(lifetime=0), releasing the server-side
	// allocation instead of leaving it to eat the credential's quota.
	//
	// And for pion's read loop ending on any other error than our own close
	// (permWatch.readerStopped). Nothing can arrive on this session any more,
	// whatever its writes report.
	sessCtx, sessCancel := context.WithCancel(ctx)
	defer sessCancel()
	go func() {
		select {
		case <-w.perm.deadCh():
			turnLog("[STREAM %d] Recycling allocation after blackhole", s.id)
			w.relay.Close()
		case <-w.perm.readerGoneCh():
			turnLog("[STREAM %d] nothing reads from %s any more (%v) — reconnecting",
				s.id, w.addr, w.perm.readerStoppedBy())
			w.relay.Close()
		case <-sessCtx.Done():
		}
	}()

	// The transports report their own handshake success against this address
	// (noteServerHandshakeOK), which is what lets a sibling's success vouch for
	// the uplink when another server fails its handshake in the same window.
	s.serverAddr = w.addr

	// Stamped before the transport runs, so a server that goes on to prove its
	// data plane already has a latency the election can rank it by.
	noteServerRTT(w.addr, w.rtt)

	started := time.Now()
	var err error
	switch cfg.PeerType {
	case "wireguard":
		err = s.runNoDTLS(ctx, w.relay, cfg.PeerAddr)
	case "srtp":
		err = s.runSRTP(ctx, w.relay, cfg.PeerAddr)
	default:
		err = s.runDTLS(ctx, w.relay, cfg.PeerAddr, true)
	}

	// Health accounting for the static assignment (see turn_server_health.go).
	// Whatever ended with the machine's own network is not the relay's: every
	// session on it dies at that moment, on every relay alike, and a handshake
	// that was under way times out for the same reason (local_network_failure.go).
	verdict := sessionOutcome(ctx.Err() != nil, w.perm.fired(), time.Since(started), err)
	if (verdict == verdictFailure || verdict == verdictHandshakeFailure) && relayNotToBlame(err, started) {
		turnLog("[STREAM %d] %s is not held to account for this session: the machine's own network failed under it", s.id, w.addr)
		verdict = verdictNone
	}
	switch verdict {
	case verdictSuccess:
		noteServerSuccess(w.addr)
	case verdictHandshakeFailure:
		noteServerHandshakeFailure(w.addr, started)
	case verdictFailure:
		noteServerFailure(w.addr)
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
	// And for a reader that stopped: the transport's own error is only the relay
	// we closed, or nil — and nil would be read as "the server closed the
	// stream". The reader's error is a transport error and stays in the chain as
	// one — its text carries addresses and ports, which must not reach the
	// substring fallback of classifyCredError (see isTransportError).
	if readerErr := w.perm.readerStoppedBy(); readerErr != nil {
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
