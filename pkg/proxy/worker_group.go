/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pion/stun/v3"
)

const (
	defaultCycleSecs = 36000 // cap for the credential cache TTL (see credentials.go)
	workerStagger    = 500 * time.Millisecond
)

// vkSemaphore limits concurrent VK API credential fetches across all groups.
// A limit of 2 lets pairs of groups fetch in parallel while avoiding
// hammering VK with unbounded concurrent authentication requests. Taken by
// getCredsCached on a miss only, never around a lookup (see there).
var vkSemaphore = make(chan struct{}, 2)

// allocSemaphore bounds concurrent TURN Allocate() handshakes. Without it,
// streams spaced by stagger still pile up because Allocate retransmits for
// ~7.8s (RTO=200ms, 7 attempts) — the first alloc hasn't failed before the 6th
// stream starts, so the server's per-IP path sees a burst and silently drops a
// share of them. Cap 3 keeps the first stream unblocked while smoothing the
// fan-out behind it.
var allocSemaphore = make(chan struct{}, 3)

// WorkerGroupConfig — parameters for one stream group (one VK link).
type WorkerGroupConfig struct {
	GroupID  int
	Link     string
	PeerAddr *net.UDPAddr
	UseUDP   bool
	PeerType string
	TurnIP   string
	TurnPort int
	// ExtraRelays join the relays VK hands out for the link (relay_extra.go).
	ExtraRelays []string
	// start is the evidence of the proxy start the workers belong to
	// (start_outcome.go): what their dials say is booked there and on no other
	// start's. nil outside a proxy start.
	start *startEvidence
}

// WorkerGroup runs the streams for one VK link using an error-driven, per-worker
// model — no group-level rotation timer, no batch kill/restart.
//
// Credentials are fetched lazily through the shared cache (fetchCreds →
// getCredsCached, single-flight per slot) and kept warm by the cache's own TTL.
// pion/turn refreshes each live TURN allocation internally (Refresh at
// lifetime/2, see internal/client/allocation.go), so a healthy stream never
// needs new credentials — our STUN keepalive is only a NAT keepalive. A worker
// re-fetches (throttled, via refreshGroupCreds) ONLY when its own session fails
// with an auth/quota error, then reconnects itself; healthy sibling streams are
// never torn down.
//
// WorkerGroup blocks until every worker has exited (ctx cancellation) so the
// caller's done-channel / graceful TURN release (deferred relayConn.Close →
// Refresh(lifetime=0) in runWithCreds) semantics are preserved.
func WorkerGroup(ctx context.Context, cfg WorkerGroupConfig, streams []*stream) {
	var wg sync.WaitGroup

	// cumStagger accumulates each stream's start delay so consecutive streams are
	// spaced at least workerStagger (500ms) apart — the jitter is added on top,
	// never subtracted, so the gap never dips below the floor. Stream 0 starts
	// immediately (cumStagger == 0) to keep tunnel-up fast.
	var cumStagger time.Duration
	for _, s := range streams {
		stagger := cumStagger
		cumStagger += workerStagger + time.Duration(rand.Intn(200))*time.Millisecond

		wg.Add(1)
		go func(s *stream, stagger time.Duration) {
			defer wg.Done()
			runWorker(ctx, cfg, s, stagger)
		}(s, stagger)
	}
	wg.Wait()
}

// runWorker drives a single persistent stream: fetch creds → connect → on exit,
// re-fetch creds (only for auth/quota errors) and reconnect. It returns when ctx
// is cancelled, or when a credential failure is one that retrying cannot fix —
// a dead call, or a captcha that lost the solve ladder maxCaptchaFailStreak
// times in a row. Giving up is reported through reportWorkerGaveUp, which
// escalates to a user-visible terminal failure once no worker is left.
//
// The TURN server is assigned statically, round-robin by stream ID (see
// assignRelays), so the streams are spread evenly across every server VK
// returned. The other servers are failover only: runWithCreds dials them just
// for this attempt, and only after the assigned one errors. failStreak only
// counts consecutive connect failures to drive the retry backoff. A session
// that stayed up for a while (or was closed cleanly by the server) resets the
// streak for a fast retry.
func runWorker(ctx context.Context, cfg WorkerGroupConfig, s *stream, stagger time.Duration) {
	if stagger > 0 {
		select {
		case <-time.After(stagger):
		case <-ctx.Done():
			return
		}
	}

	defer leaveTheDark(s) // dark_scout.go
	var st workerBackoff
	credFailStreak := 0 // consecutive credential fetches that failed for any reason
	// The credential that has had its one more try after a 486 beside a relay
	// that never answered (see quotaBesideSilence).
	quotaGraceUsed := ""
	for {
		permit, ok := waitForNetworkPermit(ctx, true)
		if !ok {
			return
		}
		if permit.unvalidatedProbe {
			turnLog("[WORKER %d] Controlled probe on unvalidated network", s.id)
		}

		// Fetch credentials via the shared cache. A cache hit is cheap (no VK
		// call); on a miss the per-slot lock single-flights the fetch so the
		// group's workers don't stampede VK, and the fetch takes vkSemaphore
		// itself (getCredsCached).
		user, pass, addrs, err := fetchCreds(ctx, cfg.Link, cfg.GroupID)
		if err != nil {
			releaseNetworkPermit(permit)
			if ctx.Err() != nil {
				return
			}
			if !permit.unvalidatedProbe && !isNetworkAvailable() {
				// Offline: not evidence about the credential, and the gate above
				// already parks the retry. Don't let it age the streaks.
				continue
			}

			// A dead call or one that needs a logged-in account cannot be fixed by
			// any number of retries — the startup path already treats both as
			// terminal. Mid-session they used to fall into the same endless 30s
			// loop as a lost packet.
			if isTerminalCredError(err) {
				reportWorkerGaveUp(s.id, err.Error())
				return
			}

			credFailStreak++
			var wait time.Duration
			switch {
			case errors.Is(err, errCaptchaUnsolved), errors.Is(err, errCaptchaLockout):
				// Either this worker just lost the solve ladder, or another one did
				// and the global lockout is still armed. Both mean the same thing:
				// the captcha gate is not opening. Give up once the session has spent
				// its budget of ladders — including the windows they put in front of
				// the user — rather than reopening it for as long as the tunnel is up.
				if captchaFailureStreak() >= maxCaptchaFailStreak {
					reportWorkerGaveUp(s.id, "captcha unsolved")
					return
				}
				// The lockout window (exponential, see bumpCaptchaLockout) is the real
				// pacing here: nothing can succeed before it expires, so sleep it out
				// instead of retrying on a cadence it would only reject again.
				wait = captchaLockoutRemaining() + time.Duration(rand.Intn(5000))*time.Millisecond
				if wait < 5*time.Second {
					wait = 5 * time.Second
				}
			default:
				// Everything else (VK rate limit, HTTP failure, a transient 5xx) is
				// assumed recoverable, so the worker keeps retrying — but on a
				// backoff, not a fixed 30s forever.
				wait = credRetryDelay(credFailStreak)
			}

			turnLog("[WORKER %d] Credential error (streak %d, captcha %d/%d): %v — retry in %v",
				s.id, credFailStreak, captchaFailureStreak(), maxCaptchaFailStreak, err, wait.Round(time.Second))
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return
			}
			continue
		}
		credFailStreak = 0

		// Effective availability can disappear while credentials are being fetched,
		// and a probe permit can be voided meanwhile (networkPermitCurrent): look
		// again before Allocate. Healthy sessions never pass through this gate.
		if !networkPermitCurrent(permit) {
			releaseNetworkPermit(permit)
			continue
		}

		// Apply optional manual TurnIP/TurnPort override to the fetched list,
		// and the relays the config adds to it.
		addrs = withExtraRelays(applyTurnOverride(addrs, cfg), cfg)

		// The path the attempt begins on: a reset after this point — another
		// network, a proxy start, a wake from sleep — makes whatever it finds
		// about a path that is gone (dark_scout.go).
		pathAtStart := darkEpoch()
		// A scout turn is checked again here, after the credential fetch that
		// may have outlasted its lease: one that has passed to another worker
		// since does not dial alongside it, and waits again.
		scouted := st.scouting
		st.scouting = false
		if scouted && !darkScoutDials(s, time.Now()) {
			releaseNetworkPermit(permit)
			if s.parkInTheDark(ctx, &st) {
				return
			}
			continue
		}

		// Where this stream runs: its own relay, round-robin by stream ID over
		// the relays with no verdict against them, with the relays still
		// holding our orphaned allocations for this credential moved last
		// (orphaned_allocations.go). The rest of the list follows only as
		// failover for this attempt. Keep the full list for the later retry
		// decision, including relays that recover meanwhile.
		// Just moved off a rested relay: the head the move picked first, the
		// relays losing in that window last (relay_move.go).
		now := time.Now()
		ordered := s.attemptOrder(user, addrs, now, s.takeMove(now))
		attemptHead := ordered[0]

		// The attempt runs under a context of its own, so that the judge of
		// relay loss can move it off a relay it rests (relay_rest.go).
		attempt := beginRelayAttempt(ctx)
		s.attempt.Store(attempt)
		s.relays.Store(&addrs)
		s.user.Store(&user)
		start := time.Now()
		// The proof that wakes this worker if the attempt fails into a dark
		// path: the next one from now (path_revival.go).
		proven := nextPathProof()
		ownProofs := s.pathProofs.Load()
		heardAtStart := relayHeardMark() // dark_scout.go
		runErr := s.runWithCreds(attempt.ctx, user, pass, ordered, cfg)
		sessionDur := time.Since(start)
		if s.pathProofs.Load() != ownProofs {
			// The session got through: only a proof made after it came down
			// says the path is back since.
			proven = nextPathProof()
		}
		s.attempt.Store(nil)
		s.relays.Store(nil)
		s.user.Store(nil)
		moved := attempt.end()
		releaseNetworkPermit(permit)
		if scouted {
			darkScoutDone(s, start, time.Now(),
				ctx.Err() == nil && !moved && s.pathProofs.Load() == ownProofs &&
					parksInTheDark(runErr) && !localNetworkError(runErr))
		}

		if ctx.Err() != nil {
			return
		}
		if moved {
			// Moved off a relay that is being rested: not a failure of
			// anything, so reconnect at once — onto another relay.
			st.reset()
			continue
		}
		if !isNetworkAvailable() && !(permit.unvalidatedProbe && classifyCredError(runErr)) {
			// Skip per-worker retry delays while offline. The gate above resumes on
			// the host's signal, fresh TURN proof, or one rate-limited probe permit.
			// Not the probe's credential refusal: a relay answered it, and unless
			// the slot is given up below, every probe after it — one a minute —
			// meets the same credential (Codex review 24.10: an on-link network
			// after the gateway left, its proof cleared with the gateway).
			continue
		}

		if runErr == nil {
			// runWithCreds returned nil while the tunnel is still up: the TURN
			// server closed this stream. Reconnect just this worker (back to its
			// assigned server) after a brief delay, with the backoff reset (avoids
			// a hot loop if the server keeps closing immediately).
			turnLog("[WORKER %d] Stream closed by server → reconnecting", s.id)
			st.reset()
			select {
			case <-time.After(time.Duration(500+rand.Intn(500)) * time.Millisecond):
			case <-ctx.Done():
				return
			}
			continue
		}

		// A 486 right after our own release on one of these relays is VK not
		// having processed that release yet, not a full credential: try the same
		// one again shortly, without rotating it or cooling down, and without
		// counting a failure (see releaseSettleWindow).
		if relay, age, ok := settlingQuotaError(runErr, user, ordered, time.Now()); ok {
			wait := releaseSettleRetry()
			turnLog("[WORKER %d] 486 with our release on %s only %v old — VK has not freed it yet, same creds again in %v",
				s.id, relay, age.Round(100*time.Millisecond), wait.Round(100*time.Millisecond))
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return
			}
			continue
		}

		// Auth/quota error → throttled, single-flight credential re-fetch so the
		// next iteration picks up a fresh credential. Healthy siblings untouched.
		// Every other error is transient from this worker's point of view: it
		// reconnects (with backoff) rather than giving up, so a stream always
		// recovers on its own — WireGuard and the sibling streams keep running
		// while just this stream is recreated.
		//
		// One exception, once per credential: a 486 from one relay while another's
		// Allocate ended without a TURN answer is tried again as it is before VK
		// is asked for anything (quotaGraceApplies).
		graced := false
		if quota, silent, ok := quotaGraceApplies(runErr, user, quotaGraceUsed, credsReplaced(cfg.GroupID, user)); ok {
			quotaGraceUsed = user
			graced = true
			turnLog("[WORKER %d] 486 from %s while %s gave no answer — one more try on the same creds before they are given up",
				s.id, quota, silent)
		}
		// Unless it is a 486 the breaker holds minting against: a relay refusing
		// fresh credentials is not cured by another one (quota_breaker.go).
		if !graced && classifyCredError(runErr) && !quotaRefusalPausesMinting(runErr, cfg.GroupID, user, time.Now()) {
			refreshGroupCreds(cfg.GroupID, user)
		}

		// A session that stayed up for a while was healthy; treat its drop as a
		// fresh failure (reset the backoff) rather than as part of a failure
		// streak.
		if sessionDur >= healthySessionDuration {
			st.reset()
		} else {
			st.failed(attemptHead)
		}

		// A failure on a server the next attempt will not even dial is not a
		// repeat of the same failure: a demotion or a stand-down has just
		// moved this stream to a different host, and that host deserves a first
		// attempt, not the backoff the dead one earned. Without this a stream
		// that failed twice on a dead relay waited 7-17s before trying the
		// working one — most of the connect budget, spent sleeping next to a
		// server that was already known to work.
		//
		// And only to a relay this streak has not started on (failedHeads): it
		// has had its first attempt, and the streak is its as much as the
		// other's. Two relays failing their handshakes: the first failure
		// demotes the head and the next attempt starts on the other, fresh; its
		// failure demotes that one too, and with every relay demoted
		// outageOrder hands the first one back — a "new" head that has already
		// failed in this streak, and the streak started over a second time.
		// Whatever else flips the head between relays the streak has tried (an
		// orphan mark, a penalty running out) did the same on every flip. The
		// set lives as long as the streak: reset forgets it, this reset keeps
		// it.
		//
		// The next attempt's head by the rule the next attempt dials by, the
		// relay this stream avoids included (relay_heard_by_others.go). A
		// move's head is not reapplied: it is for the one attempt after the
		// move, and that was this one.
		st.headMoved(attemptHead, s.attemptOrder(user, addrs, time.Now(), nil)[0])

		retryDelay := reconnectDelay(st.failStreak)
		note := ""
		// 486 (TURN allocation quota) after a mass teardown — say a host freeze
		// past the relay idle timeout, or a second network drop within ten
		// minutes, where the server-side allocations survive as ghosts still
		// holding the credential's quota — needs a new credential.
		//
		// If this credential has already been replaced — this worker's
		// refreshGroupCreds above force-expired the slot, or a sibling's did, or
		// the new one is already in — the 486 says nothing about the next
		// attempt, which runs on another identity. Retry at once: the first
		// worker back fetches the new credential (the slot lock single-flights
		// it), the rest take it from the cache. The rotation is lazy — nothing
		// fetches until a worker comes back for it — so the long cooldown here
		// only postponed the fetch: on an Android device on 2026-09-18 the new
		// credential was requested 5.2s after the rotation, the last stream came
		// back 15s after the network did.
		//
		// A 486 on the credential that is still current (the rotation was
		// throttled: it is the one fetched moments ago) gets the long jittered
		// cooldown, so a quota that stays full is not hammered in lockstep.
		if graced {
			// At once, whatever the streak: this is the try the credential is owed.
			retryDelay = reconnectDelay(0)
			note = " (one more try on these creds)"
		} else if isQuotaError(runErr) {
			if credsReplaced(cfg.GroupID, user) {
				st.reset()
				retryDelay = reconnectDelay(st.failStreak)
				note = " (on replaced creds)"
			} else {
				retryDelay = quotaCooldown()
			}
		}
		// Into a path that is dark still, no redial at all until it is back (but
		// the scout's, dark_scout.go); and out of one, a delay the dark earned
		// does not outlast it (below).
		if parksInTheDark(runErr) {
			if dark, why := findsTheDark(relayOverTCP(cfg), heardAtStart, pathAtStart, start, runErr, time.Now()); dark {
				turnLog("[WORKER %d] Error (streak %d): %v → parked: the path to the relays is dark (%s)",
					s.id, st.failStreak, runErr, why)
				if s.parkInTheDark(ctx, &st) {
					return
				}
				continue
			}
		}
		turnLog("[WORKER %d] Error (streak %d): %v → retry in %v%s", s.id, st.failStreak, runErr, retryDelay, note)
		// A delay the dark earned ends when another stream's session gets
		// through (path_revival.go).
		revivable := pathWideFailure(runErr)
		var revived <-chan struct{}
		if revivable {
			revived = proven
		}
		workerWaits(workerWait{stream: s.id, delay: retryDelay, revivable: revivable})
		deadline := time.Now().Add(retryDelay)
		select {
		case <-time.After(retryDelay):
		case <-revived:
			// One at a time behind the other workers the same proof woke.
			if !awaitRevivalSlot(ctx, deadline) {
				return
			}
			st.reset()
			if early := time.Until(deadline); early > 0 {
				turnLog("[WORKER %d] another stream's session got through — the path to the relays is back: reconnecting now, %v early",
					s.id, early.Round(100*time.Millisecond))
			}
		case <-ctx.Done():
			return
		}
	}
}

const (
	// maxCaptchaFailStreak is how many captcha solve ladders — each of which can
	// end in a visible WebView2 window — the session runs back to back before the
	// workers accept that the gate is not opening and stop. Counted session-wide
	// (see captchaFailureStreak); each failure also widens the global lockout, so
	// the five attempts stretch over ~15 minutes instead of hammering the user.
	// vkSemaphore still admits two concurrent VK fetches, but the 3-6s gap in
	// fetchVkCreds spaces the token chains themselves, so two workers no longer
	// run a full ladder each in the same round.
	maxCaptchaFailStreak = 5
	// credRetryBase is the first backoff after a failed credential fetch, and
	// credRetryMax caps the exponential growth.
	credRetryBase = 30 * time.Second
	credRetryMax  = 5 * time.Minute
)

// credRetryDelay returns the jittered backoff before retrying a credential fetch
// that failed for a recoverable reason: 30s, 1m, 2m, 4m, then 5m. A flat 30s
// forever kept a permanently broken group hitting VK 120 times an hour.
func credRetryDelay(streak int) time.Duration {
	if streak < 1 {
		streak = 1
	}
	d := credRetryBase << uint(min(streak-1, 4))
	if d > credRetryMax {
		d = credRetryMax
	}
	return d + time.Duration(rand.Intn(5000))*time.Millisecond
}

// isTerminalCredError reports whether a credential failure is one that no retry
// can fix: the VK call has ended or the join link is invalid (CALL_UNAVAILABLE),
// or the call refuses anonymous joins (CALL_REQUIRES_AUTH).
func isTerminalCredError(err error) bool {
	return isCallUnavailable(err) || errors.Is(err, errCallRequiresAuth)
}

// workerWait is a wait a worker goes into before its next attempt.
type workerWait struct {
	stream int
	delay  time.Duration
	// revivable: another stream's session getting through ends it; parked: it
	// lasts while the path is dark rather than for delay (path_revival.go).
	revivable, parked bool
}

// workerWaits is called as a worker goes into the wait before its next attempt.
// A seam for the tests, which have to know the worker is in that wait and not
// still on its way there.
var workerWaits = func(workerWait) {}

// attemptOrder is the order an attempt of this stream on user's credential
// dials addrs in: streamAttemptOrderAround — move is the head of a move off a
// rested relay, nil for none — with the relay this stream's handshakes keep
// failing on while others hear it put last, for this stream only
// (relay_heard_by_others.go). The attempt's own order and the check of whether
// the next one starts elsewhere (runWorker) are both this.
func (s *stream) attemptOrder(user string, addrs []string, now time.Time, move *relayMove) []string {
	ordered := streamAttemptOrderAround(user, addrs, s.id, now, move)
	if avoid := s.avoidedRelay(); avoid != "" {
		ordered = relayLast(ordered, avoid)
	}
	return ordered
}

// workerBackoff is what one attempt of a worker leaves for the next: the
// failure streak that drives reconnectDelay, and the heads the attempts of this
// streak started on (failedHeads). A head change resets the streak only to a
// relay not among them (runWorker); reset forgets them with the streak.
type workerBackoff struct {
	failStreak  int
	failedHeads map[string]struct{}
	// scouting: the next attempt is this worker's turn to dial a dark path
	// (dark_scout.go).
	scouting bool
}

// reset ends the streak: the next failure starts a new one, on any relay.
func (st *workerBackoff) reset() {
	st.failStreak = 0
	clear(st.failedHeads)
}

// failed counts an attempt that started on head and failed.
func (st *workerBackoff) failed(head string) {
	st.failStreak++
	if st.failedHeads == nil {
		st.failedHeads = map[string]struct{}{}
	}
	st.failedHeads[head] = struct{}{}
}

// failedOn reports whether an attempt of this streak started on head.
func (st *workerBackoff) failedOn(head string) bool {
	_, ok := st.failedHeads[head]
	return ok
}

// headMoved resets the streak when the next attempt starts on another relay
// than this one's head, unless an attempt of this streak has failed there
// already. failedHeads is kept: the streak is over, the relays it tried are
// still tried.
func (st *workerBackoff) headMoved(head, next string) {
	if next != head && !st.failedOn(next) {
		st.failStreak = 0
	}
}

// reconnectDelay returns the backoff before a worker's next connect attempt.
// Transient TURN allocate failures (a lost UDP packet, a brief server-side
// race) usually clear on a fresh attempt — and the next attempt re-races all
// servers anyway — so the first couple of retries are fast (~0.5-1s) before
// falling back to jittered exponential backoff for a genuinely dead path.
func reconnectDelay(failStreak int) time.Duration {
	if failStreak <= 1 {
		return time.Duration(500+rand.Intn(500)) * time.Millisecond
	}
	exp := uint(failStreak - 1)
	if exp > 4 {
		exp = 4
	}
	base := time.Duration(1<<exp) * time.Second // 2,4,8,16,16s
	if base > 30*time.Second {
		base = 30 * time.Second
	}
	return base + time.Duration(5+rand.Intn(11))*time.Second
}

// isAllocateMismatch: the relay answered 437 — a 5-tuple that already has an
// allocation (Allocate: the translator handed this socket the port of one out
// of reach), or none any more (Refresh, a deallocate). Never the credential's
// fault, and not the relay's: the worker's next attempt takes a fresh socket.
func isAllocateMismatch(err error) bool {
	code, ok := turnErrorCode(err)
	return ok && code == stun.CodeAllocMismatch
}

// isQuotaError reports whether err is specifically a TURN allocation-quota
// rejection (486). Narrower than classifyCredError: only the quota case warrants
// the long quotaCooldown, because the cred IS valid — its allocation slots are
// just full (usually with our own zombie allocations after a mass teardown).
func isQuotaError(err error) bool {
	if code, ok := turnErrorCode(err); ok {
		return code == stun.CodeAllocQuotaReached
	}
	if isTransportError(err) {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "quota")
}

// turnErrorCode extracts the numeric STUN/TURN error code when err carries a
// server error response (pion builds a *stun.TurnError in sendAllocateRequest,
// client.go:441). ok=false for every other error — dial/write failures,
// watchdog, context cancellation.
func turnErrorCode(err error) (stun.ErrorCode, bool) {
	var turnErr *stun.TurnError
	if errors.As(err, &turnErr) {
		return turnErr.ErrorCodeAttr.Code, true
	}
	return 0, false
}

// isTransportError reports whether err is a socket/network-level failure (dial
// refused, EHOSTUNREACH, EPIPE, timeout). Such errors say nothing about the
// credential — and critically, their text carries IPs and ephemeral ports, so
// they must never reach the substring fallbacks below. Field case: an Allocate
// from local port 50819 produced "write udp 10.69.196.227:50819->…: broken
// pipe", whose "508" matched the Insufficient-Capacity pattern and force-expired
// a healthy credential mid-outage.
func isTransportError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var syscallErr syscall.Errno
	return errors.As(err, &syscallErr)
}

// quotaCooldown is the jittered backoff after a 486 on a credential that is still
// current — its rotation was throttled, so the next attempt would run on the same
// full quota. 5-13s spreads the N simultaneously-saturated workers so they don't
// retry in lockstep and re-hit 486. (A 486 on a credential already replaced
// retries at once; see runWorker.)
func quotaCooldown() time.Duration {
	return 5*time.Second + time.Duration(rand.Intn(8001))*time.Millisecond
}

// classifyCredError reports whether err from a TURN session indicates the
// credential should be re-fetched: TURN allocation quota (486) or stale/invalid
// credentials (401/stale nonce/etc.). Other errors (dial failures, watchdog,
// transient drops) are handled by a plain reconnect that keeps the credential.
//
// Classification is code-driven where possible: pion surfaces a server error
// response as *stun.TurnError, so the numeric code is authoritative. Bare
// substring matching on the message is the fallback for errors that never carry
// a code (our own wrappers, non-pion paths) — and it runs only after transport
// errors are excluded, because their addresses/ports collide with the numeric
// patterns (see isTransportError). The surviving numeric patterns are anchored
// on "error " for the same reason.
func classifyCredError(err error) bool {
	if code, ok := turnErrorCode(err); ok {
		switch code {
		// 437 is not here. iOS field log 2026-09-28 12:58: Allocate answered
		// 437 on a fresh socket, the credential was rotated, and the fresh
		// credential got the same 437 on both relays — the 5-tuple was the
		// problem (a port the translator reused for an allocation out of
		// reach), and the worker's next socket succeeded. A trip to VK for it
		// is a step towards a captcha for nothing (isAllocateMismatch).
		case stun.CodeUnauthorized, // 401
			stun.CodeStaleNonce,           // 438
			stun.CodeWrongCredentials,     // 441
			stun.CodeAllocQuotaReached,    // 486
			stun.CodeInsufficientCapacity: // 508
			return true
		}
		return false
	}
	if isTransportError(err) {
		return false
	}
	e := strings.ToLower(err.Error())
	return strings.Contains(e, "quota") ||
		strings.Contains(e, "error 486") ||
		strings.Contains(e, "allocation quota reached") ||
		strings.Contains(e, "error 401") ||
		strings.Contains(e, "unauthorized") ||
		strings.Contains(e, "stale nonce") ||
		strings.Contains(e, "attribute not found") ||
		strings.Contains(e, "error 508") ||
		strings.Contains(e, "error 29")
}

// applyTurnOverride applies the optional manual TurnIP/TurnPort pin to the
// fetched TURN server list. A TurnIP pin replaces the whole list with the single
// pinned server; a bare TurnPort rewrites the port on every server. Returns a
// fresh slice when rewriting — addrs may alias the cached ServerAddrs slice
// (returned by reference on a cache hit), so it must not be mutated in place.
func applyTurnOverride(addrs []string, cfg WorkerGroupConfig) []string {
	if cfg.TurnIP != "" {
		_, origPort, _ := net.SplitHostPort(addrs[0])
		port := origPort
		if cfg.TurnPort != 0 {
			port = fmt.Sprintf("%d", cfg.TurnPort)
		}
		return []string{net.JoinHostPort(cfg.TurnIP, port)}
	}
	if cfg.TurnPort != 0 {
		rewritten := make([]string, len(addrs))
		for i, a := range addrs {
			origHost, _, _ := net.SplitHostPort(a)
			rewritten[i] = net.JoinHostPort(origHost, fmt.Sprintf("%d", cfg.TurnPort))
		}
		return rewritten
	}
	return addrs
}
