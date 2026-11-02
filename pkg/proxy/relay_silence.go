/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */
package proxy

import (
	"errors"
	"net"
	"sync/atomic"
	"time"
)

// A relay is not held to account for a silence the whole path shared.
//
// Android, periodic-download run on 18.10: twice in an hour the modem went
// after a cell that carried nothing, and the path was dark for about two
// minutes with the OS none the wiser — the network up throughout, the same
// address, no switch. The workers redialled into the dark: every Allocate to
// every relay went unanswered, and each silence struck its relay.
// serverFailCoalesce only slowed that down — 30s into the redials all six relays
// VK had given were stood down for five minutes, re-armed every ten seconds
// until the light came back. With every relay stood down assignRelays falls back
// to outageOrder: once the path was back, 8 of the 10 streams came up on one
// relay, and 13 minutes later they were still on it. A home router whose uplink
// stalls, or Wi-Fi that stays associated with nothing behind it, is the same
// dark here.
//
// So a failure that was only silence (silentFailure) counts against its relay
// only if some relay was heard while it was failing: anything read from a
// relay's socket — a TURN answer, a challenge or a refusal included, or data.
// A relay that is down while others answer is still struck. With nothing heard
// the silence is the path's or the relay's and nothing tells which, so it is
// not counted: an attempt that raced the other relays and heard none of them
// either, a stream alone on a dead relay. If every relay really has gone,
// standing them all down changes nothing anyway — the whole list comes back
// (assignRelays).
//
// Heard is counted as a sequence rather than a clock: an attempt notes where
// the count stood when it began and asks, when it fails, whether it has moved.
//
// VK's own API calls keep relayNotToBlame alone (vk_calls.go): their silence is
// VK's or a filter's in front of it, and the legacy chain is the fallback.
//
// Port of Android 8133eb44 (with ac30b25c, c0ad6e60), one transport: Android
// keeps the count per transport, UDP and TCP, and this client dials the relays
// over UDP only.

// relayHeard counts the times a relay was heard; relayHeardAt is when it last
// was, on the monotonic clock since relayHeardBase (0: never), for how long the
// path has been silent.
var (
	relayHeard     atomic.Uint64
	relayHeardAt   atomic.Int64
	relayHeardBase = time.Now()
	// relayGapEndAt is, on the same clock, when the last silence of the whole
	// path longer than wholePathGap ended — the first relay heard after it; 0:
	// none since the process started.
	relayGapEndAt atomic.Int64
)

// wholePathGap is how long no relay at all may go unheard before the silence
// counts as the whole path's (pathGapEndedSince). At rest every stream's
// keepalive goes out in one window of keepaliveSpread every keepaliveInterval,
// and their echoes come back in it, so the path's own gaps are about 25s; one
// keepalive or its echo lost and the next, the repeat, is 3s behind.
// dispatchStaleAfter is past both, as for a single stream.
const wholePathGap = dispatchStaleAfter

// noteRelayHeard records a relay heard, and the end of a silence of the whole
// path if this is the first relay heard after one.
//
// The time last heard moves forward only, and the silence is measured from the
// time it moves forward from. Two readers race here — every relay socket's
// read loop calls in — and with a plain swap the one that took its time first
// could store it last, setting the time back and making up a silence out of
// the other's (Codex review of the Android port, 23.10). A reader whose time is
// behind the stored one adds nothing: the later reader has already measured
// from it.
func noteRelayHeard() {
	relayHeard.Add(1)
	now := int64(time.Since(relayHeardBase))
	for {
		prev := relayHeardAt.Load()
		if now <= prev {
			return
		}
		if relayHeardAt.CompareAndSwap(prev, now) {
			if prev != 0 && now-prev > int64(wholePathGap) {
				advanceGapEnd(&relayGapEndAt, now)
			}
			return
		}
	}
}

// advanceGapEnd moves end to at, unless it is already there or later.
func advanceGapEnd(end *atomic.Int64, at int64) {
	for {
		cur := end.Load()
		if at <= cur || end.CompareAndSwap(cur, at) {
			return
		}
	}
}

// resetRelayHeardClocks forgets when a relay was last heard and when the last
// silence of the whole path ended — for a path over another transport
// (claimTransport). The count itself goes on: marks are only compared.
func resetRelayHeardClocks() {
	relayHeardAt.Store(0)
	relayGapEndAt.Store(0)
}

// pathGapEndedSince reports whether a silence of the whole path, longer than
// wholePathGap, ended after since: no relay at all was heard for that long, and
// the light came back after since.
func pathGapEndedSince(since time.Time) bool {
	end := relayGapEndAt.Load()
	return end != 0 && relayHeardBase.Add(time.Duration(end)).After(since)
}

// sinceRelayHeard is how long ago a relay was last heard, 0 if one never was.
func sinceRelayHeard(now time.Time) time.Duration {
	at := relayHeardAt.Load()
	if at == 0 {
		return 0
	}
	return now.Sub(relayHeardBase) - time.Duration(at)
}

// relayHeardMark is where the count stands now.
func relayHeardMark() uint64 { return relayHeard.Load() }

// pionTransactionLost reports whether err is a TURN transaction pion gave up:
// every retransmission unanswered, or one it could not write. pion wraps these
// private sentinels without a net.Error, and the retransmit write failure
// discards the socket error, so only the unwrapped sentinel is matched — not
// response text, addresses or transaction IDs (TestMarkersExistInVendoredPion
// pins both strings).
func pionTransactionLost(err error) bool {
	cause := err
	for errors.Unwrap(cause) != nil {
		cause = errors.Unwrap(cause)
	}
	switch cause.Error() {
	case pionAllRetransmissionsFailed, pionFailedToRetransmit:
		return true
	}
	return false
}

// The texts of pion's lost-transaction sentinels (pion/turn errors.go).
const (
	pionAllRetransmissionsFailed = "all retransmissions failed for"
	pionFailedToRetransmit       = "turn: failed to retransmit transaction"
)

// silentFailure reports whether err is a failure in which nothing came back
// from the relay: a connect or a deadline of ours timing out (an Allocate
// unanswered, a relay proof unanswered), a TURN transaction pion gave up, a
// flow the system gave up — even if a write then met the broken connection it
// leaves behind. Not a reset or a broken pipe of any other kind (the relay's
// packet, or what one leaves), not a refusal or any TURN answer, and not a
// failure it does not recognise.
func silentFailure(err error) bool {
	if err == nil {
		return false
	}
	if _, answered := turnErrorCode(err); answered || errnoIn(err, relayRefusedErrnos) {
		return false
	}
	if errors.Is(err, errRelayFlowTimedOut) {
		return true
	}
	if errnoIn(err, relayResetErrnos) {
		return false
	}
	var netErr net.Error
	switch {
	case errnoIn(err, relayTimedOutErrnos), errors.Is(err, errRelayNeverAnswered), errors.Is(err, errAllocateSilent):
		return true
	case errors.As(err, &netErr) && netErr.Timeout():
		return true
	}
	return pionTransactionLost(err)
}

// silenceNotToBlame reports whether an attempt, begun when the count stood at
// mark and ended in err, failed in a silence no relay broke meanwhile, and says
// so once in a while.
func silenceNotToBlame(err error, mark uint64, addr string) bool {
	if !silentFailure(err) || relayHeardMark() != mark {
		return false
	}
	logSilenceExcused(addr, err)
	return true
}

// A dark path fails every attempt to every relay: one line every
// silenceLogEvery, not one per attempt.
const silenceLogEvery = 30 * time.Second

// silenceLogged holds when the line last went out, on the monotonic clock since
// silenceLogBase: a wall clock stepped back by the network would keep it quiet,
// and it is the one trace an excuse leaves.
var (
	silenceLogBase = time.Now()
	silenceLogged  atomic.Int64
)

func logSilenceExcused(addr string, err error) {
	now := int64(time.Since(silenceLogBase))
	last := silenceLogged.Load()
	if (last != 0 && now-last < int64(silenceLogEvery)) || !silenceLogged.CompareAndSwap(last, now) {
		return
	}
	turnLog("[TURN HEALTH] %s: %v — no relay heard while it failed: a silence the whole path shares is held against no relay (logged once per %v)",
		addr, err, silenceLogEvery)
}

// relayHeardConn counts every read from a relay's socket as the relay heard,
// and an ICMP refusal reported on a read or a write as well: it crossed the
// path, which is lit. On Windows Go turns the refusal off for UDP sockets
// (SIO_UDP_CONNRESET, net/fd_windows.go), so there it never arrives and a relay
// with its port closed fails as silence; elsewhere pion drops the errno on the
// way, and only this sees it (Codex review of the Android port, 18.10).
type relayHeardConn struct {
	net.PacketConn
}

func (c relayHeardConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil || errnoIn(err, relayRefusedErrnos) {
		noteRelayHeard()
	}
	return n, addr, err
}

func (c relayHeardConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, addr)
	if errnoIn(err, relayRefusedErrnos) {
		noteRelayHeard()
	}
	return n, err
}
