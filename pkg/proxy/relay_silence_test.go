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
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// Silence is what nothing answered, and only that: a reset, a refusal or a TURN
// answer is the relay heard, and what is not recognised stays the relay's. The
// errnos are this platform's own (local_network_failure_*.go).
func TestSilentFailureIsWhatNothingAnswered(t *testing.T) {
	for _, err := range []error{
		&net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded},
		opErr("recvfrom", relayTimedOutErrnos[0]),
		context.DeadlineExceeded,
		fmt.Errorf("%w %s", errors.New(pionAllRetransmissionsFailed), "dHJhbnNhY3Rpb24="),
		fmt.Errorf("relay proof: %w", errRelayNeverAnswered),
		fmt.Errorf("TURN allocate: %w within %v", errAllocateSilent, allocateSilenceTimeout),
	} {
		if !silentFailure(err) {
			t.Errorf("%v is not taken for silence", err)
		}
	}
	for _, err := range []error{
		nil,
		opErr("read", relayResetErrnos[0]),
		opErr("write", relayResetErrnos[1]),
		opErr("connect", relayRefusedErrnos[0]),
		&stun.TurnError{ErrorCodeAttr: stun.ErrorCodeAttribute{Code: stun.CodeAllocQuotaReached}},
		net.ErrClosed,
		errors.New("all retransmissions failed for 10.0.0.1"), // text alone is not the sentinel
	} {
		if silentFailure(err) {
			t.Errorf("%v is taken for silence", err)
		}
	}
}

// A silence is held against no relay only while none is heard.
func TestSilenceIsExcusedOnlyWhileNoRelayIsHeard(t *testing.T) {
	const relay = "relay-a:19302"
	silent := fmt.Errorf("%w within %v", errAllocateSilent, allocateSilenceTimeout)
	mark := relayHeardMark()
	if !silenceNotToBlame(silent, mark, relay) {
		t.Fatal("an Allocate unanswered with no relay heard was held against its relay")
	}
	if silenceNotToBlame(opErr("recvfrom", relayRefusedErrnos[0]), mark, relay) {
		t.Fatal("a refusal was excused as silence")
	}
	noteRelayHeard()
	if silenceNotToBlame(silent, mark, relay) {
		t.Fatal("an Allocate unanswered while a relay was heard was excused")
	}
}

// Both relays silent, the head's Allocate unanswered and the failover to the
// other unanswered too. Before, each took a strike for every round of it.
func TestAllocatesUnansweredByEveryRelayAreHeldAgainstNone(t *testing.T) {
	first, second := twoRelaySockets(t)
	head := &sourceCounter{PacketConn: first, seen: map[string]bool{}}
	other := &sourceCounter{PacketConn: second, seen: map[string]bool{}}
	for _, c := range []*sourceCounter{head, other} {
		go func() {
			b := make([]byte, 1500)
			for {
				if _, _, err := c.ReadFrom(b); err != nil {
					return
				}
			}
		}()
	}

	runWorkersAgainst(t, 151, 1, []string{first.LocalAddr().String(), second.LocalAddr().String()})
	// The second attempt's socket reaching the head: the first attempt has
	// failed, on both relays, and been accounted for.
	waitFor(t, "the stream's second attempt", 20*time.Second, func() bool { return head.count() >= 2 })
	for _, c := range []*sourceCounter{head, other} {
		if n := relayStrikes(c.LocalAddr().String()); n != 0 {
			t.Errorf("%s took %d strike(s) for an Allocate no relay answered", c.LocalAddr(), n)
		}
	}
}

// …and a relay silent while another one answers still counts: the head is
// mute, the stream comes up on the failover, and the head takes its strike.
func TestAllocateUnansweredWhileARelayWasHeardStillCounts(t *testing.T) {
	first, second := twoRelaySockets(t)
	head := &sourceCounter{PacketConn: first, seen: map[string]bool{}}
	go func() {
		b := make([]byte, 1500)
		for {
			if _, _, err := head.ReadFrom(b); err != nil {
				return
			}
		}
	}()
	startTestRelay(t, second, 0)
	// A relay heard while the head's Allocate waits: the other stream of the
	// worker's own, as far as this one can tell.
	var stop atomic.Bool
	t.Cleanup(func() { stop.Store(true) })
	go func() {
		for !stop.Load() {
			noteRelayHeard()
			time.Sleep(100 * time.Millisecond)
		}
	}()

	h := runWorkersAgainst(t, 153, 1, []string{first.LocalAddr().String(), second.LocalAddr().String()})
	waitFor(t, "the stream up on the failover", 10*time.Second, func() bool { return h.ready() == 1 })
	waitFor(t, "the mute head's strike", 5*time.Second, func() bool { return relayStrikes(first.LocalAddr().String()) > 0 })
}

// A relay whose port is closed refuses over ICMP, and pion hides the refusal
// behind a retransmit it could not write: the refusal is the relay heard, and
// it still counts (Codex review of the Android port, 18.10). Not on Windows:
// Go turns the refusal off for UDP sockets there (SIO_UDP_CONNRESET), and a
// closed port is silence like any other.
func TestAllocateRefusedOverICMPStillCounts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("UDP sockets report no ICMP refusal on Windows")
	}
	pc := listenFakeRelay(t)
	closedPort := pc.LocalAddr().String()
	pc.Close()

	runWorkersAgainst(t, 152, 1, []string{closedPort})
	waitFor(t, "the closed port's strike", 8*time.Second, func() bool { return relayStrikes(closedPort) > 0 })
}

// withRelayHeardAt makes at the last time a relay was heard for this test (the
// zero time: never), clears the record of the path's silences, and puts it all
// back after it.
func withRelayHeardAt(t *testing.T, at time.Time) {
	t.Helper()
	prevHeard, prevGap := relayHeardAt.Load(), relayGapEndAt.Load()
	relayGapEndAt.Store(0)
	t.Cleanup(func() {
		relayHeardAt.Store(prevHeard)
		relayGapEndAt.Store(prevGap)
	})
	if at.IsZero() {
		relayHeardAt.Store(0)
		return
	}
	relayHeardAt.Store(int64(at.Sub(relayHeardBase)))
}

// relayBaseTime is a value of relayHeardAt as a time.
func relayBaseTime(v int64) time.Time { return relayHeardBase.Add(time.Duration(v)) }

// A reader whose time is behind the one already stored neither sets the time
// back nor makes up a silence out of the gap the later reader measured.
func TestALateReaderDoesNotSetTheTimeHeardBack(t *testing.T) {
	now := time.Now()
	withRelayHeardAt(t, now.Add(time.Hour)) // a later reader got there first
	noteRelayHeard()
	if got := relayBaseTime(relayHeardAt.Load()); got.Before(now.Add(time.Hour)) {
		t.Fatalf("the time last heard went back to %v", got.Sub(now))
	}
	if pathGapEndedSince(now.Add(-time.Hour)) {
		t.Fatal("a late reader recorded a silence")
	}
}

// The first relay heard after no relay at all was, for longer than
// wholePathGap, marks the end of the path's silence; a shorter pause — the
// keepalive grid's own — and the very first relay ever heard do not.
func TestTheEndOfAWholePathSilenceIsRecorded(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name  string
		heard time.Time // the relay last heard before this one
		gap   bool
	}{
		{"after a dark minute", now.Add(-time.Minute), true},
		{"just past the gap", now.Add(-wholePathGap - time.Second), true},
		{"a keepalive interval", now.Add(-keepaliveInterval), false},
		{"never heard before", time.Time{}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			withRelayHeardAt(t, c.heard)
			noteRelayHeard()
			if got := pathGapEndedSince(now.Add(-time.Second)); got != c.gap {
				t.Fatalf("a silence ending now recorded = %v, want %v", got, c.gap)
			}
			if pathGapEndedSince(time.Now().Add(time.Second)) {
				t.Fatal("a silence read as ending after it did")
			}
		})
	}
}

// An end recorded later is never taken back by one recorded earlier — what two
// racing readers, swapping their times in out of order, would otherwise do.
func TestAWholePathSilenceEndOnlyMovesForward(t *testing.T) {
	var end atomic.Int64
	advanceGapEnd(&end, 200)
	advanceGapEnd(&end, 100)
	if got := end.Load(); got != 200 {
		t.Fatalf("the end moved back to %d", got)
	}
	advanceGapEnd(&end, 300)
	if got := end.Load(); got != 300 {
		t.Fatalf("the end did not move forward: %d", got)
	}
}
