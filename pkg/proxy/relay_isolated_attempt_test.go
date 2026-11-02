/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// What a live sibling excuses on a failed TCP attempt, and what it never does:
// the relay's own answer stays the relay's, whoever else it is serving.
func TestIsolatedTCPAttemptFailure(t *testing.T) {
	now := time.Now()
	const relay = "relay-a:19302"
	failing := dispatchStream(2, false, now, 8)
	silence := fmt.Errorf("%w %s", errors.New(pionAllRetransmissionsFailed), "dHJhbnNhY3Rpb24=")
	timeout := opErr("dial", relayTimedOutErrnos[0])

	if tcpAttemptFailureIsIsolated(relay, failing, timeout) {
		t.Fatal("a failure was excused with nobody else on the relay")
	}
	defer trackLiveSession(relay, dispatchStream(1, true, now, 8))()

	for _, err := range []error{
		timeout,
		opErr("connect", relayResetErrnos[0]),
		silence,
		fmt.Errorf("%w %s", errors.New(pionFailedToRetransmit), "key"),
		fmt.Errorf("%w within %v", errAllocateSilent, relayTCPAllocateTimeout),
		io.EOF,
		io.ErrUnexpectedEOF,
	} {
		if !tcpAttemptFailureIsIsolated(relay, failing, err) {
			t.Errorf("%v was held against a relay another stream is hearing", err)
		}
	}
	for _, err := range []error{
		nil,
		&stun.TurnError{ErrorCodeAttr: stun.ErrorCodeAttribute{Code: stun.CodeAllocQuotaReached}},
		&stun.TurnError{ErrorCodeAttr: stun.ErrorCodeAttribute{Code: stun.CodeUnauthorized}},
		errors.New("attribute not found"),
		errors.New("all retransmissions failed for 10.0.0.1"), // text alone is not the sentinel
		errDataPlaneHandshake,
	} {
		if tcpAttemptFailureIsIsolated(relay, failing, err) {
			t.Errorf("%v was excused: that is the relay's answer, or not a transport failure at all", err)
		}
	}
	if tcpAttemptFailureIsIsolated("relay-b:19302", failing, timeout) {
		t.Fatal("a stream on one relay excused another")
	}
}

// blackholeNthRelayDial sends the nth TCP dial to a listener that accepts and
// never answers: the connect succeeds and the Allocate meets silence.
func blackholeNthRelayDial(t *testing.T, nth int32) {
	t.Helper()
	hole := listenTCPRelay(t)
	silentTCPRelay(hole)
	prev := dialRelayTCP
	var dialed atomic.Int32
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
		if dialed.Add(1) == nth {
			return prev(ctx, d, hole.Addr().String())
		}
		return prev(ctx, d, addr)
	}
	t.Cleanup(func() { dialRelayTCP = prev })
}

// shortTCPAllocate gives an Allocate over TCP a deadline the test can wait out.
func shortTCPAllocate(t *testing.T) {
	t.Helper()
	prev := relayTCPAllocateTimeout
	relayTCPAllocateTimeout = 2 * time.Second
	t.Cleanup(func() { relayTCPAllocateTimeout = prev })
}

// End to end: an Allocate that meets silence over TCP while a sibling is up on
// the same relay costs the relay nothing…
func TestSilentTCPAllocateBesideALiveSiblingIsNotTheRelaysFault(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	shortTCPAllocate(t)
	pinRelayConnectGap(t, 600*time.Millisecond) // the sibling is ready before the second dial
	blackholeNthRelayDial(t, 2)

	h := runWorkersAgainst(t, 173, 2, []string{relay.addr})
	waitFor(t, "both streams up, the second after its silent Allocate", 15*time.Second, func() bool { return h.ready() == 2 })
	if n := relayStrikes(relay.addr); n != 0 {
		t.Fatalf("the relay took %d strike(s) for one flow's silence with a sibling hearing it", n)
	}
}

// …and with nobody on the relay it still counts.
func TestSilentTCPAllocateAloneStillCounts(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	shortTCPAllocate(t)
	blackholeNthRelayDial(t, 1)

	h := runWorkersAgainst(t, 174, 1, []string{relay.addr})
	waitFor(t, "the stream up after its silent Allocate", 15*time.Second, func() bool { return h.ready() == 1 })
	if n := relayStrikes(relay.addr); n != 1 {
		t.Fatalf("the relay took %d strike(s) for a silent Allocate with nobody to vouch for it, want 1", n)
	}
}
