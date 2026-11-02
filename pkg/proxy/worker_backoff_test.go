/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */
package proxy

import (
	"slices"
	"testing"
	"time"
)

// Two relays failing every handshake: the first failure moves the stream to
// the other relay, a first attempt there; once both are demoted outageOrder
// hands the first one back, and that is no fresh start — this streak has failed
// there already. The streak used to start over on that return as well.
func TestABackoffStreakSurvivesTheReturnToARelayItFailedOn(t *testing.T) {
	resetServerHealth()
	t.Cleanup(resetServerHealth)
	resetAllocationBook(t)
	const relayA, relayB = "10.0.0.1:3478", "10.0.0.2:3478"
	addrs := []string{relayA, relayB}

	var st workerBackoff
	var heads []string
	var streaks []int
	for range 4 {
		now := time.Now()
		head := streamAttemptOrder("u", addrs, 0, now)[0]
		heads = append(heads, head)
		noteServerHandshakeFailureAt(head, now, now)
		st.failed(head)
		st.headMoved(head, streamAttemptOrder("u", addrs, 0, now)[0])
		streaks = append(streaks, st.failStreak)
	}
	if want := []string{relayA, relayB, relayA, relayA}; !slices.Equal(heads, want) {
		t.Fatalf("heads %v, want %v: the scenario this test is about", heads, want)
	}
	if want := []int{0, 1, 2, 3}; !slices.Equal(streaks, want) {
		t.Fatalf("streaks %v, want %v: only the move to the untried relay starts over", streaks, want)
	}
}

// reset forgets the relays with the streak: a session that stayed up, a move
// off a resting relay — the next head is a fresh start wherever it is.
func TestABackoffResetForgetsTheHeads(t *testing.T) {
	var st workerBackoff
	st.failed("a")
	st.failed("b")
	st.headMoved("b", "a")
	if st.failStreak != 2 {
		t.Fatalf("streak %d after a return to a failed head, want 2", st.failStreak)
	}
	st.reset()
	st.failed("b")
	st.headMoved("b", "a")
	if st.failStreak != 0 {
		t.Fatalf("streak %d after the reset forgot the heads, want 0", st.failStreak)
	}
	st.failed("a")
	st.headMoved("a", "a")
	if st.failStreak != 1 {
		t.Fatalf("streak %d on the same head, want 1", st.failStreak)
	}
}
