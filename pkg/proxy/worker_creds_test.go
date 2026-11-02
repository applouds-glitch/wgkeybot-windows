/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"reflect"
	"slices"
	"testing"
	"time"
)

// Streams take turns: stream i prefers the (i mod n)-th server in canonical
// order, with the rest of the list behind it as failover. resetServerHealth puts
// every test in this file back into a state with no verdicts.
func TestAssignRelaysSpreadsTheStreams(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"2.2.2.2:3478", "1.1.1.1:3478"}
	for id := 0; id < 8; id++ {
		want := []string{"1.1.1.1:3478", "2.2.2.2:3478"}[id%2]
		if got := assignRelays(addrs, id, time.Now())[0]; got != want {
			t.Fatalf("stream %d ran on %s, want %s", id, got, want)
		}
	}
}

// A stream's server must be the same no matter what order VK happened to return
// the urls in for a group's link — otherwise the same stream would land on
// different hosts in different groups' lists.
func TestAssignRelaysCanonicalOrder(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	forward := []string{"1.1.1.1:3478", "2.2.2.2:3478"}
	reversed := []string{"2.2.2.2:3478", "1.1.1.1:3478"}

	for id := 0; id < 4; id++ {
		if got, want := assignRelays(reversed, id, time.Now()), assignRelays(forward, id, time.Now()); !reflect.DeepEqual(got, want) {
			t.Errorf("stream %d: reversed input gave %v, want %v", id, got, want)
		}
	}
}

// Every server with no verdict against it stays in the returned list — the ones
// after index 0 are the failover candidates runWithCreds falls back to when the
// first one errors.
func TestAssignRelaysKeepsFailoverCandidates(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"3.3.3.3:3478", "1.1.1.1:3478", "2.2.2.2:3478"}

	got := assignRelays(addrs, 1, time.Now())
	want := []string{"2.2.2.2:3478", "3.3.3.3:3478", "1.1.1.1:3478"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// addrs may alias the cached TurnCredentials.ServerAddrs slice (getCredsCached
// returns it by reference on a hit), so assignRelays must never reorder in
// place — that would corrupt the cache for every other stream in the group.
func TestAssignRelaysDoesNotMutateInput(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"3.3.3.3:3478", "1.1.1.1:3478"}
	orig := append([]string(nil), addrs...)

	assignRelays(addrs, 1, time.Now())

	if !reflect.DeepEqual(addrs, orig) {
		t.Errorf("input mutated: got %v, want %v", addrs, orig)
	}
}

// A single server (VK returned one url, or TurnIP is pinned) must pass through
// untouched — applyTurnOverride collapses the list before we get here.
func TestAssignRelaysSingleServer(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"1.1.1.1:3478"}

	if got := assignRelays(addrs, 3, time.Now()); !reflect.DeepEqual(got, addrs) {
		t.Errorf("got %v, want %v", got, addrs)
	}
}

// A stood-down server must not keep receiving its assigned stream: assignRelays
// drops it from the list entirely, so a stream pinned to a dead host recovers
// without waiting for a tunnel restart — and the dead host cannot win the
// failover fan-out either.
func TestAssignRelaysSkipsPenalizedServer(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"1.1.1.1:3478", "2.2.2.2:3478", "3.3.3.3:3478"}

	// Stream 0 is assigned sorted[0] == addrs[0] ("1.1.1.1:3478" already sorts
	// first). Stand it down with serverFailThreshold strikes spaced past
	// serverFailCoalesce so each one counts, mirroring
	// TestNoteServerFailurePenalizesPersistentTrouble's clock seam.
	start := time.Now()
	step := serverFailCoalesce + time.Second
	for strike := 0; strike < serverFailThreshold; strike++ {
		noteServerFailureAt(addrs[0], start.Add(time.Duration(strike)*step))
	}

	got := assignRelays(addrs, 0, start.Add(time.Duration(serverFailThreshold)*step))
	if got[0] != "2.2.2.2:3478" {
		t.Fatalf("penalized server not skipped: got %v, want first entry 2.2.2.2:3478", got)
	}
	if slices.Contains(got, addrs[0]) {
		t.Fatalf("penalized server left in the failover list: %v", got)
	}
}

// If every server is penalized, that is an outage, not a bad host: the whole
// list stands, in outage order (here, with no proof anywhere, the canonical
// one), for every stream alike — the head is where every stream starts, the
// rest the failover the head's failure fans out to.
func TestAssignRelaysAllPenalizedKeepsTheWholeList(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"1.1.1.1:3478", "2.2.2.2:3478", "3.3.3.3:3478"}

	start := time.Now()
	step := serverFailCoalesce + time.Second
	for _, a := range addrs {
		for strike := 0; strike < serverFailThreshold; strike++ {
			noteServerFailureAt(a, start.Add(time.Duration(strike)*step))
		}
	}

	now := start.Add(time.Duration(serverFailThreshold) * step)
	for id := 0; id < len(addrs); id++ {
		if got := assignRelays(addrs, id, now); !reflect.DeepEqual(got, addrs) {
			t.Errorf("stream %d: all servers penalized: got %v, want the whole list %v", id, got, addrs)
		}
	}
}

// A negative stream ID still lands inside the list.
func TestAssignRelaysNegativeStreamID(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"1.1.1.1:3478", "2.2.2.2:3478"}
	if got := assignRelays(addrs, -1, time.Now()); got[0] != "2.2.2.2:3478" {
		t.Fatalf("stream -1 got %v, want 2.2.2.2:3478 first", got)
	}
}
