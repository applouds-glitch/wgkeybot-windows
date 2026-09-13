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

// A typical device runs 8 streams (2 groups × 4) against the 2 TURN servers VK
// returns. Until one of them is elected the load must land 4/4 rather than
// piling onto one host: a server nobody dials never proves itself, and the
// election would have nothing to choose from. resetServerHealth puts every test
// in this file back into that probing state.
func TestAssignServersSpreadsEvenly(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"1.1.1.1:3478", "2.2.2.2:3478"}

	counts := map[string]int{}
	for id := 0; id < 8; id++ {
		counts[assignServers(addrs, id)[0]]++
	}

	for _, a := range addrs {
		if counts[a] != 4 {
			t.Errorf("server %s got %d of 8 streams, want 4 (counts: %v)", a, counts[a], counts)
		}
	}
}

// The assigned server must be the same for a given stream ID no matter what
// order VK happened to return the urls in for that group's link — otherwise
// group 0 and group 1 would disagree on which server is index 0 and the split
// would drift.
func TestAssignServersCanonicalOrder(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	forward := []string{"1.1.1.1:3478", "2.2.2.2:3478"}
	reversed := []string{"2.2.2.2:3478", "1.1.1.1:3478"}

	for id := 0; id < 8; id++ {
		if got, want := assignServers(reversed, id), assignServers(forward, id); !reflect.DeepEqual(got, want) {
			t.Errorf("stream %d: reversed input gave %v, want %v", id, got, want)
		}
	}
}

// Every server with no verdict against it stays in the returned list — the ones
// after index 0 are the failover candidates runWithCreds falls back to when the
// assigned one errors.
func TestAssignServersKeepsFailoverCandidates(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"3.3.3.3:3478", "1.1.1.1:3478", "2.2.2.2:3478"}

	for id := 0; id < 6; id++ {
		got := assignServers(addrs, id)
		if len(got) != len(addrs) {
			t.Fatalf("stream %d: got %d servers, want %d", id, len(got), len(addrs))
		}
		seen := map[string]bool{}
		for _, a := range got {
			seen[a] = true
		}
		for _, a := range addrs {
			if !seen[a] {
				t.Errorf("stream %d: server %s missing from %v", id, a, got)
			}
		}
	}
}

// addrs may alias the cached TurnCredentials.ServerAddrs slice (getCredsCached
// returns it by reference on a hit), so assignServers must never reorder in
// place — that would corrupt the cache for every other stream in the group.
func TestAssignServersDoesNotMutateInput(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"3.3.3.3:3478", "1.1.1.1:3478"}
	orig := append([]string(nil), addrs...)

	for id := 0; id < 4; id++ {
		assignServers(addrs, id)
	}

	if !reflect.DeepEqual(addrs, orig) {
		t.Errorf("input mutated: got %v, want %v", addrs, orig)
	}
}

// A single server (VK returned one url, or TurnIP is pinned) must pass through
// untouched — applyTurnOverride collapses the list before we get here.
func TestAssignServersSingleServer(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"1.1.1.1:3478"}

	for id := 0; id < 4; id++ {
		if got := assignServers(addrs, id); !reflect.DeepEqual(got, addrs) {
			t.Errorf("stream %d: got %v, want %v", id, got, addrs)
		}
	}
}

// A stood-down server must not keep receiving its assigned stream: assignServers
// drops it from the list entirely, so a stream pinned to a dead host recovers
// without waiting for a tunnel restart — and the dead host cannot win the
// failover fan-out either.
func TestAssignServersSkipsPenalizedServer(t *testing.T) {
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

	got := assignServers(addrs, 0)
	if got[0] != "2.2.2.2:3478" {
		t.Fatalf("penalized server not skipped: got %v, want first entry 2.2.2.2:3478", got)
	}
	if slices.Contains(got, addrs[0]) {
		t.Fatalf("penalized server left in the failover list: %v", got)
	}
}

// If every server is penalized, that is an outage, not a bad host, and the
// failover list would be no better — assignServers must keep the original
// assignment rather than rotating to an equally-penalized "next" server. This
// is the single line standing between a total outage and every stream having
// nowhere to go (see the fallback comment on assignServers).
func TestAssignServersAllPenalizedKeepsOriginalAssignment(t *testing.T) {
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

	for id := 0; id < len(addrs); id++ {
		want := append(append([]string(nil), addrs[id:]...), addrs[:id]...)
		if got := assignServers(addrs, id); !reflect.DeepEqual(got, want) {
			t.Errorf("stream %d: all servers penalized but assignment changed: got %v, want %v (unpenalized rotation)", id, got, want)
		}
	}
}
