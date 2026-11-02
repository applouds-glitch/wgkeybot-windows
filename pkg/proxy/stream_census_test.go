/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */
package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

// A proxy cancelled before it starts its groups — a transport rebuild while it
// prefetched, with the next proxy up already — claims nothing of the running
// one's: its stream set, its reporter's clock and its workers' fatal count stay
// as they are (Codex review of the Windows port, 2026-10-23).
func TestACancelledProxyLeavesTheRunningOnesStateAlone(t *testing.T) {
	prevSet, prevClock := activeStreams.Load(), silentUnderLoadClock.Load()
	t.Cleanup(func() {
		activeStreams.Store(prevSet)
		silentUnderLoadClock.Store(prevClock)
		resetWorkerFatalState(0)
	})
	running := []*stream{{id: 0}, {id: 1}}
	withdraw := publishStreams(running)
	defer withdraw()
	startReporterClock(time.Now())
	clock := silentUnderLoadClock.Load()
	resetWorkerFatalState(len(running))

	lc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err = StartTunnelGroups(ctx, lc, TunnelGroupsConfig{
		Links:    []string{"https://vk.com/call/join/cancelled"},
		PeerAddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 56000},
		PeerType: "proxy_v2",
	})
	if err == nil {
		t.Fatal("a cancelled proxy started its groups")
	}
	if set := activeStreamSet(); len(set) != len(running) || set[0] != running[0] {
		t.Fatalf("the running proxy's stream set was replaced: %d streams", len(set))
	}
	if silentUnderLoadClock.Load() != clock {
		t.Fatal("the running proxy's reporter clock was started anew")
	}
	if n := fatalWorkersTotal.Load(); n != int64(len(running)) {
		t.Fatalf("the running proxy's fatal count was reset to %d workers", n)
	}
}

// A generation cancelled before its StartProxy got going — a transport
// restart, then another, the next proxy up already — claims nothing when it
// does: it does not cancel the running proxy, close its listener, or reset its
// records (Codex review of the Windows port, 2026-10-23).
func TestAStartCancelledBeforeItBeganLeavesTheRunningProxyAlone(t *testing.T) {
	lc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	running, cancelRunning := context.WithCancel(context.Background())
	defer cancelRunning()
	turnMutex.Lock()
	prevCancel, prevListener := currentTurnCancel, currentListener
	currentTurnCancel, currentListener = cancelRunning, lc
	turnMutex.Unlock()
	t.Cleanup(func() {
		turnMutex.Lock()
		currentTurnCancel, currentListener = prevCancel, prevListener
		turnMutex.Unlock()
	})
	gen := beginNetworkPathGeneration()

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	if code := StartProxy(StartProxyParams{Parent: parent}); code != -1 {
		t.Fatalf("a cancelled start returned %d, want -1", code)
	}
	if running.Err() != nil {
		t.Fatal("a cancelled start cancelled the running proxy")
	}
	if _, err := lc.WriteTo([]byte{0}, lc.LocalAddr()); err != nil {
		t.Fatalf("a cancelled start closed the running proxy's listener: %v", err)
	}
	networkAvailability.Lock()
	now := networkAvailability.transportGeneration
	networkAvailability.Unlock()
	if now != gen {
		t.Fatal("a cancelled start moved the path generation of the running proxy's streams")
	}
}

// A proxy over the other transport than the last one's starts the path's
// clocks over; one over the same keeps them.
func TestAnotherTransportStartsThePathClocksOver(t *testing.T) {
	prevTCP := activeOverTCP.Load()
	prevAt, prevGap := relayHeardAt.Load(), relayGapEndAt.Load()
	t.Cleanup(func() {
		activeOverTCP.Store(prevTCP)
		relayHeardAt.Store(prevAt)
		relayGapEndAt.Store(prevGap)
	})
	claimTransport(false)
	noteRelayHeard()
	relayGapEndAt.Store(relayHeardAt.Load())
	claimTransport(false)
	if sinceRelayHeard(time.Now()) == 0 && relayHeardAt.Load() == 0 {
		t.Fatal("a proxy over the same transport forgot when a relay was last heard")
	}
	claimTransport(true)
	if relayHeardAt.Load() != 0 || relayGapEndAt.Load() != 0 {
		t.Fatal("a proxy over TCP kept the UDP path's clocks")
	}
	if d := sinceRelayHeard(time.Now()); d != 0 {
		t.Fatalf("over a transport never heard, a relay was heard %v ago", d)
	}
}
