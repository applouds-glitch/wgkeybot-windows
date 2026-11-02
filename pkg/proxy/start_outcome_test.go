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

func TestStartTimeoutCode(t *testing.T) {
	cases := []struct {
		name          string
		credsObtained bool
		vkHeard       bool
		allocated     bool
		want          int32
	}{
		// Android field log 12.10: no internet, every VK address reset before a byte came back.
		{"no creds, VK silent", false, false, false, startVKUnreachable},
		// VK answered (a captcha, an error_code): its refusal, not the network's.
		{"no creds, VK answered", false, true, false, -1},
		// Credentials in hand, relays silent: the relays' problem, not VK's.
		{"creds, VK silent", true, false, false, -1},
		{"creds, VK answered", true, true, false, -1},
		// Credentials, allocations granted, nothing carried through: the network
		// TCP to the relays is for — or a server that does not answer.
		{"creds, allocated, nothing carried", true, true, true, startRelaysCarryNothing},
		{"creds from the cache, allocated", true, false, true, startRelaysCarryNothing},
	}
	for _, c := range cases {
		if got := startTimeoutCode(c.credsObtained, c.vkHeard, c.allocated); got != c.want {
			t.Errorf("%s: startTimeoutCode = %d, want %d", c.name, got, c.want)
		}
	}
}

// vkConnsHeard moves once per connection that carried a byte back, and not at
// all for one that closed silent — the reset in front of VK.
func TestHeardConnCountsConnectionsThatAnswered(t *testing.T) {
	read := func(answer bool) {
		client, server := net.Pipe()
		conn := &heardConn{Conn: client, onSilent: func() {}}
		go func() {
			if answer {
				server.Write([]byte("hello"))
				server.Write([]byte("again"))
			}
			server.Close()
		}()
		buf := make([]byte, 2)
		for {
			if _, err := conn.Read(buf); err != nil {
				break
			}
		}
		conn.Close()
	}

	before := vkConnsHeard.Load()
	read(false)
	if got := vkConnsHeard.Load() - before; got != 0 {
		t.Fatalf("silent connection counted as heard: +%d", got)
	}
	read(true)
	if got := vkConnsHeard.Load() - before; got != 1 {
		t.Fatalf("answering connection read in several chunks: +%d, want +1", got)
	}
}

// StartProxy's -5 reaches Manager.Connect as its own status, not as the plain
// error the tray used to show as "TURN proxy failed (status -1)".
func TestWaitReadyNamesVKUnreachable(t *testing.T) {
	tun, b := tunnelWithBoot()
	b.result = startVKUnreachable
	close(b.ready)
	if got := tun.WaitReady(time.Second); got != ReadyStatusVKUnreachable {
		t.Fatalf("WaitReady = %v, want ReadyStatusVKUnreachable", got)
	}
	if status, started := tun.WaitStartedContext(context.Background(), time.Second); !started || status != ReadyStatusVKUnreachable {
		t.Fatalf("WaitStartedContext = %v, %v; want ReadyStatusVKUnreachable, started", status, started)
	}
}

// The wait's own deadline can come before StartProxy gives its code — it waits
// for every group's credential first — and then the evidence so far speaks: no
// credential and not a byte from VK is VKUnreachable there too (codex review of
// the iOS port, 2026-10-22).
func TestWaitReadyDeadlineNamesVKUnreachable(t *testing.T) {
	prev := currentStart.Load()
	t.Cleanup(func() { currentStart.Store(prev) })

	tun, _ := tunnelWithBoot() // StartProxy still in its prefetch
	e := beginStartEvidence()
	if got := tun.WaitReady(50 * time.Millisecond); got != ReadyStatusVKUnreachable {
		t.Fatalf("deadline with nothing from VK: %v, want ReadyStatusVKUnreachable", got)
	}
	e.creds.Store(true)
	if got := tun.WaitReady(50 * time.Millisecond); got != ReadyStatusError {
		t.Fatalf("deadline with a credential in hand: %v, want ReadyStatusError", got)
	}
	beginStartEvidence()
	vkConnsHeard.Add(1) // VK answered since the start began
	if got := tun.WaitReady(50 * time.Millisecond); got != ReadyStatusError {
		t.Fatalf("deadline with VK heard: %v, want ReadyStatusError", got)
	}
}

// StartProxy's -6 reaches Manager.Connect as its own status, for the tray to
// say what was seen and what may help.
func TestWaitReadyNamesRelaysThatCarryNothing(t *testing.T) {
	tun, b := tunnelWithBoot()
	b.result = startRelaysCarryNothing
	close(b.ready)
	if got := tun.WaitReady(time.Second); got != ReadyStatusRelaysCarryNothing {
		t.Fatalf("WaitReady = %v, want ReadyStatusRelaysCarryNothing", got)
	}
}

// A start whose window held a captcha or a sleep is no evidence that the
// relays carry nothing, whatever was allocated in it (Codex review of the
// Windows port, 2026-10-23).
func TestACaptchaOrASleepIsNoCaseOfRelaysCarryingNothing(t *testing.T) {
	prev := currentStart.Load()
	t.Cleanup(func() { currentStart.Store(prev) })
	withReporterClock(t, &reporterClock{turn: time.Now()})

	plain := beginStartEvidence()
	plain.noteAllocated()
	if !plain.relaysCarriedNothing() {
		t.Fatal("an allocation with nothing carried was not the case")
	}
	asked := beginStartEvidence()
	asked.noteAllocated()
	noteStartCaptcha()
	if asked.relaysCarriedNothing() {
		t.Fatal("a start that asked for a captcha was taken for relays carrying nothing")
	}
	slept := beginStartEvidence()
	slept.noteAllocated()
	// Windows can give two immediate time.Now calls the same timestamp. Make
	// the simulated freeze unambiguously later than this start.
	time.Sleep(2 * time.Millisecond)
	now := time.Now()
	withReporterClock(t, &reporterClock{turn: now, froze: now, before: slept.began.Add(-time.Minute)})
	if slept.relaysCarriedNothing() {
		t.Fatal("a start a sleep fell inside was taken for relays carrying nothing")
	}
}

// An allocation is booked on the start its dial belongs to, whichever start is
// running when the answer comes in: a dial of a stopped proxy answered after the
// next one began does not tell the next one the relays allocate (Codex review
// of the Windows port, 2026-10-23).
func TestAnAllocationIsBookedOnItsOwnStart(t *testing.T) {
	prev := currentStart.Load()
	t.Cleanup(func() { currentStart.Store(prev) })
	old := beginStartEvidence()
	cur := beginStartEvidence()

	relay := startTestRelay(t, listenFakeRelay(t), 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, raw, relayConn, _, _, err := dialAndAllocate(ctx, &stream{}, t.Name(), "pass", relay.addr,
		WorkerGroupConfig{UseUDP: true, start: old}, dialOpts{})
	if err != nil {
		t.Fatal(err)
	}
	relayConn.Close()
	client.Close()
	raw.Close()
	if !old.allocated.Load() || cur.allocated.Load() {
		t.Fatalf("allocated: the dial's own start %v, the one running %v; want true, false", old.allocated.Load(), cur.allocated.Load())
	}
	var none *startEvidence
	none.noteAllocated() // a dial outside a start
}
