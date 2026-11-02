/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */
package proxy

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// freshDark starts a test with no dark and none left behind.
func freshDark(t *testing.T) {
	t.Helper()
	resetDarkPaths()
	t.Cleanup(resetDarkPaths)
}

// pinDarkScout sets the scout's timing for a test.
func pinDarkScout(t *testing.T, gap, period, evidence time.Duration) {
	t.Helper()
	prevGap, prevPeriod, prevEvidence := darkScoutGap, darkScoutPeriod, darkEvidenceMin
	darkScoutGap, darkScoutPeriod, darkEvidenceMin = gap, period, evidence
	t.Cleanup(func() { darkScoutGap, darkScoutPeriod, darkEvidenceMin = prevGap, prevPeriod, prevEvidence })
}

// withReporterClock makes c the WGH1 reporter's clock for a test.
func withReporterClock(t *testing.T, c *reporterClock) {
	t.Helper()
	prev := silentUnderLoadClock.Load()
	silentUnderLoadClock.Store(c)
	t.Cleanup(func() { silentUnderLoadClock.Store(prev) })
}

// awake is a reporter that has just turned, on time.
func awake(t *testing.T) { withReporterClock(t, &reporterClock{turn: time.Now()}) }

// A dark holds until a relay is heard; found against a mark that has moved
// since, it is no dark at all.
func TestADarkHoldsUntilARelayIsHeard(t *testing.T) {
	freshDark(t)
	awake(t)
	now := time.Now()
	noteDarkPath(relayHeardMark(), darkEpoch(), now, now)
	if !pathStillDark() {
		t.Fatal("a dark just found does not hold")
	}
	noteRelayHeard()
	if pathStillDark() {
		t.Fatal("a relay heard left the dark holding")
	}
	stale := relayHeardMark()
	noteRelayHeard()
	noteDarkPath(stale, darkEpoch(), now, now)
	if pathStillDark() {
		t.Fatal("a dark was found on evidence a relay heard since contradicts")
	}
}

// The turns pass down the line: each parked worker dials in its turn and goes
// to the back, a turn is due a period after the last began and a gap after it
// ended, and a scout that does not come back loses its turn to the next.
func TestScoutTurnsPassDownTheLine(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 100*time.Millisecond, time.Second, 0)
	a, b, c := &stream{id: 1}, &stream{id: 2}, &stream{id: 3}
	t0 := time.Now()
	for _, s := range []*stream{a, b, c} {
		waitInTheDark(s)
	}
	noteDarkPath(relayHeardMark(), darkEpoch(), t0, t0) // found by an attempt that began and failed at t0

	if taken, _ := takeDarkScout(a, t0.Add(500*time.Millisecond)); taken {
		t.Fatal("a turn was taken before a period had passed since the attempt that found the dark")
	}
	at := t0.Add(time.Second)
	if taken, _ := takeDarkScout(b, at); taken {
		t.Fatal("the second in line took the first's turn")
	}
	if taken, _ := takeDarkScout(a, at); !taken {
		t.Fatal("the head of the line did not get its turn when it was due")
	}
	if taken, _ := takeDarkScout(b, at.Add(5*time.Second)); taken {
		t.Fatal("the next turn was taken while the scout's was live")
	}
	if !darkScoutDials(a, at) {
		t.Fatal("the scout holding its turn was kept from dialing")
	}

	// a's attempt failed at once: its verdict keeps the dark, and the next turn
	// waits out a period from its start, not just a gap from its end.
	darkScoutDone(a, at, at, true)
	waitInTheDark(a)
	if taken, _ := takeDarkScout(b, at.Add(500*time.Millisecond)); taken {
		t.Fatal("an attempt refused at once was followed by the next within its period")
	}
	at = at.Add(time.Second)
	if taken, _ := takeDarkScout(b, at); !taken {
		t.Fatal("the next in line did not get its turn")
	}

	// b never comes back: after its lease c goes, and a after c.
	if taken, _ := takeDarkScout(c, at.Add(darkScoutLease-time.Second)); taken {
		t.Fatal("a turn passed on before the scout's lease had run out")
	}
	at = at.Add(darkScoutLease)
	if taken, _ := takeDarkScout(c, at); !taken {
		t.Fatal("a scout that never came back kept its turn past its lease")
	}
	if !darkScoutDials(c, at) {
		t.Fatal("the next scout was kept from dialing")
	}
	darkScoutDone(c, at, at.Add(7*time.Second), true)
	if taken, _ := takeDarkScout(a, at.Add(7*time.Second+darkScoutGap)); !taken {
		t.Fatal("the worker back in line did not get its next turn")
	}
}

// A scout's session that gets through ends its turn with the dark: a dark
// found again while that session still runs gets a scout of its own, not one
// kept waiting on the old scout's verdict, which comes only when its session
// ends (Codex review of the Windows port, 2026-10-23).
func TestAScoutWhoseSessionGetsThroughGivesUpItsTurn(t *testing.T) {
	freshDark(t)
	awake(t)
	pinDarkScout(t, 0, 0, 0)
	a, b := &stream{id: 1}, &stream{id: 2}
	waitInTheDark(a)
	waitInTheDark(b)
	now := time.Now()
	noteDarkPath(relayHeardMark(), darkEpoch(), now, now)
	if taken, _ := takeDarkScout(a, now); !taken || !darkScoutDials(a, now) {
		t.Fatal("the head of the line did not get to dial")
	}
	noteRelayHeard()
	a.notePathProven()

	now = now.Add(time.Minute)
	noteDarkPath(relayHeardMark(), darkEpoch(), now, now)
	if taken, _ := takeDarkScout(b, now); !taken {
		t.Fatal("a dark found while the proven scout's session ran waited on that scout")
	}
}

// A scout that is not back with its credential within its lease loses its
// turn — to the next in line, or to nobody — and has no say after: it does not
// dial beside the next scout, and its late verdict does not find the dark
// again (Codex review of the Android port, 18.10).
func TestAScoutWhoseTurnHasPassedHasNoSay(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 0, 0, 0)
	a, b := &stream{id: 1}, &stream{id: 2}
	now := time.Now()
	waitInTheDark(a)
	waitInTheDark(b)
	noteDarkPath(relayHeardMark(), darkEpoch(), now, now)
	if taken, _ := takeDarkScout(a, now); !taken {
		t.Fatal("no turn for a")
	}
	if taken, _ := takeDarkScout(b, now.Add(darkScoutLease-time.Second)); taken {
		t.Fatal("the turn passed on before the scout's lease had run out")
	}

	// a is not back by its lease: b takes the turn, and a stays out of it.
	later := now.Add(darkScoutLease)
	if taken, _ := takeDarkScout(b, later); !taken {
		t.Fatal("no turn for b after a's lease ran out")
	}
	if darkScoutDials(a, later) {
		t.Fatal("a former scout dialed beside the one holding the turn")
	}
	litPath()
	noteRelayHeard()
	darkScoutDone(a, now, later, true)
	if pathStillDark() {
		t.Fatal("the verdict of a scout whose turn had passed found the dark again")
	}
}

// A scout past its lease with nobody in line to take the turn has lost it all
// the same: back with its credential into a dark that holds, it does not dial;
// back once the light is, it dials as any worker would, and its verdict has no
// say in the dark.
func TestAScoutPastItsLeaseLosesTheTurnWithNobodyToTakeIt(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 0, 0, 0)
	a := &stream{id: 1}
	now := time.Now()
	waitInTheDark(a)
	noteDarkPath(relayHeardMark(), darkEpoch(), now, now)
	if taken, _ := takeDarkScout(a, now); !taken {
		t.Fatal("no turn for a")
	}
	later := now.Add(darkScoutLease + time.Second)
	if darkScoutDials(a, later) {
		t.Fatal("a scout back past its lease dialed the dark as the scout")
	}
	if darkScouted(&stream{id: 2}, later) {
		t.Fatal("the lost turn still read as live")
	}
	noteRelayHeard()
	if !darkScoutDials(a, later) {
		t.Fatal("a worker back once the light was kept from dialing")
	}
	darkScoutDone(a, now, later, true)
	if pathStillDark() {
		t.Fatal("the verdict of a scout that lost its turn found the dark again")
	}
}

// A scout that has dialed holds its turn until its verdict, however long its
// attempt runs: the lease bounds only the wait for its credential. Past it,
// with a relay heard meanwhile, the line still waits for the verdict, nobody
// takes the turn, and the park's limit does not let anybody go (Codex review of
// the Android port, 19.10).
func TestADialingScoutHoldsItsTurnPastItsLease(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 0, 0, 0)
	a, b := &stream{id: 1}, &stream{id: 2}
	now := time.Now()
	waitInTheDark(a)
	waitInTheDark(b)
	noteDarkPath(relayHeardMark(), darkEpoch(), now, now)
	if taken, _ := takeDarkScout(a, now); !taken {
		t.Fatal("no turn for a")
	}
	dialed := now.Add(15 * time.Second)
	if !darkScoutDials(a, dialed) {
		t.Fatal("the scout holding its turn was kept from dialing")
	}
	long := dialed.Add(2 * darkScoutLease)
	if taken, _ := takeDarkScout(b, long); taken {
		t.Fatal("the turn passed on while the scout was still dialing")
	}
	noteRelayHeard() // its Allocate answered, say
	if darkReleases(long) {
		t.Fatal("the line was let go before the dialing scout's verdict")
	}
	if !darkScouted(b, long) {
		t.Fatal("a dialing scout past its lease no longer kept the others parked")
	}
	darkScoutDone(a, dialed, long, true)
	if !pathStillDark() {
		t.Fatal("the verdict of the scout that held its turn did not find the dark again")
	}
	if taken, _ := takeDarkScout(b, long); !taken {
		t.Fatal("no turn for b after a's verdict")
	}
}

// A relay heard while a scout dials does not let the others go before the
// scout's attempt has had its say: a flicker of light that did not carry it
// through leaves the dark found again; one that did lets them go.
func TestTheOthersWaitForTheScoutsVerdict(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 0, 0, 0)
	scout, other := &stream{id: 1}, &stream{id: 2}
	now := time.Now()
	waitInTheDark(scout)
	waitInTheDark(other)
	noteDarkPath(relayHeardMark(), darkEpoch(), now, now)
	if taken, _ := takeDarkScout(scout, now); !taken {
		t.Fatal("no turn for the scout")
	}
	darkScoutDials(scout, now)

	noteRelayHeard() // its Allocate answered, say
	if darkReleases(now) {
		t.Fatal("the others were let go on a relay heard while the scout's attempt was still under way")
	}
	darkScoutDone(scout, now, now, true)
	if !pathStillDark() || darkReleases(now) {
		t.Fatal("a flicker that did not carry the scout through ended the dark")
	}

	waitInTheDark(scout)
	if taken, _ := takeDarkScout(other, now); !taken {
		t.Fatal("no turn for the next scout")
	}
	darkScoutDials(other, now)
	noteRelayHeard()
	darkScoutDone(other, now, now, false)
	if !darkReleases(now) {
		t.Fatal("the others were kept once the light carried the scout through")
	}
}

// lookout is a stream that is up and last heard its relay at heard (the zero
// time: never).
func lookout(heard time.Time) *stream {
	s := &stream{}
	s.ready.Store(true)
	if !heard.IsZero() {
		s.activity.Store(newStreamActivity(heard, 0))
	}
	return s
}

// What finds a dark, and what does not: an attempt that ran long enough with no
// relay heard and no stream hearing its relay finds one; an instant failure of
// the machine's own network, a relay heard while it ran, or a stream that heard
// its relay lately does not.
func TestWhatFindsTheDark(t *testing.T) {
	freshDark(t)
	awake(t)
	pinDarkScout(t, darkScoutGap, darkScoutPeriod, 3*time.Second)
	t.Cleanup(func() { activeStreams.Store(nil) })
	silent := fmt.Errorf("TURN allocate: %w within %v", errAllocateSilent, allocateSilenceTimeout)
	now := time.Now()
	long := now.Add(-4 * time.Second)

	for _, tc := range []struct {
		name    string
		start   time.Time
		err     error
		heard   bool // a relay heard while the attempt ran
		streams []*stream
		dark    bool
	}{
		{"a long silent attempt", long, silent, false, nil, true},
		{"one that failed at once", now, silent, false, nil, false},
		{"the machine's own network refusing it", long, opErr("sendto", netUnreachable), false, nil, false},
		{"a relay heard while it ran", long, silent, true, nil, false},
		{"a stream that heard its relay 10s ago", long, silent, false, []*stream{lookout(now.Add(-10 * time.Second))}, false},
		{"a stream silent for a minute", long, silent, false, []*stream{lookout(now.Add(-time.Minute))}, true},
	} {
		resetDarkPaths()
		set := tc.streams
		activeStreams.Store(&set)
		mark := relayHeardMark()
		if tc.heard {
			noteRelayHeard()
		}
		if dark, _ := findsTheDark(false, mark, darkEpoch(), tc.start, tc.err, now); dark != tc.dark {
			t.Errorf("%s: dark=%v, want %v", tc.name, dark, tc.dark)
		}
	}

	// Once found, an instant local failure joins it.
	resetDarkPaths()
	activeStreams.Store(nil)
	mark := relayHeardMark()
	noteDarkPath(mark, darkEpoch(), long, now)
	if dark, why := findsTheDark(false, mark, darkEpoch(), now, opErr("sendto", netUnreachable), now); !dark {
		t.Fatalf("an instant failure into a dark found did not join it (%s)", why)
	}
}

// A sleep is no dark: an attempt that a sleep fell inside — the reporter came
// in late after it began, or is overdue now, on a wake whose first turn has not
// come yet — heard nothing because nothing ran, and finds no dark; nor does a
// scout's verdict from such an attempt.
func TestASleepFindsNoDark(t *testing.T) {
	freshDark(t)
	t.Cleanup(func() { activeStreams.Store(nil) })
	activeStreams.Store(nil)
	now := time.Now()
	start := now.Add(-10 * time.Second)

	withReporterClock(t, &reporterClock{turn: now, froze: now.Add(-time.Second), before: now.Add(-5 * time.Minute)})
	if noteDarkPath(relayHeardMark(), darkEpoch(), start, now) {
		t.Fatal("an attempt a sleep ended inside of found the dark")
	}
	withReporterClock(t, &reporterClock{turn: now.Add(-5 * time.Minute)})
	if noteDarkPath(relayHeardMark(), darkEpoch(), start, now) {
		t.Fatal("an attempt that ended in a wake the reporter has not turned on yet found the dark")
	}

	// A scout's verdict from such an attempt finds none either.
	withReporterClock(t, &reporterClock{turn: now})
	scout := &stream{id: 1}
	waitInTheDark(scout)
	noteDarkPath(relayHeardMark(), darkEpoch(), start, start)
	if taken, _ := takeDarkScout(scout, now.Add(darkScoutPeriod)); !taken || !darkScoutDials(scout, now.Add(darkScoutPeriod)) {
		t.Fatal("no scout turn")
	}
	noteRelayHeard() // the light, in a flicker
	withReporterClock(t, &reporterClock{turn: now, froze: now, before: start})
	darkScoutDone(scout, start.Add(time.Second), now, true)
	if pathStillDark() {
		t.Fatal("a scout's verdict from an attempt a sleep fell inside found the dark")
	}

	// A sleep that ended before the attempt began excuses nothing.
	withReporterClock(t, &reporterClock{turn: now, froze: start.Add(-time.Minute), before: start.Add(-time.Hour)})
	if !noteDarkPath(relayHeardMark(), darkEpoch(), start, now) {
		t.Fatal("a sleep before the attempt kept it from finding the dark")
	}
}

// The reporter turning late — a wake from sleep — resets the dark: what was
// dark before says nothing about the path after, and the parked workers go.
func TestAWakeFromSleepResetsTheDark(t *testing.T) {
	freshDark(t)
	now := time.Now()
	clock := &reporterClock{turn: now}
	withReporterClock(t, clock)
	noteDarkPath(relayHeardMark(), darkEpoch(), now, now)
	epoch := darkEpoch()
	noteReporterTurn(clock.gen, now.Add(time.Second)) // on time
	if !pathStillDark() || darkEpoch() != epoch {
		t.Fatal("a turn on time reset the dark")
	}
	noteReporterTurn(clock.gen, now.Add(5*time.Minute)) // after a sleep
	if pathStillDark() || darkEpoch() == epoch {
		t.Fatal("a wake from sleep left the dark holding")
	}
}

// What ends a dark besides a relay: a stream heard while workers wait, another
// network, the network lost or back.
func TestADarkEndsWithTheStreamsHearingOrTheNetwork(t *testing.T) {
	freshDark(t)
	awake(t)
	resetAllocationBook(t)
	resetNetworkAvailabilityForTest()
	t.Cleanup(resetNetworkAvailabilityForTest)
	t.Cleanup(func() { activeStreams.Store(nil) })
	now := time.Now()
	noteDarkPath(relayHeardMark(), darkEpoch(), now, now)
	set := []*stream{lookout(now)}
	activeStreams.Store(&set)
	if dark, _ := findsTheDark(false, relayHeardMark(), darkEpoch(), now.Add(-time.Minute), errAllocateSilent, now); dark {
		t.Fatal("a stream hearing its relay left the dark holding")
	}
	if pathStillDark() {
		t.Fatal("the dark was not ended by the stream hearing")
	}
	activeStreams.Store(nil)

	noteDarkPath(relayHeardMark(), darkEpoch(), now, now)
	NotifyNetworkChange()
	if pathStillDark() {
		t.Fatal("another network left the dark holding")
	}
	noteDarkPath(relayHeardMark(), darkEpoch(), now, now)
	SetNetworkAvailable(false)
	if pathStillDark() {
		t.Fatal("the network lost left the dark holding")
	}
	noteDarkPath(relayHeardMark(), darkEpoch(), now, now)
	SetNetworkAvailable(true)
	if pathStillDark() {
		t.Fatal("the network back left the dark holding")
	}
}

// How long the path has been silent, for the tray: an idle tunnel that heard
// nothing for a while is not silent; a dark found is — since the relay last
// heard; a relay heard ends it.
func TestPathSilenceIsCountedOnlyWhenTheStreamsKnowIt(t *testing.T) {
	freshDark(t)
	awake(t)
	noteRelayHeard()
	heard := time.Now()
	later := heard.Add(40 * time.Second)
	if d := pathSilence(nil, false, later); d != 0 {
		t.Fatalf("an idle tunnel read as silent for %v", d)
	}
	noteDarkPath(relayHeardMark(), darkEpoch(), heard, heard)
	if d := pathSilence(nil, false, later); d < 39*time.Second || d > 41*time.Second {
		t.Fatalf("a dark found: silent %v, want about 40s", d)
	}
	noteRelayHeard()
	if d := pathSilence(nil, false, time.Now()); d != 0 {
		t.Fatalf("a relay heard left the path silent for %v", d)
	}
}

// With no relay ever heard, the silence counts from when the dark was found —
// not zero for as long as it lasts (Codex review of the Android port, 19.10).
func TestPathSilenceOverAPathNeverHeard(t *testing.T) {
	freshDark(t)
	awake(t)
	prev := relayHeardAt.Load()
	relayHeardAt.Store(0)
	t.Cleanup(func() { relayHeardAt.Store(prev) })

	found := time.Now()
	noteDarkPath(relayHeardMark(), darkEpoch(), found, found)
	if d := pathSilence(nil, false, found.Add(25*time.Second)); d < 24*time.Second || d > 26*time.Second {
		t.Fatalf("a dark over a path never heard: silent %v, want about 25s", d)
	}
}

// With no proxy running the tunnel reports no silence, whatever dark a proxy
// stopped or cancelled since left behind: the watchdog would hold for it with
// nobody left to dial (Codex review of the Windows port, 2026-10-23).
func TestNoProxyRunningReportsNoSilence(t *testing.T) {
	freshDark(t)
	awake(t)
	prev := activeStreams.Load()
	t.Cleanup(func() { activeStreams.Store(prev) })
	activeStreams.Store(nil)

	noteRelayHeard()
	heard := time.Now().Add(-time.Minute)
	noteDarkPath(relayHeardMark(), darkEpoch(), heard, heard)
	tunnel := &Tunnel{}
	if d := tunnel.PathSilence(); d != 0 {
		t.Fatalf("no proxy running, the tunnel read as silent for %v", d)
	}
	withdraw := publishStreams([]*stream{{id: 1}})
	defer withdraw()
	if d := tunnel.PathSilence(); d == 0 {
		t.Fatal("a proxy running over a dark read as not silent")
	}
}

// A dark found by an attempt begun on a path that a reset has since replaced is
// not recorded: the check is made under the reset's own lock (Codex review of
// the Android port, 19.10).
func TestAFindingFromBeforeAResetIsNotRecorded(t *testing.T) {
	freshDark(t)
	awake(t)
	t.Cleanup(func() { activeStreams.Store(nil) })
	activeStreams.Store(nil)
	epoch := darkEpoch()
	mark := relayHeardMark()
	now := time.Now()
	resetDarkPaths()
	if noteDarkPath(mark, epoch, now, now) {
		t.Fatal("a finding from the path before the reset was recorded")
	}
	if dark, _ := findsTheDark(false, mark, epoch, now.Add(-time.Minute), errAllocateSilent, now); dark {
		t.Fatal("an attempt from before the reset found the dark on the path after it")
	}
	if pathStillDark() {
		t.Fatal("a dark from the path before the reset holds on the one after")
	}
}

// Android's end-to-end case of UDP: an Allocate that no relay answered, with
// nothing heard meanwhile, finds the dark, and the worker parks.
func TestAnAllocateNobodyAnsweredFindsTheDark(t *testing.T) {
	freshDark(t)
	silent := listenFakeRelay(t)
	entered := waitsOf(t)
	runWorkersAgainst(t, 154, 1, []string{silent.LocalAddr().String()})
	select {
	case w := <-entered:
		if !w.parked {
			t.Fatalf("the wait after an Allocate nobody answered is %+v, want parked", w)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the worker never went into a wait")
	}
	if !pathStillDark() {
		t.Fatal("no dark found")
	}
}

// countingSocket counts the datagrams that reach a relay's socket, dark or not.
type countingSocket struct {
	net.PacketConn
	n atomic.Int32
}

func (c *countingSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.n.Add(1)
	}
	return n, addr, err
}

// End to end: three workers fail into a dark that stays. They wait, and they
// dial it one at a time, in turn — not all three over and over; the light back,
// the first to dial gets through and the others follow.
func TestWorkersWaitInTheDarkAndTakeTurnsDialingIt(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 50*time.Millisecond, 600*time.Millisecond, 0)
	resetRevivalPacing()
	counted := &countingSocket{PacketConn: listenFakeRelay(t)}
	sock := &darkSocket{PacketConn: counted}
	relay := startTestRelay(t, sock, 0)
	var mu sync.Mutex
	var parks []int
	prev := workerWaits
	workerWaits = func(w workerWait) {
		if w.parked {
			mu.Lock()
			parks = append(parks, w.stream)
			mu.Unlock()
		}
	}
	t.Cleanup(func() { workerWaits = prev })
	h := runWorkersAgainst(t, 157, 3, []string{relay.addr})
	waitFor(t, "three streams up", 10*time.Second, func() bool { return h.ready() == 3 })

	sock.dark.Store(true)
	began := time.Now()
	for _, s := range h.streams {
		recycleAttempt(s.attempt.Load())
	}
	// Every worker takes its turn: each comes back from one and parks again.
	turns := map[int]int{}
	waitFor(t, "every worker's turn", 20*time.Second, func() bool {
		mu.Lock()
		seen := append([]int(nil), parks...)
		mu.Unlock()
		clear(turns)
		if len(seen) > 3 {
			for _, id := range seen[3:] {
				turns[id]++
			}
		}
		return len(turns) == 3
	})
	elapsed := time.Since(began)
	t.Logf("turns %v in %v; %d datagrams into the dark", turns, elapsed.Round(time.Millisecond), counted.n.Load())

	sock.dark.Store(false)
	back := time.Now()
	waitFor(t, "the three back", 3*darkScoutPeriod+10*time.Second, func() bool { return h.ready() == 3 })
	t.Logf("all three back %v after the light", time.Since(back).Round(time.Millisecond))
}
