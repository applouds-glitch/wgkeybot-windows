/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */
package proxy

import (
	"slices"
	"sync"
	"time"
)

// The dark path, and the one worker at a time that dials it.
//
// When the path to the relays goes dark — Wi-Fi associated with nothing behind
// it, an uplink that stalls for minutes — every worker whose session dies in
// it redials into it: ten workers, each attempt racing its relays, streaks
// running up to 30s backoffs, and every Allocate that reached a relay while its
// answer could not come back a ghost on that relay, holding a seat of the
// credential's quota (orphaned_allocations.go) and a 486 in waiting. Android's
// periodic-download runs on 18.10 had the radio path dark for about two minutes
// at a time, three times an hour.
//
// So a dark, once found, holds until a relay is heard (relayHeardMark: anything
// read from a relay's socket), a stream hears its relay, a session's proof
// (notePathProven), another network, or a proxy start. It is found by an
// attempt of a worker's own that failed the dark's way (parksInTheDark) after
// darkEvidenceMin at least, no relay heard while it ran and no stream heard its
// relay for darkUpQuiet: its race had dialed its relays and none answered, nor
// anything else. An attempt that fails at once — the machine's own network
// refusing it — is no evidence of a dark, and joins one only if it is found.
// The least is one Allocate left unanswered to its deadline
// (allocateSilenceTimeout, 2s here); Android's 3s is under the 7.8s pion takes
// there, and here an attempt on one relay would never have reached it.
//
// While it holds, the workers that fail into it wait in line, and the one at
// its head dials it — the scout — no sooner than darkScoutPeriod after the last
// scout attempt began and darkScoutGap after it ended, its streak not growing.
// Then it goes to the back of the line: the turns pass through every parked
// worker, so a link whose relays are dead cannot keep the others' from being
// dialed. The first relay to answer ends the dark, but the waiting workers stay
// until the scout's attempt has had its say — a proof wakes them all, one at a
// time as always (awaitRevivalSlot); a flicker of light that does not carry the
// scout through leaves the dark found again by its verdict, and nobody else
// dialed into it. A scout that is not back with its credential within
// darkScoutLease loses its turn; once it dials, the turn is its own until the
// attempt has had its say. While the dark holds, the park's limit
// (pathDarkParkMax) no longer lets the others go: a relay set that has really
// died is still dialed, by the scouts.
//
// A dark belongs to one path: an attempt begun before a reset — another
// network, a proxy start — does not find it again on the path after
// (darkEpoch).
//
// A sleep is no dark (as on iOS, where the process freezes). An attempt that a
// sleep fell inside heard no relay because nothing ran, not because the path
// carried nothing: it finds no dark (hostFrozeSince), and a scout's verdict
// from such an attempt finds none either. Read as Android reads it, every
// wake from sleep would declare the path dark and park the very workers the
// wake needs. A sleep that the reporter's clock sees end resets the darks
// (silent_under_load.go, reporterTurn): what was dark before it says nothing
// about the path after, and the parked workers go at once, one at a time.
//
// Port of Android 8133eb44 (with ead7f1bc), one transport (UDP), with the iOS
// port's freeze protection on the WGH1 reporter's clock.

var (
	darkScoutGap    = 500 * time.Millisecond // from one scout attempt's end to the next; vars for the tests
	darkScoutPeriod = 6 * time.Second        // from one scout attempt's start to the next: an attempt refused at once does not loop
	darkScoutLease  = 20 * time.Second       // a scout not back by then has lost its turn
	darkEvidenceMin = allocateSilenceTimeout // an attempt shorter than this tells nothing about the path
	darkUpQuiet     = 30 * time.Second       // a stream that heard its relay this recently says the path is there
)

// darkPath is the state of the path.
type darkPath struct {
	found     bool
	since     time.Time
	mark      uint64 // relayHeardMark when found: a relay heard since ends it
	scout     *stream
	dialing   bool // the scout has dialed: its turn lasts until its verdict
	lastScout *stream
	leaseTill time.Time // the scout's turn ends then, until it dials
	nextScout time.Time
	waiting   []*stream // the parked workers, in the order of their turns
}

var darkPaths struct {
	sync.Mutex
	d     darkPath
	epoch uint64 // the path's number: every reset starts another
}

// darkEpoch is the number of the path the dark belongs to now; an attempt takes
// it as it begins.
func darkEpoch() uint64 {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	return darkPaths.epoch
}

// hostFrozeSince reports whether the process may have slept at some point since
// since: the WGH1 reporter, which turns every second for as long as the proxy
// runs, came in late after since, or is overdue now — a wake whose first turn
// has not come yet (silentUnderLoadClock).
func hostFrozeSince(since time.Time) bool {
	c := silentUnderLoadClock.Load()
	if c == nil {
		return false
	}
	return c.froze.After(since) || time.Since(c.turn) > time.Second+silentUnderLoadFreeze
}

// noteDarkPath records the path found dark, with no relay heard since mark, by
// an attempt that began at attemptStart on path epoch; a dark already found and
// still holding stays as it is. It reports whether the dark holds now — not for
// an attempt begun on another path, whose finding a reset since has made about
// a path that is gone: checked under the same lock as the reset (Codex review
// of the Android port, 19.10).
func noteDarkPath(mark, epoch uint64, attemptStart, now time.Time) bool {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	if epoch != darkPaths.epoch {
		return false
	}
	d := &darkPaths.d
	d.noteLocked(mark, attemptStart, now)
	return d.found
}

func (d *darkPath) noteLocked(mark uint64, attemptStart, now time.Time) {
	if d.holdsLocked() || relayHeardMark() != mark {
		return
	}
	// An attempt a sleep fell inside heard nothing because nothing ran.
	if hostFrozeSince(attemptStart) {
		return
	}
	d.found, d.since, d.mark = true, now, mark
	if next := scoutNext(attemptStart, now); next.After(d.nextScout) {
		d.nextScout = next
	}
	turnLog("[PATH] no relay heard — the path is dark: the workers that fail into it wait, and take turns dialing it alone")
}

// scoutNext is when the next scout attempt may begin after one that began at
// start and ended at end.
func scoutNext(start, end time.Time) time.Time {
	next := end.Add(darkScoutGap)
	if p := start.Add(darkScoutPeriod); p.After(next) {
		next = p
	}
	return next
}

// holdsLocked reports whether the dark is found and no relay heard since, and
// ends it once one is.
func (d *darkPath) holdsLocked() bool {
	if !d.found {
		return false
	}
	if relayHeardMark() == d.mark {
		return true
	}
	turnLog("[PATH] a relay heard after %v dark", time.Since(d.since).Round(100*time.Millisecond))
	d.found = false
	return false
}

// pathStillDark reports whether the dark holds.
func pathStillDark() bool {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	return darkPaths.d.holdsLocked()
}

// liveScoutLocked reports whether a scout holds its turn: dialing, or not yet
// past its lease.
func (d *darkPath) liveScoutLocked(now time.Time) bool {
	return d.scout != nil && (d.dialing || now.Before(d.leaseTill))
}

// darkReleases reports whether the parked workers may go: no dark holds, and
// no scout attempt is under way whose outcome is still to tell whether the
// light it saw is back for good.
func darkReleases(now time.Time) bool {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.d
	return !d.holdsLocked() && !d.liveScoutLocked(now)
}

// litPath ends the dark and any scout attempt's say in it: a session's proof,
// or a stream hearing its relay.
func litPath() {
	darkPaths.Lock()
	d := &darkPaths.d
	d.found, d.scout, d.dialing = false, nil, false
	darkPaths.Unlock()
}

// resetDarkPaths forgets the dark and starts another path: another network,
// another proxy, a wake from sleep. The parked workers see it on their next
// look and go, one at a time.
func resetDarkPaths() {
	darkPaths.Lock()
	darkPaths.d = darkPath{}
	darkPaths.epoch++
	darkPaths.Unlock()
}

// waitInTheDark puts s at the back of the line.
func waitInTheDark(s *stream) {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.d
	if !slices.Contains(d.waiting, s) {
		d.waiting = append(d.waiting, s)
	}
}

// stopWaitingInTheDark takes s out of the line.
func stopWaitingInTheDark(s *stream) {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.d
	d.waiting = slices.DeleteFunc(d.waiting, func(w *stream) bool { return w == s })
}

// leaveTheDark takes s out of the line, and its scout turn if it holds one: a
// worker that stops.
func leaveTheDark(s *stream) {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.d
	d.waiting = slices.DeleteFunc(d.waiting, func(w *stream) bool { return w == s })
	if d.scout == s {
		d.scout, d.dialing = nil, false
	}
}

// takeDarkScout gives s the next scout turn if the dark holds, s is at the head
// of the line, the turn is due and no scout holds a live one; changed reports a
// scout other than the last.
func takeDarkScout(s *stream, now time.Time) (taken, changed bool) {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.d
	if !d.holdsLocked() || now.Before(d.nextScout) || len(d.waiting) == 0 || d.waiting[0] != s {
		return false, false
	}
	if d.liveScoutLocked(now) {
		return false, false
	}
	d.waiting = d.waiting[1:]
	changed = d.lastScout != s
	d.scout, d.dialing, d.lastScout, d.leaseTill = s, false, s, now.Add(darkScoutLease)
	return true, changed
}

// darkScoutDials reports whether s, back from a scout turn with its credential,
// is to dial: it still holds the turn, which is then its own until its verdict
// (darkScoutDone) — or no dark holds and no other scout's turn is live. A
// scout back past its lease has lost the turn even if nobody has taken it yet.
func darkScoutDials(s *stream, now time.Time) bool {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.d
	if d.scout == s && (d.dialing || now.Before(d.leaseTill)) {
		d.dialing = true
		return true
	}
	return !d.holdsLocked() && !d.liveScoutLocked(now)
}

// darkScoutDone ends s's scout turn, if it dialed in it and still holds it, for
// an attempt that began at start: the next is due by scoutNext. dark is the
// scout's verdict: its attempt failed the dark's way and never got through, so
// whatever was heard while it dialed — a flicker of light — did not carry, and
// the dark is found again before anybody else is let into it; not from an
// attempt a sleep fell inside (noteLocked). A scout whose turn has passed — its
// lease run out before it dialed, a proof, a reset — has no say (Codex review
// of the Android port, 18.10).
func darkScoutDone(s *stream, start, now time.Time, dark bool) {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.d
	if d.scout != s || !d.dialing {
		return
	}
	if dark {
		d.noteLocked(relayHeardMark(), start, now)
	}
	d.scout, d.dialing = nil, false
	if next := scoutNext(start, now); next.After(d.nextScout) {
		d.nextScout = next
	}
}

// darkScouted reports whether a worker other than s holds a live scout turn.
func darkScouted(s *stream, now time.Time) bool {
	darkPaths.Lock()
	defer darkPaths.Unlock()
	d := &darkPaths.d
	return d.scout != s && d.liveScoutLocked(now)
}

// heardWithin reports whether a stream that is up has heard its relay within
// quiet.
func heardWithin(streams []*stream, now time.Time, quiet time.Duration) bool {
	for _, s := range streams {
		if !s.ready.Load() {
			continue
		}
		if a := s.activity.Load(); a != nil && a.heardAge(now) < quiet {
			return true
		}
	}
	return false
}

// findsTheDark reports, for a worker whose attempt has just failed the dark's
// way, whether the path is dark, and records it so; why says how it was told.
// The attempt began at start on path epoch, the count of relays heard standing
// at mark then; overTCP says what it dialed over, for the lookout of the TCP
// sockets (pathLooksDark).
func findsTheDark(overTCP bool, mark, epoch uint64, start time.Time, err error, now time.Time) (dark bool, why string) {
	set := activeStreamSet()
	switch {
	case heardWithin(set, now, pathDarkQuiet):
		litPath()
		return false, ""
	case overTCP && pathLooksDark(set, now):
		if !noteDarkPath(relayHeardMark(), epoch, start, now) {
			return false, ""
		}
		return true, "a socket stalled, no relay heard for " + pathDarkQuiet.String()
	case relayHeardMark() == mark && now.Sub(start) >= darkEvidenceMin &&
		!localNetworkError(err) && !heardWithin(set, now, darkUpQuiet):
		if !noteDarkPath(mark, epoch, start, now) {
			return false, ""
		}
		return true, "no relay heard while the attempt ran"
	case pathStillDark():
		return true, "no relay heard since it went dark"
	}
	return false, ""
}

// pathSilence is how long the path to the relays has been silent, when the
// streams know it to be — a dark found and holding, or over TCP the lookout's
// stalled sockets with no relay heard for pathDarkQuiet — counted from the
// relay last heard, or from when the dark was found if no relay ever answered;
// zero otherwise: a tunnel that is idle hears nothing for a while and is not
// silent. streams are the running proxy's, over TCP if overTCP.
//
// For the tray (Tunnel.PathSilence): in Android's dark spells of 18.10 the
// network stayed up for two minutes while nothing came over it, and the screen
// said "Connected" for the first 30s of each, then "Reconnecting…" — as if the
// tunnel were at fault, while it was the relays the network no longer reached.
func pathSilence(streams []*stream, overTCP bool, now time.Time) time.Duration {
	darkPaths.Lock()
	d := &darkPaths.d
	found := d.holdsLocked()
	since := d.since
	darkPaths.Unlock()
	if !found && !(overTCP && pathLooksDark(streams, now)) {
		return 0
	}
	if heard := sinceRelayHeard(now); heard > 0 {
		return heard
	}
	if found {
		return max(now.Sub(since), 0)
	}
	return 0
}
