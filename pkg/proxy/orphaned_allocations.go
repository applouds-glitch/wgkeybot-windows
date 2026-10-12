/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"math/rand"
	"net"
	"sync"
	"time"
)

// Allocations orphaned by a lost network.
//
// VK allows about ten simultaneous allocations per (credential, relay), and a
// session puts all of its streams on one relay, so the pair is full while the
// session lives. When the physical network the session's sockets are bound to
// goes away, none of them can send the Refresh(0) that would release their
// allocation: the relay keeps all of them for the allocation lifetime while
// nobody holds them. Every reconnect on the same credential then opened with a
// 486 from that relay on every stream before fanning out to the other one —
// seen on an Android device on 2026-09-18 after each Wi-Fi drop, ten 486s per
// recovery — and a second drop within ten minutes filled the other relay too,
// which cost a fresh credential from VK.
//
// Such a (credential, relay) is marked orphaned for the allocation lifetime,
// and attempts on that credential try its other relays first. Only the order
// changes — an orphaned relay stays in the list, last — so a mark can never make
// a working relay unreachable; if the others fail, the orphaned one is still
// dialed and answers for itself. Two events mark it, each covering what the
// other cannot see:
//
//   - a close whose Refresh(0) did not leave the socket. pion sends it once,
//     without waiting, and returns the write error from Close, so that error is
//     exactly "the release never went out". It is also the only trigger that
//     sees the streams that die first: one failed write ends a session, and on
//     a Wi-Fi drop the stack starts refusing writes before the host reports the
//     loss — the Android field log of 2026-09-18 has "network is unreachable"
//     ~100 ms ahead of the host's signal, with those allocations already closed;
//   - the network the sockets were opened on going away — on Windows the
//     physical default gateway lost or exchanged for another
//     (orphanLiveAllocations, from the host's signals) — for every allocation
//     still live at that moment. Their release may yet be "sent" into a link
//     that is gone without a write error (carrier lost, route not yet removed).
//
// A release that went out on a live network is not marked: VK frees those
// (confirmed on the device the same day). The book outlives the proxy session
// on purpose: credentials are kept across a stop and a reconnect (StopProxy),
// so the quota they hold on a relay is still theirs to trip over.

// orphanedAllocationLifetime is how long VK keeps an allocation whose client is
// gone: its lifetime, counted from its last refresh. When that refresh happened
// is not known here, so the whole lifetime is counted from the loss — a relay
// may be tried last a little longer than necessary, never tried first while
// provably full.
const orphanedAllocationLifetime = 600 * time.Second

// A release that did go out is not instant either. On the Android device on
// 2026-09-18 a restart closed ten fresh allocations on a live network, every
// Refresh(0) sent, and the first Allocate on the same credential and relay 0.6s
// later drew a 486; the same stop with a 6s pause before the start got all ten
// back. The worker read that 486 as a full credential: it force-expired it and
// fetched a new one from VK — the trip that can cost a captcha — to cure a
// quota that was seconds from freeing itself.
//
// So a 486 from a relay where one of our releases went out less than
// releaseSettleWindow ago retries the same credential after releaseSettleRetry,
// instead of rotating it. The window bounds the cost of a wrong guess: past it,
// a 486 takes the usual path.
const releaseSettleWindow = 10 * time.Second

// releaseSettleRetry is the pause before trying the same credential again: two
// or three tries fit before the 6s it took on the device, and a refusal costs
// the relay nothing.
func releaseSettleRetry() time.Duration {
	return 1500*time.Millisecond + time.Duration(rand.Intn(1001))*time.Millisecond
}

type relayIdentity struct {
	user  string // TURN username: one VK identity
	relay string // TURN server address
}

var allocationBook = struct {
	sync.Mutex
	live         map[relayIdentity]int
	orphanedTill map[relayIdentity]time.Time
	announced    map[relayIdentity]bool      // this mark has already been logged as steering a dial
	releasedAt   map[relayIdentity]time.Time // when our latest release there went out
}{
	live:         map[relayIdentity]int{},
	orphanedTill: map[relayIdentity]time.Time{},
	announced:    map[relayIdentity]bool{},
	releasedAt:   map[relayIdentity]time.Time{},
}

// trackedRelay counts one live allocation until it is closed. The relay conn is
// closed from several places (the session's defer, an early close that unblocks
// its reads, a losing failover candidate, a late answer allocateWithDeadline
// disposes of), sometimes at once; only the first close sends the release, so
// only its outcome counts, and the count is released exactly once.
type trackedRelay struct {
	net.PacketConn
	key    relayIdentity
	mu     sync.Mutex
	closed bool
}

func trackAllocation(relay net.PacketConn, user, addr string) net.PacketConn {
	key := relayIdentity{user: user, relay: addr}
	allocationBook.Lock()
	allocationBook.live[key]++
	allocationBook.Unlock()
	return &trackedRelay{PacketConn: relay, key: key}
}

func (r *trackedRelay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.PacketConn.Close() // pion: "already closed"
	}
	r.closed = true
	err := r.PacketConn.Close()
	releaseAllocation(r.key, err, time.Now())
	return err
}

// releaseAllocation drops one live allocation from the count; unreleased is the
// error of its Refresh(0) write, nil when the release went out.
func releaseAllocation(key relayIdentity, unreleased error, now time.Time) {
	allocationBook.Lock()
	if allocationBook.live[key]--; allocationBook.live[key] <= 0 {
		delete(allocationBook.live, key)
	}
	fresh := false
	if unreleased == nil {
		allocationBook.releasedAt[key] = now
	} else {
		fresh = orphanLocked(key, now)
	}
	allocationBook.Unlock()

	// One line per mark: a dying network fails all of a session's releases.
	if fresh {
		turnLog("[QUOTA] release of our allocation on %s did not go out (%v) — creds %s held there for %v, other relays go first",
			key.relay, unreleased, credsTag(key.user), orphanedAllocationLifetime)
	}
}

// orphanLocked marks key until its newest orphan expires and reports whether
// this starts a mark (none was in force). A mark that is only extended keeps
// its steering line already logged.
func orphanLocked(key relayIdentity, now time.Time) bool {
	till, marked := allocationBook.orphanedTill[key]
	fresh := !marked || !now.Before(till)
	allocationBook.orphanedTill[key] = now.Add(orphanedAllocationLifetime)
	if fresh {
		delete(allocationBook.announced, key)
	}
	return fresh
}

// orphanLiveAllocations marks every allocation still counted live: the network
// their sockets were opened on is gone, and they can no longer release
// themselves. Called on the host's transitions only — the physical gateway
// lost (setNetworkAvailable) or exchanged for another (NotifyNetworkChange) —
// never on the polls that repeat an unchanged state, so a mark is not extended
// on every offline tick.
func orphanLiveAllocations(now time.Time) {
	allocationBook.Lock()
	type orphaned struct {
		key   relayIdentity
		count int
	}
	var marked []orphaned
	for key, count := range allocationBook.live {
		orphanLocked(key, now)
		marked = append(marked, orphaned{key, count})
	}
	allocationBook.Unlock()

	// Durations, not clock times: a line stamped later cannot disagree with them.
	for _, m := range marked {
		turnLog("[QUOTA] the network is gone with %d allocation(s) on %s (creds %s) — orphaned for %v, other relays go first",
			m.count, m.key.relay, credsTag(m.key.user), orphanedAllocationLifetime)
	}
}

// attemptOrder is the server order for one attempt on user's credential: the
// session's order (assignServers — election, stand-downs, round-robin by
// stream), with relays still holding our orphaned allocations for this
// credential moved to the end. Callers comparing "where would the next attempt
// go" must use this too, not assignServers alone, or they see a different head
// than the attempt.
func attemptOrder(user string, addrs []string, streamID int, now time.Time) []string {
	return orderAroundOrphans(user, assignServers(addrs, streamID), now)
}

// orderAroundOrphans moves the relays holding orphaned allocations for user to
// the end, keeping the order within both parts. It returns a new slice.
func orderAroundOrphans(user string, addrs []string, now time.Time) []string {
	allocationBook.Lock()
	var clean, orphaned []string
	var orphanKeys []relayIdentity
	for _, addr := range addrs {
		key := relayIdentity{user: user, relay: addr}
		till, ok := allocationBook.orphanedTill[key]
		if ok && !now.Before(till) {
			delete(allocationBook.orphanedTill, key)
			delete(allocationBook.announced, key)
			ok = false
		}
		if ok {
			orphaned = append(orphaned, addr)
			orphanKeys = append(orphanKeys, key)
		} else {
			clean = append(clean, addr)
		}
	}
	if len(orphaned) == 0 || len(clean) == 0 {
		// Nothing to steer around, or nowhere else to go: the order stands.
		allocationBook.Unlock()
		return append([]string(nil), addrs...)
	}
	// One line per mark, not per worker: ten streams consult this at once.
	type steer struct {
		key  relayIdentity
		left time.Duration
	}
	var steered []steer
	for _, key := range orphanKeys {
		if !allocationBook.announced[key] {
			allocationBook.announced[key] = true
			steered = append(steered, steer{key, allocationBook.orphanedTill[key].Sub(now).Round(time.Second)})
		}
	}
	allocationBook.Unlock()

	for _, s := range steered {
		turnLog("[QUOTA] %s still holds our orphaned allocations for creds %s (%v left) — dialing %v first",
			s.key.relay, credsTag(s.key.user), s.left, clean)
	}
	return append(clean, orphaned...)
}

// settlingQuotaError reports whether err, the outcome of an attempt on user's
// credential over addrs, is a 486 that our own recent release explains: one of
// those relays — of the ones that answered 486, where the error says which did
// (quotaAnsweredBy): a release on one relay explains nothing about another's
// quota — saw a release of ours go out less than releaseSettleWindow ago and
// holds no orphans of ours. It names that relay and the release's age. An
// orphaned relay is left out on purpose: its 486 is our ghosts, which will not
// be gone in seconds.
func settlingQuotaError(err error, user string, addrs []string, now time.Time) (string, time.Duration, bool) {
	if err == nil || !isQuotaError(err) {
		return "", 0, false
	}
	answers := quotaAnsweredBy(err, addrs)
	allocationBook.Lock()
	defer allocationBook.Unlock()
	for _, answer := range answers {
		addr := answer.addr
		key := relayIdentity{user: user, relay: addr}
		at, ok := allocationBook.releasedAt[key]
		if !ok {
			continue
		}
		// Every worker of the group comes back with an attempt of its own, some
		// long after the 486 in it came in (a fallback can queue for an Allocate
		// slot behind a silent relay), so the first to ask must not take the
		// entry from the rest: it is judged by the 486's own time below, and
		// only swept here once it is as old as an orphan mark gets.
		if now.Sub(at) >= orphanedAllocationLifetime {
			delete(allocationBook.releasedAt, key)
			continue
		}
		// Judged at the moment the relay said 486, not when the attempt ended:
		// another relay's silence can hold the attempt open for seconds more,
		// and the window would run out on a 486 that was well inside it. A 486
		// from before the release is explained by it all the more.
		heard := answer.at
		if heard.IsZero() {
			heard = now
		}
		age := max(heard.Sub(at), 0)
		if age >= releaseSettleWindow {
			continue
		}
		if till, orphaned := allocationBook.orphanedTill[key]; orphaned && now.Before(till) {
			continue
		}
		return addr, age, true
	}
	return "", 0, false
}
