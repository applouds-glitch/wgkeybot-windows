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
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

const (
	orphanRelay1 = "10.0.0.1:3478"
	orphanRelay2 = "10.0.0.2:3478"
	orphanRelay3 = "10.0.0.3:3478"
)

var orphanRelays = []string{orphanRelay1, orphanRelay2, orphanRelay3}

func resetAllocationBook(t *testing.T) {
	t.Helper()
	reset := func() {
		allocationBook.Lock()
		allocationBook.live = map[relayIdentity]int{}
		allocationBook.tracked = map[*trackedRelay]bool{}
		allocationBook.orphanedTill = map[relayIdentity]time.Time{}
		allocationBook.orphans = map[relayIdentity]int{}
		allocationBook.markOf = map[relayIdentity]uint64{}
		allocationBook.announced = map[relayIdentity]bool{}
		allocationBook.releasedAt = map[relayIdentity]time.Time{}
		allocationBook.succeeded = map[string]bool{}
		allocationBook.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// countingConn stands in for a pion relay conn: only Close is ever called. Its
// Nth Close returns errs[N], nil past the end — pion returns the Refresh(0)
// write error from the first close and "already closed" from later ones.
type countingConn struct {
	net.PacketConn
	closes atomic.Int32
	errs   []error
}

func (c *countingConn) Close() error {
	n := int(c.closes.Add(1)) - 1
	if n < len(c.errs) {
		return c.errs[n]
	}
	return nil
}

var errReleaseUnsent = errors.New("write: network is unreachable")

func liveAllocations(user, relay string) int {
	allocationBook.Lock()
	defer allocationBook.Unlock()
	return allocationBook.live[relayIdentity{user: user, relay: relay}]
}

func orphanedTill(user, relay string) time.Time {
	allocationBook.Lock()
	defer allocationBook.Unlock()
	return allocationBook.orphanedTill[relayIdentity{user: user, relay: relay}]
}

// ghosts is how many of user's ghosts the mark on relay counts at now; 0 with
// no mark in force.
func ghosts(user, relay string, now time.Time) int {
	allocationBook.Lock()
	defer allocationBook.Unlock()
	key := relayIdentity{user: user, relay: relay}
	if till, ok := allocationBook.orphanedTill[key]; !ok || !now.Before(till) {
		return 0
	}
	return allocationBook.orphans[key]
}

// orphanOrder is addrs with the relays crowded with user's ghosts put last.
func orphanOrder(user string, addrs []string, now time.Time) []string {
	return behindCrowded(addrs, crowdedRelays(user, addrs, now))
}

// behindCrowded moves the crowded relays of order to its end, keeping the order
// within both parts; if all or none are crowded, nowhere is better to go and the
// order stands. It returns a new slice.
func behindCrowded(order []string, crowded map[string]bool) []string {
	var clean, full []string
	for _, addr := range order {
		if crowded[addr] {
			full = append(full, addr)
		} else {
			clean = append(clean, addr)
		}
	}
	if len(clean) == 0 || len(full) == 0 {
		return append([]string(nil), order...)
	}
	return append(clean, full...)
}

// loseOn tracks n live allocations of user's on relay and loses the network
// they were opened on: n ghosts there. Lost again by a later call, the ones
// already counted under the mark are not counted twice (countedLocked).
func loseOn(user, relay string, n int, now time.Time) {
	for i := 0; i < n; i++ {
		trackAllocation(&countingConn{}, user, relay)
	}
	orphanLiveAllocations(now)
}

// The network drops under two allocations on relay 1: two ghosts there. One on
// relay 2 closed while the network was alive is none — VK released that one.
// Two ghosts leave room under the quota, so the order stands.
func TestLosingTheNetworkOrphansOnlyLiveAllocations(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()

	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	trackAllocation(&countingConn{}, "alice", orphanRelay2).Close()

	orphanLiveAllocations(now)

	if n := ghosts("alice", orphanRelay1, now.Add(time.Second)); n != 2 {
		t.Fatalf("relay 1 holds %d ghost(s), want 2", n)
	}
	if n := ghosts("alice", orphanRelay2, now.Add(time.Second)); n != 0 {
		t.Fatalf("relay 2 holds %d ghost(s) of a released allocation", n)
	}
	if got := orphanOrder("alice", orphanRelays, now.Add(time.Second)); !slices.Equal(got, orphanRelays) {
		t.Fatalf("two ghosts steered the order: %v", got)
	}
}

// The device case: a session's allocations on relay 1, the network drops, the
// reconnect on the same credential goes to the relays not crowded with our
// ghosts — once they fill half the quota (orphanSteerAt).
func TestARelayCrowdedWithGhostsGoesLast(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	loseOn("alice", orphanRelay1, orphanSteerAt, now)

	got := orphanOrder("alice", orphanRelays, now.Add(time.Second))
	if want := []string{orphanRelay2, orphanRelay3, orphanRelay1}; !slices.Equal(got, want) {
		t.Fatalf("after the loss: %v, want %v", got, want)
	}
}

// The host's signals on Windows: the physical gateway lost (the availability
// flag going false) or exchanged for another (a network change). Each marks
// what is live at that moment; the polls that repeat "no network" do not
// extend the mark.
func TestHostSignalsOrphanOnTheTransitionOnly(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkAvailabilityForTest()
	t.Cleanup(resetNetworkAvailabilityForTest)

	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	setNetworkAvailable(false)
	first := orphanedTill("alice", orphanRelay1)
	if first.IsZero() {
		t.Fatal("losing the gateway did not orphan the live allocation")
	}
	time.Sleep(5 * time.Millisecond)
	setNetworkAvailable(false) // the tray polls the same state every 5s
	if got := orphanedTill("alice", orphanRelay1); !got.Equal(first) {
		t.Fatalf("a repeated offline poll extended the mark: %v -> %v", first, got)
	}
	if n := ghosts("alice", orphanRelay1, time.Now()); n != 1 {
		t.Fatalf("a repeated offline poll counted the allocation again: %d ghosts", n)
	}
	setNetworkAvailable(true)
	if got := orphanedTill("alice", orphanRelay1); !got.Equal(first) {
		t.Fatal("the network coming back changed the mark")
	}

	trackAllocation(&countingConn{}, "bob", orphanRelay2)
	NotifyNetworkChange()
	if orphanedTill("bob", orphanRelay2).IsZero() {
		t.Fatal("a gateway change did not orphan the live allocation")
	}
}

// The mark is the allocation lifetime, counted from the loss: still in force a
// second before it ends, gone at the end.
func TestOrphanMarkLastsTheAllocationLifetime(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	orphanLiveAllocations(now)

	if n := ghosts("alice", orphanRelay1, now.Add(orphanedAllocationLifetime-time.Second)); n != 1 {
		t.Fatalf("a second before the lifetime ends: %d ghosts, want the one", n)
	}
	if n := ghosts("alice", orphanRelay1, now.Add(orphanedAllocationLifetime)); n != 0 {
		t.Fatalf("at the end of the lifetime: %d ghosts, want none", n)
	}
}

// The quota is per credential: another credential still goes to relay 1 first.
func TestOrphanMarkIsPerCredential(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	loseOn("alice", orphanRelay1, orphanSteerAt, now)

	if got := orphanOrder("bob", orphanRelays, now); !slices.Equal(got, orphanRelays) {
		t.Fatalf("another credential was steered: %v", got)
	}
}

// When every relay is marked there is nowhere better to go; the order stands
// instead of being shuffled by the marks. The input is never modified.
func TestOrphanOrderWithEveryRelayMarked(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	for _, r := range orphanRelays {
		loseOn("alice", r, orphanSteerAt, now)
	}

	in := slices.Clone(orphanRelays)
	got := orphanOrder("alice", in, now)
	if !slices.Equal(got, orphanRelays) {
		t.Fatalf("all marked: %v, want the order unchanged", got)
	}
	got[0] = "mutated"
	if !slices.Equal(in, orphanRelays) {
		t.Fatal("the caller's slice was shared with the result")
	}
}

func TestOrphanOrderDoesNotModifyItsInput(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	loseOn("alice", orphanRelay1, orphanSteerAt, now)

	in := slices.Clone(orphanRelays)
	orphanOrder("alice", in, now)
	if !slices.Equal(in, orphanRelays) {
		t.Fatalf("input reordered in place: %v", in)
	}
}

// A relay conn is closed from several places; only the first close releases
// the count, so a double close cannot hide another live allocation on the pair.
func TestTrackedRelayReleasesOnce(t *testing.T) {
	resetAllocationBook(t)
	inner := &countingConn{}
	first := trackAllocation(inner, "alice", orphanRelay1)
	trackAllocation(&countingConn{}, "alice", orphanRelay1)

	first.Close()
	first.Close()
	if n := liveAllocations("alice", orphanRelay1); n != 1 {
		t.Fatalf("live after a double close of one of two: %d, want 1", n)
	}
	if inner.closes.Load() != 2 {
		t.Fatalf("inner conn closed %d times, want every Close passed through", inner.closes.Load())
	}

	now := time.Now()
	orphanLiveAllocations(now)
	if n := ghosts("alice", orphanRelay1, now); n != 1 {
		t.Fatalf("the remaining live allocation counted as %d ghosts, want 1", n)
	}
}

// The field order of events: the stack refuses a write, the session ends and
// closes its relay — the release fails to go out too — and only then does the
// host report the loss. Nothing is live by then, so the network trigger sees
// nothing; the failed release must have marked the pair on its own.
func TestAReleaseThatDidNotGoOutOrphans(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	trackAllocation(&countingConn{errs: []error{errReleaseUnsent}}, "alice", orphanRelay1).Close()
	trackAllocation(&countingConn{}, "alice", orphanRelay2).Close()
	orphanLiveAllocations(now)

	if n1, n2 := ghosts("alice", orphanRelay1, now), ghosts("alice", orphanRelay2, now); n1 != 1 || n2 != 0 {
		t.Fatalf("after a failed release on relay 1 and a sent one on relay 2: %d and %d ghosts, want 1 and 0", n1, n2)
	}
}

// Only the close that sent the release speaks for it: the "already closed"
// error of a later close says nothing about the relay.
func TestOnlyTheFirstCloseSpeaksForTheRelease(t *testing.T) {
	resetAllocationBook(t)
	r := trackAllocation(&countingConn{errs: []error{nil, errReleaseUnsent}}, "alice", orphanRelay1)
	r.Close()
	if err := r.Close(); err == nil {
		t.Fatal("the second close hid the inner conn's answer")
	}
	if n := ghosts("alice", orphanRelay1, time.Now()); n != 0 {
		t.Fatalf("a released allocation was counted by a later close: %d ghosts", n)
	}
}

// A mark lasts from the newest orphan: a second failed release later on
// extends it.
func TestALaterOrphanExtendsTheMark(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	trackAllocation(&countingConn{errs: []error{errReleaseUnsent}}, "alice", orphanRelay1).Close()
	later := now.Add(5 * time.Minute)
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, errReleaseUnsent, later, nil)

	if n := ghosts("alice", orphanRelay1, now.Add(orphanedAllocationLifetime+time.Minute)); n != 2 {
		t.Fatalf("the first orphan's expiry ended a mark the later one extended: %d ghosts, want both", n)
	}
}

// streamAttemptOrder is what both the attempt and the "did the head move"
// check in runWorker use, so it has to apply the marks on top of the stream's
// own order.
func TestStreamAttemptOrderAppliesTheMarks(t *testing.T) {
	resetAllocationBook(t)
	defer resetServerHealth()
	resetServerHealth()
	now := time.Now()
	head := assignRelays(orphanRelays, 0, now)[0]
	loseOn("alice", head, orphanSteerAt-1, now)

	if got := streamAttemptOrder("alice", orphanRelays, 0, now); got[0] != head {
		t.Fatalf("streamAttemptOrder = %v with %d ghosts on %s, want it kept first", got, orphanSteerAt-1, head)
	}
	loseOn("alice", head, 1, now)
	got := streamAttemptOrder("alice", orphanRelays, 0, now)
	if got[0] == head || got[len(got)-1] != head {
		t.Fatalf("streamAttemptOrder = %v with %d ghosts on %s, want it moved last", got, orphanSteerAt, head)
	}
}

// Android field runs 18.10: after a dark, a few ghosts on most relays sent
// every stream to the one relay left without any. The streams are spread over
// the relays that are not crowded — rotated among them, not before the crowded
// ones are put last, which would hand each crowded relay's streams to the next
// one.
func TestCrowdedRelaysAreSteeredAroundAndTheRestSpread(t *testing.T) {
	resetAllocationBook(t)
	defer resetServerHealth()
	resetServerHealth()
	now := time.Now()
	a, b, c, d, e, f := "10.0.1.1:3478", "10.0.1.2:3478", "10.0.1.3:3478", "10.0.1.4:3478", "10.0.1.5:3478", "10.0.1.6:3478"
	addrs := []string{a, b, c, d, e, f}
	for _, r := range []string{b, c, d} {
		loseOn("alice", r, orphanSteerAt, now)
	}
	loseOn("alice", e, 4, now) // as many as one relay held in those runs: still one to spread over

	var heads []string
	for id := 0; id < 8; id++ {
		got := streamAttemptOrder("alice", addrs, id, now)
		heads = append(heads, got[0])
		if tail := got[3:]; !slices.Contains(tail, b) || !slices.Contains(tail, c) || !slices.Contains(tail, d) {
			t.Fatalf("stream %d: %v, want the crowded relays behind the rest", id, got)
		}
	}
	if want := []string{a, e, f, a, e, f, a, e}; !slices.Equal(heads, want) {
		t.Fatalf("heads %v, want %v", heads, want)
	}
}

// One allocation is one ghost, whichever of its triggers speak for it: the
// network it was opened on lost (twice over), its release failed, and its
// relay no longer knew it. Two allocations lost in two outages are two.
func TestEachAllocationIsCountedOnceAsAGhost(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	r := trackAllocation(&countingConn{errs: []error{errReleaseUnsent}}, "alice", orphanRelay1)
	orphanLiveAllocations(now)
	orphanLiveAllocations(now)
	r.Close()
	noteOutOfReach("alice", orphanRelay1, trackedAllocation(r), now)
	if n := ghosts("alice", orphanRelay1, now); n != 1 {
		t.Fatalf("one allocation counted as %d ghosts", n)
	}

	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	orphanLiveAllocations(now.Add(time.Minute))
	if n := ghosts("alice", orphanRelay1, now.Add(time.Minute)); n != 2 {
		t.Fatalf("two allocations lost in two outages counted as %d ghosts", n)
	}
}

// A session's gateway goes, comes back with the session alive, and goes again:
// the ghost is held from the later loss, not dropped when the first one's mark
// runs out — and lost once more after that mark ran out too, it counts under
// the new one (Codex review of the Android port, 18.10).
func TestAnAllocationLostAgainIsHeldFromTheLaterLoss(t *testing.T) {
	resetAllocationBook(t)
	t0 := time.Now()
	r := trackAllocation(&countingConn{}, "alice", orphanRelay1)
	orphanLiveAllocations(t0)
	orphanLiveAllocations(t0.Add(500 * time.Second))
	if n := ghosts("alice", orphanRelay1, t0.Add(600*time.Second)); n != 1 {
		t.Fatalf("%d ghost(s) when the first loss's mark ran out, want the one, held from the second", n)
	}

	orphanLiveAllocations(t0.Add(1200 * time.Second))
	if n := ghosts("alice", orphanRelay1, t0.Add(1201*time.Second)); n != 1 {
		t.Fatalf("lost under a new mark: %d ghost(s), want it counted again", n)
	}
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, errReleaseUnsent, t0.Add(1210*time.Second), trackedAllocation(r))
	if n := ghosts("alice", orphanRelay1, t0.Add(1211*time.Second)); n != 1 {
		t.Fatalf("its failed release after that: %d ghost(s), want still one", n)
	}
}

func startOrphanTestServer(t *testing.T) (net.PacketConn, *turn.Server) {
	t.Helper()
	pc := listenFakeRelay(t)
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "orphan-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "orphan-test", "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return pc, server
}

// End to end through the real allocation path: a successful Allocate is
// counted until its relay conn is closed.
func TestDialAndAllocateCountsTheAllocation(t *testing.T) {
	resetAllocationBook(t)
	defer resetServerHealth()
	pc, _ := startOrphanTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addr := pc.LocalAddr().String()
	client, raw, relay, _, _, err := dialAndAllocate(ctx, &stream{}, "carol", "pass", addr, WorkerGroupConfig{UseUDP: true}, dialOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	defer client.Close()
	if n := liveAllocations("carol", addr); n != 1 {
		t.Fatalf("live after Allocate: %d, want 1", n)
	}
	relay.Close()
	if n := liveAllocations("carol", addr); n != 0 {
		t.Fatalf("live after closing the relay: %d, want 0", n)
	}
	if n := ghosts("carol", addr, time.Now()); n != 0 {
		t.Fatalf("a release sent to a live relay counted %d ghosts", n)
	}
}

// The real pion path of an unsent release: the socket under the client is gone
// when the relay closes, so Refresh(0) cannot be written and Close says so.
func TestDialAndAllocateMarksAnUnsentRelease(t *testing.T) {
	resetAllocationBook(t)
	defer resetServerHealth()
	pc, _ := startOrphanTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addr := pc.LocalAddr().String()
	client, raw, relay, _, _, err := dialAndAllocate(ctx, &stream{}, "dave", "pass", addr, WorkerGroupConfig{UseUDP: true}, dialOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	raw.Close()
	if relay.Close() == nil {
		t.Fatal("pion reported a release written to a closed socket as sent")
	}
	if n := ghosts("dave", addr, time.Now()); n != 1 {
		t.Fatalf("an unsent release counted %d ghosts, want 1", n)
	}
}

// The device case: a restart released ten allocations on relay 2 over a live
// network and dialed it again 0.6s later. Relay 1 still holds the ghosts of
// the drop before. The 486 is our own release still being processed, so the
// credential must be kept.
func TestA486RightAfterOurReleaseKeepsTheCreds(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	orphanLiveAllocations(now)
	trackAllocation(&countingConn{}, "alice", orphanRelay2).Close()

	attempt := []string{orphanRelay2, orphanRelay1}
	relay, age, ok := settlingQuotaError(quota486(), "alice", attempt, time.Now().Add(600*time.Millisecond))
	if !ok || relay != orphanRelay2 {
		t.Fatalf("486 0.6s after our release on relay 2: relay=%q ok=%v, want relay 2", relay, ok)
	}
	if age < 600*time.Millisecond || age >= releaseSettleWindow {
		t.Fatalf("release age %v, want about 0.6s", age)
	}
}

// Past the window a 486 is a 486 again: rotate the credential as always.
func TestReleaseSettleWindowEnds(t *testing.T) {
	resetAllocationBook(t)
	t0 := time.Now()
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, nil, t0, nil)

	if _, _, ok := settlingQuotaError(quota486(), "alice", orphanRelays, t0.Add(releaseSettleWindow-time.Millisecond)); !ok {
		t.Fatal("a 486 just inside the window was not read as our release settling")
	}
	if _, _, ok := settlingQuotaError(quota486(), "alice", orphanRelays, t0.Add(releaseSettleWindow)); ok {
		t.Fatal("a 486 at the end of the window still kept the credential")
	}
}

// Only a quota refusal is explained by an unprocessed release: a 401, a
// transport failure or no error at all take their usual paths.
func TestOnlyAQuotaRefusalSettles(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, nil, now, nil)

	for _, err := range []error{
		nil,
		allocateErr(turnErr(stun.CodeUnauthorized)),
		allocateErr(writeErr(50486, syscall.ENETUNREACH)),
	} {
		if _, _, ok := settlingQuotaError(err, "alice", orphanRelays, now); ok {
			t.Errorf("%v was read as our release settling", err)
		}
	}
}

// A relay holding our orphans answers 486 because of them, and they last ten
// minutes, not seconds: a release there does not make its 486 worth waiting for.
// A release that did not go out is no release at all.
func TestAnOrphanedRelayDoesNotSettle(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	trackAllocation(&countingConn{}, "alice", orphanRelay1).Close() // released, live network
	trackAllocation(&countingConn{}, "alice", orphanRelay1)         // then lost with it
	orphanLiveAllocations(now)
	trackAllocation(&countingConn{errs: []error{errReleaseUnsent}}, "alice", orphanRelay2).Close()

	if relay, _, ok := settlingQuotaError(quota486(), "alice", orphanRelays, time.Now()); ok {
		t.Fatalf("486 read as settling on %s, which holds our orphans", relay)
	}
}

// The release is ours on one credential and one relay: another credential's
// 486, or an attempt that never dialed that relay, is not explained by it.
func TestSettlingIsPerCredentialAndRelay(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, nil, now, nil)

	if _, _, ok := settlingQuotaError(quota486(), "bob", orphanRelays, now); ok {
		t.Fatal("another credential's 486 was read as alice's release settling")
	}
	if _, _, ok := settlingQuotaError(quota486(), "alice", []string{orphanRelay2, orphanRelay3}, now); ok {
		t.Fatal("an attempt that never dialed relay 1 was explained by a release there")
	}
}

// The same through runWorker itself: a relay refusing every Allocate with 486
// right after our release there gets the same credential again within seconds,
// and the credential is never rotated (the path that fetched a new one from VK).
func TestWorkerRetriesTheSameCredsWhileOurReleaseSettles(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	pc, _ := startInitialRefusalServer(t, 100, stun.CodeAllocQuotaReached)
	addr := pc.LocalAddr().String()

	prev := globalGetCreds
	globalGetCreds = func(context.Context, string, int) (string, string, []string, error) {
		return t.Name(), "pass", []string{addr}, nil
	}
	defer func() { globalGetCreds = prev }()

	const group = 91
	cacheID := group * streamsPerCredValue()
	cache := getStreamCache(cacheID)
	defer func() {
		credentialsStore.mu.Lock()
		delete(credentialsStore.caches, cacheID)
		credentialsStore.mu.Unlock()
	}()
	releaseAllocation(relayIdentity{user: t.Name(), relay: addr}, nil, time.Now(), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()
	runWorker(ctx, WorkerGroupConfig{GroupID: group, Link: "test", UseUDP: true, PeerType: "wireguard"}, &stream{}, 0)

	cache.refreshMu.Lock()
	rotated := !cache.lastRefresh.IsZero()
	cache.refreshMu.Unlock()
	if rotated {
		t.Fatal("a 486 right after our own release rotated the credential")
	}
	if n := pc.count(); n < 2 {
		t.Fatalf("%d Allocate attempt(s) in 3.5s, want the same credential tried again", n)
	}
}

// A session that ended because the relay no longer knows its socket leaves
// the allocation seated at the relay: the (credential, relay) is orphaned, the
// next attempts on that credential go to the other relays first, and the
// Refresh(0) its close sent — from the socket the relay does not know — does
// not read as a release settling.
func TestOutOfReachSessionOrphansItsRelay(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	probe := &deadStreamError{silent: time.Minute, probe: true, listened: 30 * time.Second}
	for _, c := range []struct {
		name string
		hole blackholeKind
		err  error
		want bool
	}{
		{"probe", noBlackhole, probe, true},
		{"wrapped", noBlackhole, fmt.Errorf("the relay connection is no longer read: %w", &deadStreamError{probe: true}), true},
		{"400", blackholeOutOfReach, errors.New("relay RX: read udp: use of closed network connection"), true},
		{"silent relay", blackholeRelay, errors.New("relay RX: read udp: use of closed network connection"), false},
		{"detector", noBlackhole, &deadStreamError{silent: 90 * time.Second}, false},
		{"transport", noBlackhole, errors.New("relay RX: read udp: use of closed network connection"), false},
		// The text of the old reading is no longer read at all.
		{"text", noBlackhole, errors.New("TURN blackhole: Failed to refresh permissions: CreatePermission error response (error 400: Bad Request)"), false},
		{"nil", noBlackhole, nil, false},
	} {
		if got := sessionOutOfReach(c.hole, c.err); got != c.want {
			t.Errorf("%s: out of reach %v, want %v", c.name, got, c.want)
		}
	}
	key := relayIdentity{user: "u", relay: orphanRelay1}
	releaseAllocation(key, nil, now, nil) // the close's Refresh(0) went out — on the new mapping
	noteOutOfReach("u", orphanRelay1, nil, now)
	if n := ghosts("u", orphanRelay1, now); n != 1 {
		t.Fatalf("an out-of-reach session left %d ghosts, want 1", n)
	}
	if _, _, settling := settlingQuotaError(quota486(), "u", []string{orphanRelay1}, now.Add(time.Second)); settling {
		t.Fatal("a 486 from a relay holding an out-of-reach allocation read as a release settling")
	}
}
