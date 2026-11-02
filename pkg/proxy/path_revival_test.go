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
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// What the dark leaves behind and what a relay says: only the first is cured by
// a session getting through afterwards. The errnos are this platform's own.
func TestPathWideFailuresAreToldFromTheRelaysAnswers(t *testing.T) {
	allocateSilence := fmt.Errorf("TURN allocate: %w", fmt.Errorf("%w %s", errors.New(pionAllRetransmissionsFailed), "dHJhbnNhY3Rpb24="))
	allocateDeadline := fmt.Errorf("TURN allocate: %w within %v", errAllocateSilent, allocateSilenceTimeout)
	readTimeout := fmt.Errorf("relay RX: %w", &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded})
	refused := fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeForbidden))

	for name, err := range map[string]error{
		"Allocate past our deadline": allocateDeadline,
		"Allocate unanswered":        allocateSilence,
		"Allocate retransmit unsent": fmt.Errorf("TURN allocate: %w", fmt.Errorf("%w %s", errors.New(pionFailedToRetransmit), "key")),
		"a read past its deadline":   readTimeout,
		"relay proof unanswered":     fmt.Errorf("%w: %w", errDataPlaneHandshake, fmt.Errorf("%w in %v", errRelayNeverAnswered, relayProofTimeout)),
		"DTLS handshake unanswered":  fmt.Errorf("%w: DTLS handshake failed: %w", errDataPlaneHandshake, context.DeadlineExceeded),
		"session gone deaf":          &deadStreamError{silent: 90 * time.Second},
		"reset":                      fmt.Errorf("relay RX: %w", opErr("recvfrom", relayResetErrnos[0])),
		"no route":                   fmt.Errorf("TURN allocate: %w", opErr("sendto", netUnreachable)),
		"both relays silent":         newRaceError([]relayAttemptError{{err: allocateSilence}, {err: allocateDeadline}}),
	} {
		if !pathWideFailure(err) {
			t.Errorf("%s (%v): not read as the dark's doing", name, err)
		}
	}

	for name, err := range map[string]error{
		"none":                       nil,
		"quota":                      fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeAllocQuotaReached)),
		"credential":                 fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeUnauthorized)),
		"allocation mismatch":        fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeAllocMismatch)),
		"forbidden":                  refused,
		"refused":                    fmt.Errorf("relay RX: %w", opErr("recvfrom", relayRefusedErrnos[0])),
		"flow closed by the relay":   fmt.Errorf("the relay connection is no longer read: %w", io.EOF),
		"blackhole":                  fmt.Errorf("TURN blackhole: %s", "allocation refresh failed"),
		"DTLS handshake refused":     fmt.Errorf("%w: DTLS handshake failed: %w", errDataPlaneHandshake, errors.New("alert: bad certificate")),
		"sentinel's text alone":      errors.New("all retransmissions failed for 10.0.0.1"),
		"one silent, one answering":  newRaceError([]relayAttemptError{{err: refused}, {err: allocateDeadline}}),
		"one answering 486":          newRaceError([]relayAttemptError{{err: allocateDeadline}, {err: fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeAllocQuotaReached))}}),
		"something not known at all": errors.New("TURN listen: something else"),
	} {
		if pathWideFailure(err) {
			t.Errorf("%s (%v): read as the dark's doing", name, err)
		}
	}
}

// A proof wakes every wait: the channel a worker holds is closed by the next
// proof, and the next worker to ask gets a fresh one. Each proof is booked on
// the stream that made it.
func TestAProofClosesTheWaits(t *testing.T) {
	wait := nextPathProof()
	if nextPathProof() != wait {
		t.Fatal("two workers asking before any proof were given different waits")
	}
	s := &stream{}
	s.flowFails.Store(&flowFailRun{relay: "relay-a:3478", n: flowFailsBeforeAvoid})
	s.notePathProven()
	if !closed(wait) {
		t.Fatal("a proof did not end the wait")
	}
	if closed(nextPathProof()) {
		t.Fatal("the wait handed out after a proof is already over")
	}
	if s.pathProofs.Load() != 1 {
		t.Fatalf("the stream booked %d proofs, want 1", s.pathProofs.Load())
	}
	if s.avoidedRelay() != "" {
		t.Fatal("a session of its own did not end the stream's run of flow failures")
	}
}

func pinRevivalGap(t *testing.T, d time.Duration) {
	t.Helper()
	prev := revivalGap
	revivalGap = func() time.Duration { return d }
	resetRevivalPacing()
	t.Cleanup(func() {
		revivalGap = prev
		resetRevivalPacing()
	})
}

func resetRevivalPacing() {
	revivalPacing.Lock()
	revivalPacing.next = time.Time{}
	revivalPacing.Unlock()
}

// Woken together, gone one at a time: the first at once, the rest a gap apart.
// A worker whose own delay ends first goes then, and holds nobody up; one whose
// attempt ends meanwhile does not go at all.
func TestWokenWorkersReconnectOneAtATime(t *testing.T) {
	const gap = 150 * time.Millisecond
	pinRevivalGap(t, gap)

	start := time.Now()
	far := start.Add(time.Minute)
	var mu sync.Mutex
	var went []time.Duration
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !awaitRevivalSlot(context.Background(), far) {
				t.Error("a waiter with a live context was turned away")
			}
			mu.Lock()
			went = append(went, time.Since(start))
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(went, func(i, j int) bool { return went[i] < went[j] })
	if went[0] > 50*time.Millisecond {
		t.Fatalf("the first woken worker waited %v", went[0])
	}
	for i := 1; i < len(went); i++ {
		if d := went[i] - went[i-1]; d < gap-30*time.Millisecond {
			t.Fatalf("woken workers went %v apart (%v), want at least %v", d, went, gap)
		}
	}

	// The next slot is a gap away; a worker whose delay runs out sooner goes at
	// its own time and takes no slot.
	revivalPacing.Lock()
	next := time.Now().Add(gap)
	revivalPacing.next = next
	revivalPacing.Unlock()
	soon := time.Now().Add(gap / 3)
	if !awaitRevivalSlot(context.Background(), soon) {
		t.Fatal("a worker reaching its own deadline was turned away")
	}
	if late := time.Since(soon); late < 0 || late > 40*time.Millisecond {
		t.Fatalf("a worker whose delay ran out went %v after it", late)
	}
	revivalPacing.Lock()
	taken := !revivalPacing.next.Equal(next)
	revivalPacing.Unlock()
	if taken {
		t.Fatal("a worker that went at its own deadline took a slot")
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	if awaitRevivalSlot(ctx, far) {
		t.Fatal("a worker whose attempt ended was still let go")
	}
}

// darkSocket is a relay's socket that, while dark, takes in whatever comes and
// hands none of it to the TURN server reading it: the path to the relay gone
// while the network stays up.
type darkSocket struct {
	net.PacketConn
	dark atomic.Bool
}

func (c *darkSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil || !c.dark.Load() {
			return n, addr, err
		}
	}
}

// waitsOf reports every wait a worker goes into, through the seam runWorker
// calls as it enters one.
func waitsOf(t *testing.T) <-chan workerWait {
	t.Helper()
	entered := make(chan workerWait, 64)
	prev := workerWaits
	workerWaits = func(w workerWait) {
		select {
		case entered <- w:
		default:
		}
	}
	t.Cleanup(func() { workerWaits = prev })
	return entered
}

// awaitLongWait returns the first wait of stream id at least min long.
func awaitLongWait(t *testing.T, entered <-chan workerWait, id int, min time.Duration) workerWait {
	t.Helper()
	timeout := time.After(30 * time.Second)
	for {
		select {
		case w := <-entered:
			if w.stream == id && w.delay >= min {
				return w
			}
		case <-timeout:
			t.Fatal("the worker never went into a long wait: the test staged nothing")
			return workerWait{}
		}
	}
}

// startSibling runs one more worker of the group, on stream id.
func startSibling(t *testing.T, group, id int, peer *net.UDPAddr) *stream {
	t.Helper()
	s, _ := newNoDTLSTestStream(t)
	s.id = id
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWorker(ctx, WorkerGroupConfig{GroupID: group, Link: "test", UseUDP: benchUseUDP(), PeerType: "wireguard", PeerAddr: peer}, s, 0)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return s
}

// The field case of Android's 17.10 log, over UDP: the path went dark, a
// worker's redials went into it and it backed off for 7-17s; the path came
// back, and it slept on next to it. Once another stream's session gets through,
// it has to be back within a second or two, not at the end of its delay.
func TestASiblingGettingThroughWakesAWorkerBackingOffFromTheDark(t *testing.T) {
	resetRevivalPacing()
	// The backoff's wake, not the park's: here an Allocate unanswered finds the
	// dark at once (darkEvidenceMin), and a parked worker is let go by the
	// light instead (TestWorkersWaitInTheDarkAndTakeTurnsDialingIt). Codex
	// review of the Windows port, 2026-10-23.
	freshDark(t)
	pinDarkScout(t, darkScoutGap, darkScoutPeriod, time.Hour)
	sock := &darkSocket{PacketConn: listenFakeRelay(t)}
	sock.dark.Store(true)
	relay := startTestRelay(t, sock, 0)
	entered := waitsOf(t)
	answer := make(chan struct{})
	close(answer)
	peer := fakeRelay(t, answer)
	h := runWorkersAgainstPeer(t, 141, 1, []string{relay.addr}, peer)

	// Two Allocates into the dark: the second wait is reconnectDelay(2), 7-17s.
	w := awaitLongWait(t, entered, 0, 5*time.Second)
	if w.parked || w.delay > 20*time.Second {
		t.Fatalf("the wait after Allocates unanswered: parked %v for %v, want the backoff of 7-17s", w.parked, w.delay)
	}
	if !w.revivable {
		t.Fatal("the wait after Allocates unanswered cannot be woken")
	}
	slept := time.Now()

	// The path is back, and nothing says so yet: the worker sleeps on.
	sock.dark.Store(false)
	time.Sleep(time.Second)
	if h.ready() != 0 {
		t.Fatal("the worker came back before any session got through")
	}

	sibling := startSibling(t, 141, 1, peer)
	waitFor(t, "the sibling's session", 5*time.Second, sibling.ready.Load)
	through := time.Now()
	waitFor(t, "the sleeping worker back", 4*time.Second, func() bool { return h.ready() == 1 })
	t.Logf("back %v after the sibling got through, %v into a wait of %v", time.Since(through).Round(time.Millisecond),
		time.Since(slept).Round(time.Millisecond), w.delay.Round(time.Millisecond))
	if took := time.Since(slept); took >= w.delay {
		t.Fatalf("back %v into a wait of %v: it was sat out", took, w.delay)
	}
}

// What a session getting through must not end: a relay's answer, and above all
// the cooldown after a 486 on a credential that is still current — the quota is
// the credential's on the relay, and the path coming back frees none of it.
func TestASiblingGettingThroughDoesNotCutARelaysAnswer(t *testing.T) {
	t.Run("486 on the current credential", func(t *testing.T) {
		resetAllocationBook(t)
		resetNetworkAvailabilityForTest()
		defer resetNetworkAvailabilityForTest()
		resetServerHealth()
		const group = 144
		dropCredSlot(t, group)
		refuser, _ := startInitialRefusalServer(t, 1000, stun.CodeAllocQuotaReached)
		addr := refuser.LocalAddr().String()
		// Just rotated: the 486 cannot rotate again, so the worker takes the
		// long cooldown.
		cache := getStreamCache(group * streamsPerCredValue())
		cache.refreshMu.Lock()
		cache.lastRefresh = time.Now()
		cache.refreshMu.Unlock()

		entered := waitsOf(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := runWorkerAgainst(t, ctx, group, addr, func(context.Context, string) (string, string, []string, int, error) {
			return t.Name(), "pass", []string{addr}, 0, nil
		})
		defer func() {
			cancel()
			<-done
		}()
		w := <-entered
		if w.revivable {
			t.Fatal("the quota cooldown can be woken")
		}
		dials := refuser.count()
		(&stream{}).notePathProven()
		time.Sleep(2 * time.Second)
		if n := refuser.count() - dials; n != 0 {
			t.Fatalf("%d dial(s) within 2s of another stream's session getting through: the quota cooldown was cut short", n)
		}
	})

	t.Run("refused", func(t *testing.T) {
		refuser, _ := startInitialRefusalServer(t, 1000, stun.CodeForbidden)
		entered := waitsOf(t)
		runWorkersAgainst(t, 145, 1, []string{refuser.LocalAddr().String()})
		w := awaitLongWait(t, entered, 0, 5*time.Second)
		if w.revivable {
			t.Fatal("the wait after a refusal can be woken")
		}
		dials := refuser.count()
		(&stream{}).notePathProven()
		time.Sleep(2 * time.Second)
		if n := refuser.count() - dials; n != 0 {
			t.Fatalf("%d dial(s) within 2s of another stream's session getting through: a refusal's delay was cut short", n)
		}
	})
}

// Who is parked while the path is dark: a failure of the dark's — silence, a
// flow the system gave up, a write the machine's own stack refused — and not a
// reset, which is the relay's packet reaching us, nor any answer.
func TestWhoIsParkedWhileThePathIsDark(t *testing.T) {
	reset, pipe := relayResetErrnos[0], relayResetErrnos[len(relayResetErrnos)-1]
	giveUp := fmt.Errorf("%w: no progress for %v: %w", errRelayFlowTimedOut, relayTCPUserTimeout, opErr("write", pipe))
	silence := fmt.Errorf("TURN TCP dial: %w", opErr("connect", relayTimedOutErrnos[0]))
	for name, err := range map[string]error{
		"connect timed out":           fmt.Errorf("TURN TCP dial: %w", &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}),
		"Allocate unanswered":         fmt.Errorf("TURN allocate: %w", fmt.Errorf("%w within %v", errAllocateSilent, allocateSilenceTimeout)),
		"given up by the system":      giveUp,
		"write refused by the stack":  fmt.Errorf("relay TX: %w", opErr("write", localNetworkErrnos[0])),
		"relay proof unanswered":      fmt.Errorf("%w: %w", errDataPlaneHandshake, fmt.Errorf("%w in %v", errRelayNeverAnswered, relayProofTimeoutTCP)),
		"session deaf to the relay":   &deadStreamError{silent: 90 * time.Second},
		"two relays silent in a race": newRaceError([]relayAttemptError{{err: giveUp}, {err: silence}}),
	} {
		if !parksInTheDark(err) {
			t.Errorf("%s (%v): not parked", name, err)
		}
	}
	resetErr := fmt.Errorf("TURN TCP dial: %w", opErr("read", reset))
	for name, err := range map[string]error{
		"reset by the relay":    fmt.Errorf("the relay connection is no longer read: %w", opErr("read", reset)),
		"written after a reset": fmt.Errorf("relay TX: %w", opErr("write", pipe)),
		// Whichever came in last: the race's chain carries only its spokesman.
		"a reset, then a silence, in a race": newRaceError([]relayAttemptError{{err: resetErr}, {err: silence}}),
		"a silence, then a reset, in a race": newRaceError([]relayAttemptError{{err: silence}, {err: resetErr}}),
		"quota":                              fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeAllocQuotaReached)),
		"refused":                            fmt.Errorf("TURN allocate: %w", turnErr(stun.CodeForbidden)),
		"none":                               nil,
	} {
		if parksInTheDark(err) {
			t.Errorf("%s (%v): parked", name, err)
		}
	}
}

// tcpLookout is a stream that is up, as the lookout of the TCP sockets reads it.
func tcpLookout(overTCP, stalled bool, heard time.Time) *stream {
	s := &stream{}
	s.ready.Store(true)
	s.overTCP.Store(overTCP)
	s.sendStalled.Store(stalled)
	if !heard.IsZero() {
		s.activity.Store(newStreamActivity(heard, 0))
	}
	return s
}

// What the streams that are up have to say for the path to be dark: a socket
// stalled, and nobody hearing.
func TestWhenThePathLooksDark(t *testing.T) {
	now := time.Now()
	silent := now.Add(-pathDarkQuiet - time.Second)
	heard := now.Add(-pathDarkQuiet / 2)
	down := tcpLookout(true, true, silent)
	down.ready.Store(false)

	for name, tc := range map[string]struct {
		streams []*stream
		dark    bool
	}{
		"nobody up":                    {nil, false},
		"stalled, silent":              {[]*stream{tcpLookout(true, true, silent)}, true},
		"stalled, no clock yet":        {[]*stream{tcpLookout(true, true, time.Time{})}, true},
		"stalled, still hearing":       {[]*stream{tcpLookout(true, true, heard)}, false},
		"stalled beside a quiet one":   {[]*stream{tcpLookout(true, true, silent), tcpLookout(true, false, silent)}, true},
		"stalled beside a hearing one": {[]*stream{tcpLookout(true, true, silent), tcpLookout(true, false, heard)}, false},
		"quiet, nothing stalled":       {[]*stream{tcpLookout(true, false, silent), tcpLookout(true, false, silent)}, false},
		"UDP quiet":                    {[]*stream{tcpLookout(false, false, silent)}, false},
		"the stalled one is down":      {[]*stream{down, tcpLookout(true, false, silent)}, false},
		"the hearing one is down, too": {[]*stream{tcpLookout(true, true, silent), func() *stream { s := tcpLookout(true, false, heard); s.ready.Store(false); return s }()}, true},
		"a stall mark over UDP":        {[]*stream{tcpLookout(false, true, silent)}, false},
	} {
		if got := pathLooksDark(tc.streams, now); got != tc.dark {
			t.Errorf("%s: dark=%v, want %v", name, got, tc.dark)
		}
	}
}

// relayDials stages the TCP connects to the relays: while dark, every connect
// times out; tried counts them all.
type relayDials struct {
	dark  atomic.Bool
	tried atomic.Int32
}

func stageRelayDials(t *testing.T) *relayDials {
	t.Helper()
	dials := &relayDials{}
	prev := dialRelayTCP
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, to string) (net.Conn, error) {
		dials.tried.Add(1)
		if dials.dark.Load() {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
		}
		return prev(ctx, d, to)
	}
	t.Cleanup(func() { dialRelayTCP = prev })
	return dials
}

// publishLookout makes the proxy's stream set the worker's streams and a
// lookout stream that is up: stalled over TCP, its relay last heard a minute ago.
func publishLookout(t *testing.T, streams []*stream) *stream {
	t.Helper()
	l := tcpLookout(true, true, time.Now().Add(-time.Minute))
	set := append(append([]*stream(nil), streams...), l)
	prev := activeStreams.Load()
	activeStreams.Store(&set)
	t.Cleanup(func() { activeStreams.Store(prev) })
	return l
}

// Android's blackout runs of 18.10, over TCP: with every socket stalled and no
// relay heard, a worker whose session ended redialed into the dark again and
// again. Now it redials once, finds the dark from the lookout — a connect
// refused at once is no evidence of its own — and waits, no failure counted,
// no further dial, until a stream hears its relay; then it is back within a
// second or so.
func TestAWorkerFailingIntoADarkPathIsParkedUntilARelayIsHeard(t *testing.T) {
	freshDark(t)
	awake(t)
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	resetRevivalPacing()
	dials := stageRelayDials(t)
	entered := waitsOf(t)
	answer := make(chan struct{})
	close(answer)
	h := runWorkersAgainstPeer(t, 146, 1, []string{relay.addr}, fakeRelay(t, answer))
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })
	l := publishLookout(t, h.streams)

	dials.dark.Store(true)
	tried := dials.tried.Load()
	recycleAttempt(h.streams[0].attempt.Load())
	var w workerWait
	select {
	case w = <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker never went into a wait")
	}
	if !w.parked {
		t.Fatalf("the wait after a connect into the dark is %+v, want parked", w)
	}
	time.Sleep(3 * time.Second)
	if n := dials.tried.Load() - tried; n != 1 {
		t.Fatalf("%d connect(s) while the path was dark, want the one that found it dark", n)
	}

	dials.dark.Store(false)
	heard := time.Now()
	l.activity.Load().noteRx(heard)
	waitFor(t, "the parked worker back", 3*time.Second, func() bool { return h.ready() == 1 })
	t.Logf("back %v after a relay was heard", time.Since(heard).Round(time.Millisecond))
}

// The tray's question over TCP: the lookout's stalled sockets with no relay
// heard are the path silent, before any dark is found; over UDP nothing
// stalls, and nothing found is no silence.
func TestPathSilenceOverTCPAsksTheLookout(t *testing.T) {
	freshDark(t)
	awake(t)
	noteRelayHeard()
	now := time.Now().Add(10 * time.Second)
	stalled := []*stream{tcpLookout(true, true, now.Add(-time.Minute))}
	if d := pathSilence(stalled, true, now); d < 9*time.Second {
		t.Fatalf("stalled sockets and no relay heard: silent %v, want about 10s", d)
	}
	if d := pathSilence(stalled, false, now); d != 0 {
		t.Fatalf("over UDP the lookout was asked: silent %v", d)
	}
	moving := []*stream{tcpLookout(true, false, now.Add(-time.Minute))}
	if d := pathSilence(moving, true, now); d != 0 {
		t.Fatalf("sockets moving, no dark found: silent %v", d)
	}
}
