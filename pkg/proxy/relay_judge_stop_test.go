/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */
package proxy

import (
	"context"
	"sync"
	"testing"
	"time"
)

// A judge whose proxy has stopped — RestartTransport starts the next one at
// once — touches nothing of the next proxy's: liveSessions and relayRest.peer
// outlive a proxy.

// A judge cancelled before it acts rests no relay and moves no session.
func TestACancelledJudgeMovesNoSession(t *testing.T) {
	withCleanRelayRest(t)
	const relay = "10.0.0.1:3478"
	h := sessionOn(t, relay, []string{relay, "10.0.0.2:3478"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	restJudgedRelays(ctx, []relayVerdict{{relay: relay, rate: 0.05}}, time.Now())
	if out := recycleRelaySessions(ctx, relay, time.Now(), nil); out.moved != 0 {
		t.Fatalf("a cancelled judge moved %d session(s)", out.moved)
	}
	restDeafRelay(ctx, relayDeafVerdict{relay: relay, deaths: relayDeafStrikes}, 1, time.Now())
	if relayResting(relay, time.Now()) {
		t.Fatal("a cancelled judge rested the relay")
	}
	select {
	case <-h.ctx.Done():
		t.Fatal("a cancelled judge recycled the session")
	case <-time.After(relayRecycleGap + 100*time.Millisecond):
	}
}

// firstCheckContext tells, on checked, that ctx.Err() has been asked once —
// the judge is past its entry check.
type firstCheckContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (c *firstCheckContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked) })
	return err
}

// The judge passed its entry check, then waited for liveSessions while the
// proxy stopped and the next one booked a session on the relay: it does not
// recycle that session (Codex review of the Android port, 23.10).
func TestAJudgeStoppedBeforeItReadsTheSessionsMovesNoneOfTheNextProxys(t *testing.T) {
	withCleanRelayRest(t)
	const relay = "10.0.0.1:3478"
	old, stop := context.WithCancel(context.Background())
	defer stop()
	judge := &firstCheckContext{Context: old, checked: make(chan struct{})}

	liveSessions.Lock()
	prior := liveSessions.byRelay
	liveSessions.byRelay = map[string]map[*stream]struct{}{}
	var unlock sync.Once
	release := func() { unlock.Do(liveSessions.Unlock) }
	defer release()
	t.Cleanup(func() {
		liveSessions.Lock()
		liveSessions.byRelay = prior
		liveSessions.Unlock()
	})
	out := make(chan relayMoveOut, 1)
	go func() { out <- recycleRelaySessions(judge, relay, time.Now(), nil) }()
	select {
	case <-judge.checked:
	case <-time.After(2 * time.Second):
		t.Fatal("the judge never reached its entry check")
	}
	stop()
	next, stopNext := context.WithCancel(context.Background())
	defer stopNext()
	h := beginRelayAttempt(next)
	defer h.end()
	s := &stream{id: 1, ctx: next}
	relays := []string{relay, "10.0.0.2:3478"}
	s.relays.Store(&relays)
	s.attempt.Store(h)
	liveSessions.byRelay[relay] = map[*stream]struct{}{s: {}}
	release()

	select {
	case r := <-out:
		if r.moved != 0 || s.move.Load() != nil {
			t.Errorf("the stopped proxy's judge moved the next one's session: moved %d, move %+v", r.moved, s.move.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the judge never returned")
	}
	select {
	case <-h.ctx.Done():
		t.Error("the stopped proxy's judge recycled the next one's session")
	case <-time.After(relayRecycleGap + 100*time.Millisecond):
	}
}
