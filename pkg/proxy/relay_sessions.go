/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"sync"
	"sync/atomic"
)

// The sessions running on each relay, and the attempt each one belongs to —
// what the judge of relay loss needs to move the sessions off a relay it rests
// (relay_rest.go).
//
// Android keeps both beside its network switch: there every worker attempt is
// registered with the network its sockets are bound to, and a move to another
// network recycles them (network_switch.go). Windows binds no socket to a
// network, so the attempt here is only what the rest needs: a context of its
// own under the worker's, and the mark that says it was ended on purpose — a
// recycled attempt is not a failure of anything, and its worker reconnects at
// once (runWorker).

// liveSessions books the streams running a session on each relay.
var liveSessions = struct {
	sync.Mutex
	byRelay map[string]map[*stream]struct{}
}{byRelay: map[string]map[*stream]struct{}{}}

// trackLiveSession books s as running a session on addr until the returned func
// is called.
func trackLiveSession(addr string, s *stream) func() {
	liveSessions.Lock()
	set := liveSessions.byRelay[addr]
	if set == nil {
		set = map[*stream]struct{}{}
		liveSessions.byRelay[addr] = set
	}
	set[s] = struct{}{}
	liveSessions.Unlock()

	return func() {
		liveSessions.Lock()
		delete(set, s)
		if len(liveSessions.byRelay[addr]) == 0 {
			delete(liveSessions.byRelay, addr)
		}
		liveSessions.Unlock()
	}
}

// liveSessionCounts is how many sessions run on each relay now.
func liveSessionCounts() map[string]int {
	liveSessions.Lock()
	defer liveSessions.Unlock()
	out := make(map[string]int, len(liveSessions.byRelay))
	for relay, set := range liveSessions.byRelay {
		out[relay] = len(set)
	}
	return out
}

// relayAttempt is one worker attempt — dial, allocate and the session that
// follows — run under a context of its own so that it can be ended from outside
// without ending the worker.
type relayAttempt struct {
	ctx    context.Context
	cancel context.CancelFunc
	moved  atomic.Bool
}

func beginRelayAttempt(parent context.Context) *relayAttempt {
	ctx, cancel := context.WithCancel(parent)
	return &relayAttempt{ctx: ctx, cancel: cancel}
}

// recycleAttempt ends the attempt so that its worker reconnects at once and
// counts no failure — and, the relay it ran on resting, onto another one.
func recycleAttempt(a *relayAttempt) {
	if a.moved.CompareAndSwap(false, true) {
		a.cancel()
	}
}

// end releases the attempt's context and reports whether it was recycled.
func (a *relayAttempt) end() (moved bool) {
	a.cancel()
	return a.moved.Load()
}
