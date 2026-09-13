/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"sync"
	"sync/atomic"
)

// Terminal-failure accounting for the worker pool.
//
// A worker used to retry a credential failure forever on a fixed cadence: an
// unsolvable captcha or a call that no longer exists produced the same 30s sleep
// as a lost packet, so a stream that could never come back kept re-running the
// solve ladder — window included — for as long as the tunnel was up, and nothing
// ever told the user why the connection was not working.
//
// Workers now give up on failures that retrying cannot fix (see runWorker). A
// group that loses every worker is dead, but the tunnel may still be carried by
// the other groups, so a single give-up is not fatal. Only when every worker in
// the session has given up does the tunnel have no transport left at all — that
// is the terminal state, published here for the host to read.
//
// Published as a polled string rather than a channel because both consumers
// already poll: winbridge's WaitReady loop and the 30s watchdog tick. A channel
// would need either draining or a guaranteed single reader, and there are two.
var (
	fatalWorkersTotal atomic.Int64
	fatalWorkersDead  atomic.Int64
	fatalOnce         atomic.Pointer[sync.Once]

	fatalMu     sync.RWMutex
	fatalReason string
)

// resetWorkerFatalState re-arms the accounting for a fresh session. total is the
// number of workers about to be launched.
func resetWorkerFatalState(total int) {
	fatalWorkersTotal.Store(int64(total))
	fatalWorkersDead.Store(0)
	fatalOnce.Store(&sync.Once{})
	fatalMu.Lock()
	fatalReason = ""
	fatalMu.Unlock()
}

// reportWorkerGaveUp records that one worker stopped retrying for good. When the
// last one goes, the session is reported as terminally failed — once.
func reportWorkerGaveUp(streamID int, reason string) {
	dead := fatalWorkersDead.Add(1)
	total := fatalWorkersTotal.Load()
	turnLog("[WORKER %d] Gave up permanently (%s) — %d/%d workers dead", streamID, reason, dead, total)
	if total <= 0 || dead < total {
		return
	}
	once := fatalOnce.Load()
	if once == nil {
		return
	}
	once.Do(func() {
		turnLog("[PROXY] Every worker gave up — reporting terminal failure: %s", reason)
		fatalMu.Lock()
		fatalReason = reason
		fatalMu.Unlock()
	})
}

// turnFatalReason returns the reason every worker gave up, or "" while the
// session still has transport.
func turnFatalReason() string {
	fatalMu.RLock()
	defer fatalMu.RUnlock()
	return fatalReason
}
