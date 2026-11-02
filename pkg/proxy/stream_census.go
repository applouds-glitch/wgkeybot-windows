/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */
package proxy

import (
	"sync"
	"sync/atomic"
)

// The stream set of the proxy that is running: for the parked workers' look at
// the streams that are up (path_revival.go, dark_scout.go), and for the screen.

// activeStreams is the stream set of the proxy that is running, nil when none is.
var activeStreams atomic.Pointer[[]*stream]

// activeOverTCP is the transport of the proxy that is running, claimed with its
// stream set: for the questions asked without a worker's config at hand
// (pathSilence). After the proxy stops it is the last one's.
var activeOverTCP atomic.Bool

// claimTransport makes overTCP the running proxy's transport (under
// runningProxyMu). A proxy over the other transport than the last one's
// starts the path's clocks over: when a relay was last heard over UDP says
// nothing of how long TCP has been silent, and a dark found over TCP at once
// read as silent since the last UDP packet (Codex review of the Windows port,
// 2026-10-23).
func claimTransport(overTCP bool) {
	if activeOverTCP.Swap(overTCP) != overTCP {
		resetRelayHeardClocks()
	}
}

// runningProxyMu orders a proxy's claim on the process-wide state of the one
// running — its stream set, its reporter's clock, its workers' fatal count —
// against the next proxy's (StartTunnelGroups). A transport rebuild cancels
// the old proxy and starts the next at once, without waiting for the old
// StartProxy to return: one cancelled while it prefetched came out of it after
// the next had started its groups, published its own set and clock over
// theirs, and withdrew the set as it drained — the running proxy's streams
// gone from the census, its reporter shut out of the clock (Codex review of
// the Windows port, 2026-10-23). A claim checks the proxy's context under the
// lock: the next start comes after the old one's cancel, so the old claim
// either comes first or sees the cancel.
var runningProxyMu sync.Mutex

// publishStreams makes streams the running set and returns the call that
// withdraws it — only if it is still the one published: a stop that drains
// slowly must not take the next start's set down with it.
func publishStreams(streams []*stream) (withdraw func()) {
	set := &streams
	activeStreams.Store(set)
	return func() { activeStreams.CompareAndSwap(set, nil) }
}

// activeStreamSet is the stream set of the proxy that is running; nil if none.
func activeStreamSet() []*stream {
	if set := activeStreams.Load(); set != nil {
		return *set
	}
	return nil
}

// readyStreamCount is the number of streams handed to the dispatcher, or -1 when
// no proxy is running — which is not the same as a proxy with none.
func readyStreamCount() int {
	set := activeStreams.Load()
	if set == nil {
		return -1
	}
	n := 0
	for _, s := range *set {
		if s.ready.Load() {
			n++
		}
	}
	return n
}
