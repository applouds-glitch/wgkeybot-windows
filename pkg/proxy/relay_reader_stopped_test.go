/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"net"
	"testing"
	"time"
)

// resetDownstream resets every connection the front holds towards the client,
// the way the field relays did to flows that had gone deaf: an RST, not a FIN.
func (f *stallingFront) resetDownstream() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 0; i < len(f.conns); i += 2 {
		if tc, ok := f.conns[i].(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		f.conns[i].Close()
	}
}

// A reset on an idle tunnel. pion's read loop ends on it and says so at debug
// level only; the next write of ours is the keepalive, up to 25s away, and its
// error is logged and retried. Nothing else ended the session before the
// dead-stream detector, 90s on. The stream has to come back by itself, within
// seconds, and the relay is not to blame for one flow.
func TestResetTCPFlowOnAnIdleTunnelIsReplacedAtOnce(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	front := startStallingFront(t, relay.addr)
	overTCP(t)

	h := runWorkersAgainst(t, 122, 1, []string{front.addr})
	t.Cleanup(front.close)
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })

	front.resetDownstream()
	waitFor(t, "the stream back up on a new connection", 8*time.Second, func() bool {
		return front.accepted.Load() >= 2 && h.ready() == 1
	})

	serverHealthState.Lock()
	failures := healthEntryLocked(front.addr).failures
	serverHealthState.Unlock()
	if failures != 0 {
		t.Fatalf("the relay took %d strike(s) for a flow that was reset", failures)
	}
}
