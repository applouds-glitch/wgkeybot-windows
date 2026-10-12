/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
)

func TestPionReceiveFailuresStayVisible(t *testing.T) {
	for _, tc := range []struct {
		format string
		err    error
		want   bool
	}{
		{pionInboundFailed, errors.New("non-STUN message from STUN server"), true},
		{pionReadLoopFailed, io.EOF, true},
		{pionReadLoopFailed, errors.New("network unreachable"), true},
		{pionReadLoopFailed, &net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}, false},
		{"Received %s", fmt.Errorf("user payload: %s", pionInboundFailed), false},
	} {
		if got := pionReceiveFailure(tc.format, tc.err); got != tc.want {
			t.Errorf("%s / %v: got %v", tc.format, tc.err, got)
		}
	}
}

// A receive-loop failure logged under pion's client scope latches on the
// session's permWatch; the same line under any other scope must not.
func TestPionReceiveFailureStopsReaderOnlyInClientScope(t *testing.T) {
	cause := errors.New("wsarecv: connection reset")

	w := newPermWatch(1)
	pionLogFactory{streamID: 1, watch: w}.NewLogger("ice").Debugf(pionReadLoopFailed, cause)
	if closed(w.readerGoneCh()) {
		t.Fatal("a foreign scope stopped the reader")
	}

	pionLogFactory{streamID: 1, watch: w}.NewLogger(permWatchScope).Debugf(pionReadLoopFailed, cause)
	if !closed(w.readerGoneCh()) {
		t.Fatal("reader failure did not latch")
	}
	if got := w.readerStoppedBy(); !errors.Is(got, cause) {
		t.Fatalf("readerStoppedBy = %v, want %v", got, cause)
	}
	if w.fired() {
		t.Fatal("a stopped reader must not read as a blackhole")
	}
}
