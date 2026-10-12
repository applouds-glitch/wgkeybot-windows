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
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func relayStrikes(addr string) int {
	serverHealthState.Lock()
	defer serverHealthState.Unlock()
	return healthEntryLocked(addr).failures
}

func opErr(op string, errno syscall.Errno) error {
	return &net.OpError{Op: op, Net: "udp", Err: os.NewSyscallError(op, errno)}
}

// Which errors are the local stack speaking about its own network — and which
// are the far end's answer, or its silence, and stay the relay's.
func TestLocalNetworkErrorsAreToldFromTheRelaysAnswers(t *testing.T) {
	for _, errno := range localNetworkErrnos {
		if err := fmt.Errorf("relay TX: %w", opErr("write", errno)); !localNetworkError(err) {
			t.Errorf("%v was read as the relay's doing", err)
		}
	}
	for _, err := range []error{
		nil,
		opErr("connect", syscall.ECONNREFUSED),
		opErr("read", syscall.ECONNRESET),
		opErr("write", syscall.EPIPE),
		opErr("connect", syscall.ETIMEDOUT),
		context.DeadlineExceeded,
		errDataPlaneHandshake,
		errAllocateSilent,
		errors.New("all retransmissions failed"),
		&stun.TurnError{ErrorCodeAttr: stun.ErrorCodeAttribute{Code: stun.CodeAllocQuotaReached}},
	} {
		if localNetworkError(err) {
			t.Errorf("%v was read as the machine's own network", err)
		}
	}
}

// The network's side of it: nothing to say while there is none, or once the one
// an attempt began on was left after it began — and only then.
func TestNetworkLeftSince(t *testing.T) {
	resetNetworkAvailabilityForTest()
	t.Cleanup(resetNetworkAvailabilityForTest)

	before := time.Now()
	if networkLeftSince(before) {
		t.Fatal("a proxy never told of a loss excused its relays")
	}
	setNetworkAvailable(true) // reported again: nothing was left
	if networkLeftSince(before) {
		t.Fatal("the same network reported again read as a departure")
	}

	time.Sleep(2 * time.Millisecond)
	setNetworkAvailable(false)
	if !networkLeftSince(time.Now()) {
		t.Fatal("no network, and the relay still answers for what ends now")
	}
	setNetworkAvailable(true)
	if !networkLeftSince(before) {
		t.Fatal("an attempt begun before the loss answers for it after the return")
	}
	time.Sleep(2 * time.Millisecond)
	after := time.Now()
	if networkLeftSince(after) {
		t.Fatal("an attempt begun after the return was excused by the old loss")
	}

	time.Sleep(2 * time.Millisecond)
	NotifyNetworkChange() // exchanged for another
	if !networkLeftSince(after) {
		t.Fatal("moving to another network did not read as leaving the old one")
	}
}

// An Allocate that goes unanswered while the host reports the network gone is
// not the relay's silence — and the same silence on a network that stayed still
// counts, or the exemption would have swallowed the accounting whole.
func TestSilentAllocateCountsOnlyWhileTheNetworkStayed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		leave      bool
		wantStrike int
	}{
		{"network stayed", false, 1},
		{"network left", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetNetworkAvailabilityForTest()
			t.Cleanup(resetNetworkAvailabilityForTest)
			resetServerHealth()
			t.Cleanup(resetServerHealth)
			addr := listenFakeRelay(t).LocalAddr().String() // reads nothing, answers nothing

			if tc.leave {
				go func() {
					time.Sleep(200 * time.Millisecond)
					setNetworkAvailable(false)
				}()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*allocateSilenceTimeout)
			defer cancel()
			if _, _, _, _, _, err := dialAndAllocate(ctx, &stream{}, t.Name(), "pass", addr, WorkerGroupConfig{UseUDP: true}); !errors.Is(err, errAllocateSilent) {
				t.Fatalf("want a silent Allocate, got %v", err)
			}
			if n := relayStrikes(addr); n != tc.wantStrike {
				t.Fatalf("relay took %d strike(s), want %d", n, tc.wantStrike)
			}
		})
	}
}
