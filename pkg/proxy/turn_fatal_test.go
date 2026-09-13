/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import "testing"

// reportWorkerGaveUp must only report the session terminally fatal once
// *every* worker has given up — a spurious dead >= total on a session that
// still has a working group would tear down a tunnel that is carrying
// traffic just fine, and tell the user to get a new config for no reason.
// The accounting is re-armed from two call sites with two different totals
// (StartProxy passes 0 before it knows how many workers it will launch,
// StartTunnelGroups passes the real count once it does), so this pins both
// the "not yet" edge (3 of 4 dead) and the "exactly now" edge (4 of 4).
func TestReportWorkerGaveUpNeedsEveryWorker(t *testing.T) {
	resetWorkerFatalState(4)
	defer resetWorkerFatalState(0)

	for i := 0; i < 3; i++ {
		reportWorkerGaveUp(i, "captcha unsolved")
	}
	if turnFatalReason() != "" {
		t.Fatal("one group dying reported the session fatal")
	}

	reportWorkerGaveUp(3, "captcha unsolved")
	if turnFatalReason() == "" {
		t.Fatal("last worker did not report fatal")
	}
}

// StartProxy re-arms the accounting with total=0 before StartTunnelGroups has
// told it how many workers are about to launch. A worker report landing in
// that window must stay inert rather than incrementing toward a total it does
// not know yet — otherwise a session could be declared fatal (dead >= total,
// with total==0) before it has a single worker running, tearing down a tunnel
// that never got a chance to carry anything.
func TestReportWorkerGaveUpInertBeforeGroupsStart(t *testing.T) {
	resetWorkerFatalState(0) // StartProxy's total=0 arming
	defer resetWorkerFatalState(0)

	reportWorkerGaveUp(0, "stale worker")
	if turnFatalReason() != "" {
		t.Fatal("total<=0 accounting was not inert")
	}
}
