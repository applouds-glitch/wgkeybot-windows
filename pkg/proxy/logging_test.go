/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"testing"
	"time"
)

// Метка строки и время в теле сообщения — в одном поясе: по умолчанию в
// локальном, как у стандартного log, после SetTimezoneOffset — в заданном.
func TestLogClockFollowsTheLogZone(t *testing.T) {
	logMu.Lock()
	prev := logLoc
	logMu.Unlock()
	t.Cleanup(func() {
		logMu.Lock()
		logLoc = prev
		logMu.Unlock()
	})

	at := time.Date(2026, 9, 23, 9, 0, 0, 0, time.UTC)
	logMu.Lock()
	logLoc = time.Local
	logMu.Unlock()
	if got, want := logClock(at).Format("15:04"), at.In(time.Local).Format("15:04"); got != want {
		t.Fatalf("default zone: %s, want local %s", got, want)
	}

	SetTimezoneOffset(3 * 3600)
	if got := logClock(at).Format("15:04"); got != "12:00" {
		t.Fatalf("with a +3h offset: %s, want 12:00", got)
	}
}
