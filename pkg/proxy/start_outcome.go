/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */
package proxy

import (
	"sync/atomic"
	"time"
)

// What a start that ran out of time tells the caller.
//
// The plain -1 after the startup timeout says nothing about why, and the tray
// answered it with "TURN proxy failed (status -1)". Android field log 12.10
// (Xiaomi, Tele2): the user had no internet at all, the cached credentials had
// expired, and every VK address reset the connection before a byte came back.
// About ten taps over 2.5 hours, each 60-70s, none of which could help — and
// the screen never said what was wrong.
//
// startVKUnreachable is that case named: no credential reached this start, and
// not one VK connection carried a byte back while it ran. Then nothing VK said
// stood between us and credentials; the network in between did — no internet
// behind the gateway, a captive portal not yet passed, or a filter in front of
// VK. One byte back (a TLS hello, an error page, a captcha) is VK answering,
// and the start keeps the plain -1: a refusal VK gave has its own paths.
//
// Port of Android ead7f1bc, with the iOS port's evidence for WaitReady.
const startVKUnreachable int32 = -5

// startRelaysCarryNothing is the case TCP to the relays is for, named (Windows
// only): the start had its credentials, a relay granted it an allocation, and
// not one stream carried a round trip through its relay before the window
// closed. Over UDP that is what the network of relay_transport.go does — the
// answers to Allocate and CreatePermission come back, nothing the relay
// forwards down ever arrives — and the tray says TCP may get through, which
// is the user's to choose: Windows cannot see the operator behind a phone's
// hotspot. It is also what a server that does not answer through the relays
// looks like, so it says what was seen, not why. Not a start that asked for a
// captcha or slept: the 30s it is given ran out on the user or on the sleep,
// and an allocation granted before says nothing about the path after (Codex
// review of the Windows port, 2026-10-23).
const startRelaysCarryNothing int32 = -6

// vkConnsHeard counts VK API connections that carried at least one byte back
// (heardConn). Only ever compared with a snapshot taken at the start of the
// attempt, so its absolute value means nothing.
var vkConnsHeard atomic.Uint64

// startEvidence is what the running start has had from VK so far: whether any
// credential reached it, and the count of VK connections heard when it began.
// Published for WaitReadyContext (vkUnreachableSoFar), whose own 90s deadline
// can come before StartProxy gives its code: StartProxy waits for every
// group's credential first, and over a network that lets the SYN through and
// says nothing after it, each VK connection takes the TLS guard's 15s
// (vk_dial.go) and the fetches can outlast that deadline (codex review of the
// iOS port, 2026-10-22).
type startEvidence struct {
	heardAt   uint64
	began     time.Time
	creds     atomic.Bool
	allocated atomic.Bool // a relay granted this start an allocation
	captcha   atomic.Bool // the start asked for a captcha
}

var currentStart atomic.Pointer[startEvidence]

// beginStartEvidence starts the evidence of a proxy start.
func beginStartEvidence() *startEvidence {
	e := &startEvidence{heardAt: vkConnsHeard.Load(), began: time.Now()}
	currentStart.Store(e)
	return e
}

// vkHeard reports whether VK sent a byte back since the start began.
func (e *startEvidence) vkHeard() bool { return vkConnsHeard.Load() != e.heardAt }

// noteAllocated books an allocation a relay granted to the start e — the one
// the dial belongs to, not the one running now: a dial of a stopped proxy can
// still be answered after the next one has begun (Codex review of the Windows
// port, 2026-10-23). A nil e is no start.
func (e *startEvidence) noteAllocated() {
	if e != nil {
		e.allocated.Store(true)
	}
}

// noteStartCaptcha books a captcha asked for during the running start: captcha
// requests are the process's, one at a time.
func noteStartCaptcha() {
	if e := currentStart.Load(); e != nil {
		e.captcha.Store(true)
	}
}

// relaysCarriedNothing reports whether what the start's window held is the
// relays answering and carrying nothing: an allocation granted, with no captcha
// asked for and no sleep inside the window to have used it up.
func (e *startEvidence) relaysCarriedNothing() bool {
	return e.allocated.Load() && !e.captcha.Load() && !hostFrozeSince(e.began)
}

// vkUnreachableSoFar reports whether the running start has had no credential
// and not a byte back from VK: what its own timeout would call
// startVKUnreachable.
func vkUnreachableSoFar() bool {
	e := currentStart.Load()
	return e != nil && startTimeoutCode(e.creds.Load(), e.vkHeard(), e.relaysCarriedNothing()) == startVKUnreachable
}

// startTimeoutCode is the code for a start whose window closed without a
// stream proving its data plane; carriedNothing is relaysCarriedNothing.
func startTimeoutCode(credsObtained, vkHeard, carriedNothing bool) int32 {
	switch {
	case !credsObtained && !vkHeard:
		return startVKUnreachable
	case credsObtained && carriedNothing:
		return startRelaysCarryNothing
	}
	return -1
}
