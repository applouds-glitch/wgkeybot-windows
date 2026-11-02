//go:build !windows

/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import "syscall"

// The POSIX spelling of the same failures (see local_network_failure_windows.go),
// kept so the platform-neutral part builds and tests on the host.
var localNetworkErrnos = []syscall.Errno{
	syscall.ECONNABORTED,  // the socket's network was torn down under it
	syscall.ENETUNREACH,   // no route: the interface is gone
	syscall.ENETDOWN,      //
	syscall.EADDRNOTAVAIL, // the source address left with the lease
	syscall.EPERM,         // the platform's firewall cut the socket off
}

// The relay's answers a socket reports, and the silences it times out on
// (relay_silence.go).
var (
	relayRefusedErrnos  = []syscall.Errno{syscall.ECONNREFUSED}
	relayResetErrnos    = []syscall.Errno{syscall.ECONNRESET, syscall.EPIPE}
	relayTimedOutErrnos = []syscall.Errno{syscall.ETIMEDOUT}
	// relayFlowGaveUpErrnos: a TCP connection to a relay the kernel gave up
	// (relayFlowConn, relayTCPUserTimeout).
	relayFlowGaveUpErrnos = []syscall.Errno{syscall.ETIMEDOUT}
)
