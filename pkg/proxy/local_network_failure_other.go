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
