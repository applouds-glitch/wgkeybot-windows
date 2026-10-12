/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import "syscall"

// On Windows the stdlib's syscall.ENETUNREACH and friends are invented values
// that no socket call returns, so the local-network failures are matched by
// their Winsock codes — and by the Win32 codes the same conditions arrive as
// when an overlapped send completes through the IOCP rather than failing
// synchronously. Host unreachable is left out on purpose: that one can be a
// router's answer about the relay's side of the path.
var localNetworkErrnos = []syscall.Errno{
	10053, // WSAECONNABORTED: the socket's network was torn down under it
	10051, // WSAENETUNREACH: no route, the interface is gone
	10050, // WSAENETDOWN
	10049, // WSAEADDRNOTAVAIL: the source address left with the lease
	1231,  // ERROR_NETWORK_UNREACHABLE
	1236,  // ERROR_CONNECTION_ABORTED
}
