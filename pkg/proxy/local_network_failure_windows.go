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

// The relay's answers a socket reports, and the silences it times out on
// (relay_silence.go). Winsock's own numbers: syscall's ECONNREFUSED and the
// like are invented on Windows and never come back from a socket.
var (
	relayRefusedErrnos  = []syscall.Errno{10061, 1225} // WSAECONNREFUSED, ERROR_CONNECTION_REFUSED
	relayResetErrnos    = []syscall.Errno{10054, 109}  // WSAECONNRESET, ERROR_BROKEN_PIPE
	relayTimedOutErrnos = []syscall.Errno{10060, 1460} // WSAETIMEDOUT, ERROR_TIMEOUT
)

// relayFlowGaveUpErrnos are how Windows reports a TCP connection to a relay it
// gave up itself (relayFlowConn): the retransmission limit run out
// (relayTCPUserTimeout) or the keepalive probes unanswered. Winsock does not
// say which of these a given limit ends in — a timeout, an abort "possibly due
// to a data transmission time-out" or a keepalive reset — so all of them count;
// the errno is in the line the session ends with.
var relayFlowGaveUpErrnos = []syscall.Errno{
	10060, // WSAETIMEDOUT
	1460,  // ERROR_TIMEOUT
	10053, // WSAECONNABORTED
	1236,  // ERROR_CONNECTION_ABORTED
	10052, // WSAENETRESET: the keepalive found the connection broken
}
