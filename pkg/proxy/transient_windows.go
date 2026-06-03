/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"errors"
	"syscall"
)

// Winsock send-side error codes (stable since Winsock 1.1). The stdlib syscall
// package doesn't export the WSA* names, so we define the numeric values.
const (
	wsaEWOULDBLOCK = syscall.Errno(10035) // WSAEWOULDBLOCK
	wsaENOBUFS     = syscall.Errno(10055) // WSAENOBUFS
)

// isTransientSendErr reports whether a UDP WriteTo error is a transient,
// recoverable Windows condition rather than a dead path.
//
// WSAENOBUFS (the per-socket send buffer / NIC queue is momentarily full under
// heavy WireGuard traffic) and WSAEWOULDBLOCK are per-packet hiccups — the
// socket and the TURN allocation are still fine. Dropping the offending packet
// (WireGuard retransmits) and keeping the stream is the correct response.
//
// Tearing the stream down on these would make every stream reconnect at once
// under load; the resulting re-Allocate burst manufactures a spurious TURN
// allocation-quota (486) response, which then force-expires the credential
// cache and triggers a VK re-fetch — fatal once the VPN is up.
func isTransientSendErr(err error) bool {
	return errors.Is(err, wsaENOBUFS) || errors.Is(err, wsaEWOULDBLOCK)
}
