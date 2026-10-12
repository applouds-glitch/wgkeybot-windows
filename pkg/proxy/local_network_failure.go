/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"errors"
	"time"
)

// A failure of the machine's own network is not held against a relay.
//
// The health accounting reads a young session's error or a failed Allocate as
// the relay's doing. When the network under the socket goes away they all fail
// at once, on every relay in use, and it read those too: a Wi-Fi drop or a
// laptop lid put three strikes on each relay within the coalescing window's
// reach, and every relay stood down for five minutes at the very moment the
// path returned (Android field log 19.09: twenty stand-downs of a relay with
// live streams on it over 23 minutes of a flapping network).
//
// Two tests, because neither sees everything. The error: these errnos are the
// local stack speaking about its own interface or route, never a relay's
// answer, and they arrive before the host notices the loss. The network: a
// timeout carries no errno at all, and a session that went quiet because the
// path left under it proves nothing either — whatever ended while there was no
// network, or after the network it began on was left, says nothing about the
// far end.
//
// What stays the relay's: a refusal, silence on a network that stayed
// (timeouts), a reset, any TURN error. An unblamed relay costs an attempt that
// fails fast; a blamed healthy one cost five minutes.
func localNetworkError(err error) bool {
	for _, errno := range localNetworkErrnos {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

// relayNotToBlame: the failure of an attempt begun at started, ending in err,
// belongs to the machine's network rather than to the relay.
func relayNotToBlame(err error, started time.Time) bool {
	return localNetworkError(err) || networkLeftSince(started)
}
