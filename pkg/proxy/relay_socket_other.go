//go:build !windows && !linux

/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"net"
	"syscall"
	"time"
)

// Elsewhere the package is built only to run its tests: the connection keeps
// the system's defaults.

func setTCPUserTimeout(*net.TCPConn, time.Duration) error { return nil }

func setTCPMaxSegment(syscall.RawConn, int) error { return nil }

func readRelaySocket(*net.TCPConn) (relaySocketSample, bool) { return relaySocketSample{}, false }
