//go:build !windows

/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

// isTransientSendErr is meaningful only on Windows (WSAENOBUFS / WSAEWOULDBLOCK).
// On other platforms no send error is treated as transient, so the build stays
// platform-neutral and pkg/proxy keeps vetting/compiling off-Windows.
func isTransientSendErr(err error) bool { return false }
