/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"os"
	"sync/atomic"
)

// The directory where the proxy keeps what has to outlive the process: the app
// is quit, updated or the machine restarted between sessions. Empty until the
// host names it, and then nothing is kept.
var stateDir atomic.Pointer[string]

// SetStateDir names that directory (%APPDATA%\WgKeyBot on Windows). The host
// calls it once at startup, before any proxy start or link check.
func SetStateDir(dir string) { stateDir.Store(&dir) }

func stateDirPath() string {
	if dir := stateDir.Load(); dir != nil {
		return *dir
	}
	return ""
}

// replaceFile writes data to path through a temporary file, so that a process
// dying mid-write leaves the old file and not half of the new one. No fsync: a
// process dying is what the file is for, and the page cache outlives that; a
// power cut that loses the file costs what a corrupt one does. os.Rename
// replaces an existing file on Windows too (MOVEFILE_REPLACE_EXISTING).
func replaceFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
