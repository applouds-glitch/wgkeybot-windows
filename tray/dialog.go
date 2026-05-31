//go:build windows

package tray

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// psRun runs a PowerShell script without showing a console window.
func psRun(script string) ([]byte, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	return cmd.Output()
}

// PickConfFile opens a Windows file picker dialog and returns the selected .conf path.
// Returns empty string if the user cancels.
func PickConfFile(initialDir string) (string, error) {
	script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
$d = New-Object System.Windows.Forms.OpenFileDialog
$d.Title  = 'WgKeyBot — Select WireGuard config'
$d.Filter = 'WireGuard config (*.conf)|*.conf|All files (*.*)|*.*'
$d.InitialDirectory = '%s'
if ($d.ShowDialog() -eq 'OK') { Write-Output $d.FileName }
`, escapePS(initialDir))
	out, err := psRun(script)
	if err != nil {
		return "", fmt.Errorf("file picker: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// InputDialog shows a Windows VisualBasic InputBox and returns the entered text.
// Returns empty string if the user cancels.
func InputDialog(title, prompt string) (string, error) {
	script := fmt.Sprintf(`
Add-Type -AssemblyName Microsoft.VisualBasic
$r = [Microsoft.VisualBasic.Interaction]::InputBox('%s', '%s', '')
Write-Output $r
`, escapePS(prompt), escapePS(title))
	out, err := psRun(script)
	if err != nil {
		return "", fmt.Errorf("input dialog: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// ShowError shows a Windows error MessageBox (non-blocking — runs in background).
func ShowError(title, message string) {
	script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show('%s', '%s', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
`, escapePS(message), escapePS(title))
	psRun(script) //nolint:errcheck
}

// ShowInfo shows a Windows info MessageBox.
func ShowInfo(title, message string) {
	script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show('%s', '%s', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
`, escapePS(message), escapePS(title))
	psRun(script) //nolint:errcheck
}

// OpenFile opens a file in Notepad.
func OpenFile(path string) {
	exec.Command("notepad.exe", path).Start()
}

// escapePS escapes a string for embedding inside single quotes in PowerShell.
func escapePS(s string) string {
	// Single quotes are escaped by doubling them in PowerShell
	s = strings.ReplaceAll(s, "'", "''")
	// Newlines: break out of the string literal and concat
	s = strings.ReplaceAll(s, "\n", "' + \"`n\" + '")
	return s
}
