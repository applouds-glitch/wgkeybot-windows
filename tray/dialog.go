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

// SelectConfig shows a ListBox dialog to pick one config from the given paths.
// Returns the selected path, or empty string if cancelled.
func SelectConfig(paths []string) (string, error) {
	// Build a newline-separated list of display names for PowerShell
	var names []string
	for _, p := range paths {
		// Extract filename without extension for display
		name := p
		if idx := strings.LastIndexAny(p, `/\`); idx >= 0 {
			name = p[idx+1:]
		}
		name = strings.TrimSuffix(name, ".conf")
		names = append(names, name)
	}
	// Pass paths as Base64-encoded JSON to avoid escaping issues
	pathsArg := strings.Join(paths, "|")
	namesArg := strings.Join(names, "|")

	script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$paths = '%s' -split '\|'
$names = '%s' -split '\|'

$form            = New-Object System.Windows.Forms.Form
$form.Text       = 'WgKeyBot — Select config'
$form.Size       = New-Object System.Drawing.Size(360, 240)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

$list            = New-Object System.Windows.Forms.ListBox
$list.Dock       = 'Fill'
$list.Font       = New-Object System.Drawing.Font('Segoe UI', 10)
$names | ForEach-Object { $list.Items.Add($_) | Out-Null }
if ($list.Items.Count -gt 0) { $list.SelectedIndex = 0 }
$list.Add_DoubleClick({ $form.DialogResult = 'OK'; $form.Close() })

$btn             = New-Object System.Windows.Forms.Button
$btn.Text        = 'Connect'
$btn.Dock        = 'Bottom'
$btn.Height      = 36
$btn.Add_Click({ $form.DialogResult = 'OK'; $form.Close() })

$form.Controls.Add($list)
$form.Controls.Add($btn)
$form.AcceptButton = $btn

if ($form.ShowDialog() -eq 'OK' -and $list.SelectedIndex -ge 0) {
    Write-Output $paths[$list.SelectedIndex]
}
`, escapePS(pathsArg), escapePS(namesArg))

	out, err := psRun(script)
	if err != nil {
		return "", fmt.Errorf("select dialog: %w", err)
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
