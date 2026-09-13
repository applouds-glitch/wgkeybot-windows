//go:build windows

package tray

import (
	"os/exec"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// InputDialog uses native controls on its own message thread. Unicode input
// no longer depends on the encoding of a PowerShell child process.
func InputDialog(title, prompt string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	w, err := newNativeWindow(title, 472, 152, 0)
	if err != nil {
		return "", err
	}
	defer w.dispose()
	w.label(prompt, 20, 18, 432, 24, 0)
	edit := w.add("EDIT", "", 0x00800000|0x0080|wsTabstop, 0, 20, 50, 432, 28, 0)
	pSendMessage.Call(edit.hwnd, 0x00c5, 4096, 0) // EM_SETLIMITTEXT
	w.add("BUTTON", "Импортировать", 1|wsTabstop, 1, 196, 100, 150, 32, 0)
	w.add("BUTTON", "Отмена", wsTabstop, 2, 356, 100, 96, 32, 0)
	var result string
	w.command = func(id int) {
		switch id {
		case 1:
			var buf [4097]uint16
			pGetWindowText.Call(edit.hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			result = strings.TrimSpace(windows.UTF16ToString(buf[:]))
			pDestroyWindow.Call(w.hwnd)
		case 2:
			pDestroyWindow.Call(w.hwnd)
		}
	}
	w.show()
	pSetFocus.Call(edit.hwnd)
	err = w.run()
	return result, err
}

func ShowError(title, message string) {
	windows.MessageBox(0, nativeString(message), nativeString(title), 0x00000010|0x00010000)
}

func ShowInfo(title, message string) {
	windows.MessageBox(0, nativeString(message), nativeString(title), 0x00000040|0x00010000)
}

func OpenFile(path string) { exec.Command("notepad.exe", path).Start() }
