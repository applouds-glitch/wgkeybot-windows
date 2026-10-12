//go:build windows

package tray

import (
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Exercise actual User32 controls on both architectures in Windows CI. This
// catches struct packing/callback ABI errors that cross-compilation cannot.
func TestNativeWindowControls(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	w, err := newNativeWindow("WgKeyBot UI test", 472, 152, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.dispose()
	// WS_CLIPCHILDREN leaves group box interiors unpainted.
	if style, _, _ := user32dll.NewProc("GetWindowLongW").Call(w.hwnd, ^uintptr(15)); style&0x02000000 != 0 {
		t.Fatal("native window must not clip children")
	}
	edit := w.add("EDIT", "", 0x00800000|wsTabstop, 10, 20, 20, 420, 28, 0)
	edit.setText("Проверка Unicode — VPN & SOCKS")
	var buf [128]uint16
	pGetWindowText.Call(edit.hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if got := windows.UTF16ToString(buf[:]); got != edit.text {
		t.Fatalf("text corrupted: %q", got)
	}
	button := w.add("BUTTON", "VPN", bsRadiobutton|wsTabstop, 11, 20, 70, 120, 26, 0)
	button.check(true)
	if got, _, _ := pSendMessage.Call(button.hwnd, 0x00f0, 0, 0); got != 1 {
		t.Fatal("radio check not applied")
	}
	button.enable(false)
	if got, _, _ := user32dll.NewProc("IsWindowEnabled").Call(button.hwnd); got != 0 {
		t.Fatal("button not disabled")
	}
	// Apply 150% layout and back; controls must remain valid after font replacement.
	w.dpi = 144
	w.updateFonts()
	w.layout()
	w.dpi = 96
	w.updateFonts()
	w.layout()
	w.command = func(id int) {
		if id != 11 {
			t.Errorf("wrong command ID: %d", id)
		}
		pDestroyWindow.Call(w.hwnd)
	}
	pPostMessage.Call(w.hwnd, wmCommand, 11, button.hwnd)
	if err := w.run(); err != nil {
		t.Fatal(err)
	}
}
