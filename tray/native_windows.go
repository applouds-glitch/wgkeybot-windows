//go:build windows

package tray

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A small Win32 host shared by the dashboard and token dialog. Callers own a
// locked OS thread; only PostMessage may be used from another goroutine.
const (
	nativeClass     = "WgKeyBot.NativeWindow"
	wmClose         = 0x0010
	wmCommand       = 0x0111
	wmTimer         = 0x0113
	wmShowDashboard = 0x8001
	wmDispose       = 0x8002
	wsTabstop       = 0x00010000
	wsGroup         = 0x00020000
	bsPushbutton    = 0
	bsCheckbox      = 2
	bsRadiobutton   = 4
	bsGroupbox      = 7
)

var (
	pCreateWindow     = user32dll.NewProc("CreateWindowExW")
	pDefWindowProc    = user32dll.NewProc("DefWindowProcW")
	pDestroyWindow    = user32dll.NewProc("DestroyWindow")
	pSendMessage      = user32dll.NewProc("SendMessageW")
	pPostMessage      = user32dll.NewProc("PostMessageW")
	pShowWindow       = user32dll.NewProc("ShowWindow")
	pSetForeground    = user32dll.NewProc("SetForegroundWindow")
	pSetFocus         = user32dll.NewProc("SetFocus")
	pEnableWindow     = user32dll.NewProc("EnableWindow")
	pGetMessage       = user32dll.NewProc("GetMessageW")
	pTranslateMessage = user32dll.NewProc("TranslateMessage")
	pDispatchMessage  = user32dll.NewProc("DispatchMessageW")
	pIsDialogMessage  = user32dll.NewProc("IsDialogMessageW")
	pPostQuitMessage  = user32dll.NewProc("PostQuitMessage")
	pSetWindowText    = user32dll.NewProc("SetWindowTextW")
	pGetWindowText    = user32dll.NewProc("GetWindowTextW")
	pSetWindowPos     = user32dll.NewProc("SetWindowPos")
	pMoveWindow       = user32dll.NewProc("MoveWindow")
	pGetDPI           = user32dll.NewProc("GetDpiForWindow")
	pAdjustWindowRect = user32dll.NewProc("AdjustWindowRectExForDpi")
	pSetTimer         = user32dll.NewProc("SetTimer")
	pKillTimer        = user32dll.NewProc("KillTimer")
	gdi32dll          = windows.NewLazySystemDLL("gdi32.dll")
	pCreateFont       = gdi32dll.NewProc("CreateFontW")
	pDeleteObject     = gdi32dll.NewProc("DeleteObject")
	nativeWindows     sync.Map // HWND -> *nativeWindow; window data stays on its UI thread.
	nativeRegister    sync.Once
	nativeRegisterErr error
)

type nativeRect struct{ Left, Top, Right, Bottom int32 }
type nativeMessage struct {
	Window         uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	X, Y           int32
	Private        uint32
}
type nativeWindowClass struct {
	Size, Style                        uint32
	Proc                               uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	MenuName, ClassName                *uint16
	SmallIcon                          uintptr
}
type nativeControl struct {
	hwnd                uintptr
	x, y, width, height int
	font                int
	text                string
}
type nativeWindow struct {
	hwnd     uintptr
	dpi      int
	controls []*nativeControl
	fonts    [3]uintptr
	command  func(int)
	tick     func()
	close    func()
	err      error
}

func nativeString(s string) *uint16 {
	// Strings from configs may contain NUL; Windows strings cannot.
	runes := []rune(s)
	for i, r := range runes {
		if r == 0 {
			runes[i] = ' '
		}
	}
	p, _ := windows.UTF16PtrFromString(string(runes))
	return p
}

func nativeWndProc(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	if value, ok := nativeWindows.Load(hwnd); ok {
		w := value.(*nativeWindow)
		switch msg {
		case wmCommand:
			if wparam>>16 == 0 && w.command != nil {
				w.command(int(wparam & 0xffff))
			}
			return 0
		case wmTimer:
			if w.tick != nil {
				w.tick()
			}
			return 0
		case wmClose:
			if w.close != nil {
				w.close()
			} else {
				pDestroyWindow.Call(hwnd)
			}
			return 0
		case wmShowDashboard:
			w.show()
			return 0
		case wmDispose:
			pDestroyWindow.Call(hwnd)
			return 0
		case 0x0002: // WM_DESTROY
			pKillTimer.Call(hwnd, 1)
			pPostQuitMessage.Call(0)
			return 0
		case 0x02e0: // WM_DPICHANGED
			w.dpi = int(wparam & 0xffff)
			w.updateFonts()
			// LPARAM points to a RECT owned by User32 for this callback. Copy it
			// through the native API instead of keeping an integer-derived Go pointer.
			var r nativeRect
			windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlMoveMemory").Call(uintptr(unsafe.Pointer(&r)), lparam, unsafe.Sizeof(r))
			pSetWindowPos.Call(hwnd, 0, uintptr(r.Left), uintptr(r.Top), uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), 0x14)
			w.layout()
			return 0
		}
	}
	r, _, _ := pDefWindowProc.Call(hwnd, uintptr(msg), wparam, lparam)
	return r
}

func newNativeWindow(title string, width, height int, owner uintptr) (*nativeWindow, error) {
	instance, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW").Call(0)
	nativeRegister.Do(func() {
		windows.NewLazySystemDLL("comctl32.dll").NewProc("InitCommonControls").Call()
		cursor, _, _ := user32dll.NewProc("LoadCursorW").Call(0, 32512)
		// With a manifest, goversioninfo assigns icon group ID 2 (manifest ID 1).
		icon, _, _ := user32dll.NewProc("LoadIconW").Call(instance, 2)
		wc := nativeWindowClass{Proc: windows.NewCallback(nativeWndProc), Instance: instance,
			Icon: icon, SmallIcon: icon, Cursor: cursor, Background: 16, ClassName: nativeString(nativeClass)}
		wc.Size = uint32(unsafe.Sizeof(wc))
		r, _, err := user32dll.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&wc)))
		if r == 0 {
			nativeRegisterErr = fmt.Errorf("RegisterClassExW: %w", err)
		}
	})
	if nativeRegisterErr != nil {
		return nil, nativeRegisterErr
	}
	const style = 0x00c80000 | 0x00020000 | 0x02000000 // caption, system menu, minimize, clip children
	hwnd, _, err := pCreateWindow.Call(0, uintptr(unsafe.Pointer(nativeString(nativeClass))), uintptr(unsafe.Pointer(nativeString(title))),
		style, 0x80000000, 0x80000000, uintptr(width), uintptr(height), owner, 0, instance, 0)
	if hwnd == 0 {
		return nil, fmt.Errorf("CreateWindowExW: %w", err)
	}
	dpi, _, _ := pGetDPI.Call(hwnd)
	if dpi == 0 {
		dpi = 96
	}
	w := &nativeWindow{hwnd: hwnd, dpi: int(dpi)}
	nativeWindows.Store(hwnd, w)
	w.updateFonts()
	r := nativeRect{Right: int32(w.scale(width)), Bottom: int32(w.scale(height))}
	pAdjustWindowRect.Call(uintptr(unsafe.Pointer(&r)), style, 0, 0, dpi)
	// Center on the monitor containing the newly created window.
	monitor, _, _ := user32dll.NewProc("MonitorFromWindow").Call(hwnd, 2)
	mi := struct {
		Size          uint32
		Monitor, Work nativeRect
		Flags         uint32
	}{}
	mi.Size = uint32(unsafe.Sizeof(mi))
	if ok, _, _ := user32dll.NewProc("GetMonitorInfoW").Call(monitor, uintptr(unsafe.Pointer(&mi))); ok != 0 {
		x := mi.Work.Left + (mi.Work.Right-mi.Work.Left-(r.Right-r.Left))/2
		y := mi.Work.Top + (mi.Work.Bottom-mi.Work.Top-(r.Bottom-r.Top))/2
		pSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), 0x14)
	}
	return w, nil
}

func (w *nativeWindow) scale(v int) int { return v * w.dpi / 96 }

func (w *nativeWindow) updateFonts() {
	old := w.fonts
	for i, size := range []int{14, 24, 18} {
		weight := uintptr(400)
		if i > 0 {
			weight = 600
		}
		w.fonts[i], _, _ = pCreateFont.Call(uintptr(-w.scale(size)), 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, 0,
			uintptr(unsafe.Pointer(nativeString("Segoe UI"))))
	}
	for _, c := range w.controls {
		pSendMessage.Call(c.hwnd, 0x0030, w.fonts[c.font], 1)
	}
	for _, font := range old {
		if font != 0 {
			pDeleteObject.Call(font)
		}
	}
}

func (w *nativeWindow) add(class, text string, style uintptr, id, x, y, width, height, font int) *nativeControl {
	c := &nativeControl{x: x, y: y, width: width, height: height, font: font, text: text}
	c.hwnd, _, _ = pCreateWindow.Call(0, uintptr(unsafe.Pointer(nativeString(class))), uintptr(unsafe.Pointer(nativeString(text))),
		0x50000000|style, uintptr(w.scale(x)), uintptr(w.scale(y)), uintptr(w.scale(width)), uintptr(w.scale(height)), w.hwnd, uintptr(id), 0, 0)
	if c.hwnd == 0 {
		w.err = fmt.Errorf("не удалось создать элемент %s", class)
	}
	pSendMessage.Call(c.hwnd, 0x0030, w.fonts[font], 1) // WM_SETFONT
	w.controls = append(w.controls, c)
	return c
}

func (w *nativeWindow) label(text string, x, y, width, height, font int) *nativeControl {
	return w.add("STATIC", text, 0x80, 0, x, y, width, height, font) // SS_NOPREFIX
}

func (w *nativeWindow) layout() {
	for _, c := range w.controls {
		pMoveWindow.Call(c.hwnd, uintptr(w.scale(c.x)), uintptr(w.scale(c.y)), uintptr(w.scale(c.width)), uintptr(w.scale(c.height)), 1)
	}
}

func (w *nativeWindow) show() {
	pShowWindow.Call(w.hwnd, 9) // SW_RESTORE also reveals a window hidden to tray.
	pSetForeground.Call(w.hwnd)
	if w.tick != nil {
		w.tick()
	}
}

func (w *nativeWindow) dispose() {
	pDestroyWindow.Call(w.hwnd)
	nativeWindows.Delete(w.hwnd)
	for _, font := range w.fonts {
		if font != 0 {
			pDeleteObject.Call(font)
		}
	}
}

func (w *nativeWindow) run() error {
	if w.err != nil {
		return w.err
	}
	w.show()
	var msg nativeMessage
	for {
		r, _, err := pGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) == -1 {
			return fmt.Errorf("GetMessageW: %w", err)
		}
		if r == 0 {
			return nil
		}
		if handled, _, _ := pIsDialogMessage.Call(w.hwnd, uintptr(unsafe.Pointer(&msg))); handled == 0 {
			pTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			pDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
		}
	}
}

func (c *nativeControl) setText(text string) {
	if c.text == text {
		return
	}
	c.text = text
	pSetWindowText.Call(c.hwnd, uintptr(unsafe.Pointer(nativeString(text))))
}
func (c *nativeControl) enable(enabled bool) {
	var v uintptr
	if enabled {
		v = 1
	}
	pEnableWindow.Call(c.hwnd, v)
}
func (c *nativeControl) check(checked bool) {
	var v uintptr
	if checked {
		v = 1
	}
	pSendMessage.Call(c.hwnd, 0x00f1, v, 0) // BM_SETCHECK
}

// FocusWindow brings the existing instance's dashboard back from the tray.
func FocusWindow() bool {
	hwnd, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(nativeString(nativeClass))), uintptr(unsafe.Pointer(nativeString("WgKeyBot"))))
	if hwnd == 0 {
		return false
	}
	pSetForeground.Call(hwnd)
	pPostMessage.Call(hwnd, wmShowDashboard, 0, 0)
	return true
}
