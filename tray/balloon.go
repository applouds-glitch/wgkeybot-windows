//go:build windows

package tray

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	niifInfo    = 0x00000001
	niifWarning = 0x00000002
	niifError   = 0x00000003
	niifNosound = 0x00000010

	nimModify     = 0x00000001
	nimSetVersion = 0x00000004
	nifInfo       = 0x00000010

	notifIconVersion4 = 0x4
)

// notifyData mirrors NOTIFYICONDATAW (shellapi.h).
type notifyData struct {
	CbSize                        uint32
	HWnd                          windows.Handle
	UID, UFlags, UCallbackMessage uint32
	HIcon                         windows.Handle
	SzTip                         [128]uint16
	DwState, DwStateMask          uint32
	SzInfo                        [256]uint16
	UTimeout                      uint32
	SzInfoTitle                   [64]uint16
	DwInfoFlags                   uint32
	GuidItem                      windows.GUID
	HBalloonIcon                  windows.Handle
}

var (
	shell32dll    = windows.NewLazySystemDLL("shell32.dll")
	user32dll     = windows.NewLazySystemDLL("user32.dll")
	pShellNotifyW = shell32dll.NewProc("Shell_NotifyIconW")
	pFindWindowW  = user32dll.NewProc("FindWindowW")
)

// SetNotifyIconVersion4 уведомляет Windows что приложение поддерживает
// NOTIFYICON_VERSION_4. Это подавляет автоматический баллун при первом
// появлении иконки в трее (Windows 10/11).
func SetNotifyIconVersion4() {
	hwnd := systrayHWnd()
	if hwnd == 0 {
		return
	}
	nid := notifyData{
		HWnd:     hwnd,
		UID:      100,
		UTimeout: notifIconVersion4,
	}
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	pShellNotifyW.Call(uintptr(nimSetVersion), uintptr(unsafe.Pointer(&nid)))
}

// Notify shows a balloon tip using the existing systray tray icon.
// On Windows 10/11 balloon tips are displayed as toast notifications.
func Notify(title, msg string, infoFlags uint32) {
	hwnd := systrayHWnd()
	if hwnd == 0 {
		return
	}
	nid := notifyData{
		HWnd:        hwnd,
		UID:         100, // systray registers its icon with ID=100
		UFlags:      nifInfo,
		DwInfoFlags: infoFlags | niifNosound,
	}
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	copyStr16(nid.SzInfoTitle[:], title)
	copyStr16(nid.SzInfo[:], msg)
	pShellNotifyW.Call(uintptr(nimModify), uintptr(unsafe.Pointer(&nid)))
}

// systrayHWnd finds the hidden window that getlantern/systray created.
// It registers its window class as "SystrayClass".
func systrayHWnd() windows.Handle {
	cls, _ := windows.UTF16PtrFromString("SystrayClass")
	hwnd, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(cls)), 0)
	return windows.Handle(hwnd)
}

func copyStr16(dst []uint16, s string) {
	src := windows.StringToUTF16(s)
	n := copy(dst, src)
	if n < len(dst) {
		dst[n] = 0
	}
}
