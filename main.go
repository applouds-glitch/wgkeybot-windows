//go:build windows

package main

import (
	"errors"
	"os"

	"github.com/getlantern/systray"
	"github.com/wgkeybot/windows/tray"
	"golang.org/x/sys/windows"
)

func main() {
	// Prevent multiple instances via named mutex.
	name, _ := windows.UTF16PtrFromString("WgKeyBot_SingleInstance")
	handle, err := windows.CreateMutex(nil, false, name)
	if handle == 0 {
		os.Exit(1)
	}
	defer windows.CloseHandle(handle)

	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if !tray.FocusWindow() {
			showAlreadyRunning()
		}
		os.Exit(0)
	}

	debug := false
	for _, arg := range os.Args[1:] {
		if arg == "--debug" || arg == "-debug" {
			debug = true
		}
	}

	app := tray.New(debug)
	systray.Run(app.OnReady, app.OnExit)
}

func showAlreadyRunning() {
	caption, _ := windows.UTF16PtrFromString("WgKeyBot")
	text, _ := windows.UTF16PtrFromString("Приложение уже запущено.\nПроверьте значок в области уведомлений (трее).")
	windows.MessageBox(0, text, caption, 0x00000040|0x00040000) // MB_ICONINFORMATION | MB_SYSTEMMODAL
}
