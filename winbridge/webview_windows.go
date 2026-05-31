package winbridge

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync/atomic"
	"time"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

// autoClickJS auto-clicks the "I'm not a robot" checkbox while the window is
// still hidden, mirroring the Android invisible-WebView flow. It polls the top
// document for the checkbox, and:
//   - if a slider puzzle is present (or appears after the click), it asks Go to
//     reveal the window via wgkReveal so the user can solve it manually;
//   - otherwise it clicks the checkbox (a plain el.click(); this is an
//     isTrusted=false event, which VK may accept for the checkbox — if it does
//     not, the slider/timeout path reveals the window for a manual solve).
const autoClickJS = `
(function() {
    if (window.top !== window.self) return; // top frame only
    var done = false;
    function slider() {
        return document.querySelector(
            '[class*="SliderCaptcha"],[class*="Kaleidoscope"],' +
            '.vkc__SliderCaptcha-module__description,' +
            '.vkc__KaleidoscopeScreen-module__captchaId,' +
            '.vkc__SwipeButton-module__track'
        );
    }
    function checkbox() {
        return document.querySelector('label.vkc__Checkbox-module__Checkbox')
            || document.querySelector('label[for="not-robot-captcha-checkbox"]')
            || document.getElementById('not-robot-captcha-checkbox');
    }
    function reveal() { if (window.wgkReveal) { try { window.wgkReveal(); } catch (e) {} } }
    function watchSlider() {
        var t = 0;
        var iv2 = setInterval(function() {
            t++;
            if (slider()) { clearInterval(iv2); reveal(); }
            else if (t > 30) { clearInterval(iv2); }
        }, 400);
    }
    function tick() {
        if (done) return;
        if (slider()) { done = true; reveal(); return; }
        var el = checkbox();
        if (!el) return;
        var r = el.getBoundingClientRect();
        var st = window.getComputedStyle(el);
        if (r.width < 5 || r.height < 5 || st.display === 'none' || st.visibility === 'hidden') return;
        done = true;
        var think = 600 + Math.random() * 1000;
        setTimeout(function() { try { el.click(); } catch (e) {} watchSlider(); }, think);
    }
    var n = 0;
    var iv = setInterval(function() { n++; tick(); if (done || n > 60) clearInterval(iv); }, 300);
})();
`

// presentCaptcha shows the captcha page (served by the local reverse proxy) and
// blocks until the success_token is intercepted, ctx is cancelled, or the user
// closes the window.
//
// It prefers an embedded WebView2 window: WebView2 has no browser extensions, so
// ad blockers / privacy extensions cannot block the captcha resources, and it
// runs in-process so the local proxy stays alive for the window's whole
// lifetime. The window starts hidden and auto-clicks the checkbox; it is only
// revealed if the captcha needs manual interaction. If the WebView2 runtime is
// unavailable it falls back to the system browser.
func presentCaptcha(ctx context.Context, localOrigin string, tokenCh <-chan string) (string, error) {
	if token, ok := showCaptchaWindow(ctx, localOrigin, tokenCh); ok {
		if token != "" {
			log.Printf("[Captcha] Token intercepted via WebView2 (%d bytes)", len(token))
			return token, nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("captcha window closed without token")
	}

	// Fallback: system browser (subject to ad-blocker extensions).
	log.Printf("[Captcha] WebView2 unavailable — falling back to system browser")
	if err := openBrowser(localOrigin); err != nil {
		log.Printf("[Captcha] Cannot open browser: %v", err)
	}
	select {
	case token := <-tokenCh:
		log.Printf("[Captcha] Token intercepted via browser (%d bytes)", len(token))
		return token, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// revealFallbackDelay is how long the hidden auto-click attempt runs before the
// window is revealed for manual solving (in case the click was silently
// rejected without producing a slider).
const revealFallbackDelay = 12 * time.Second

// showCaptchaWindow opens the captcha page in an embedded WebView2 window that
// starts off-screen (rendered but invisible). Injected JS auto-clicks the
// checkbox; the window is moved on-screen and focused only if a slider appears
// or the invisible attempt does not produce a token in time. Runs the Win32
// message loop until the token arrives, ctx is cancelled, or the user closes
// the window. Returns ok=false if WebView2 could not be created.
//
// WebView2 requires the message loop to run on a single OS thread, hence
// LockOSThread for the duration of the call.
func showCaptchaWindow(ctx context.Context, localOrigin string, tokenCh <-chan string) (token string, ok bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Captcha] WebView2 init panic: %v — falling back", r)
			token, ok = "", false
		}
	}()

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "WgKeyBot — Captcha",
			Width:  480,
			Height: 640,
			Center: false, // positioned manually (off-screen first)
		},
	})
	if w == nil {
		return "", false
	}
	hwnd := uintptr(w.Window())

	// Render the page without showing it: park the window off-screen.
	moveWindowOffscreen(hwnd)

	var revealed int32
	reveal := func() {
		if atomic.CompareAndSwapInt32(&revealed, 0, 1) {
			w.Dispatch(func() {
				log.Printf("[Captcha] Revealing captcha window for manual solve")
				centerAndShowWindow(hwnd)
			})
		}
	}
	_ = w.Bind("wgkReveal", func() { reveal() })
	w.Init(autoClickJS)

	out := make(chan string, 1)
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		select {
		case t := <-tokenCh:
			out <- t
		case <-watchCtx.Done():
			out <- ""
		}
		// PostMessage(WM_CLOSE) is thread-safe; it closes the window which ends
		// Run() via the WM_DESTROY → Terminate path in the library's wndproc.
		w.Destroy()
	}()

	// If the invisible attempt neither solves nor triggers a slider, reveal the
	// window so the user is not stuck behind an invisible captcha.
	go func() {
		select {
		case <-time.After(revealFallbackDelay):
			reveal()
		case <-watchCtx.Done():
		}
	}()

	w.Navigate(localOrigin)
	w.Run() // blocks on the message loop until the window closes

	cancel() // unblock the watcher if the user closed the window manually
	return <-out, true
}

// ── Win32 window helpers ────────────────────────────────────────────────────────

const (
	swpNoSize     = 0x0001
	swpNoZOrder   = 0x0004
	swpNoActivate = 0x0010
	swpShowWindow = 0x0040
	swShow        = 5
	smCXScreen    = 0
	smCYScreen    = 1
	captchaWinW   = 480
	captchaWinH   = 640
)

// moveWindowOffscreen parks the (already shown) window far off-screen so the
// WebView keeps rendering and running scripts without being visible.
func moveWindowOffscreen(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	setWindowPos := user32.NewProc("SetWindowPos")
	_, _, _ = setWindowPos.Call(hwnd, 0, ^uintptr(31999), ^uintptr(31999), 0, 0,
		swpNoSize|swpNoZOrder|swpNoActivate) // x=y=-32000
}

// centerAndShowWindow moves the window to the center of the primary monitor,
// shows it, and brings it to the foreground.
func centerAndShowWindow(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	setWindowPos := user32.NewProc("SetWindowPos")
	showWindow := user32.NewProc("ShowWindow")
	getSystemMetrics := user32.NewProc("GetSystemMetrics")

	sw, _, _ := getSystemMetrics.Call(smCXScreen)
	sh, _, _ := getSystemMetrics.Call(smCYScreen)
	x := (int(sw) - captchaWinW) / 2
	y := (int(sh) - captchaWinH) / 2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}

	_, _, _ = setWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), captchaWinW, captchaWinH, swpNoZOrder|swpShowWindow)
	_, _, _ = showWindow.Call(hwnd, swShow)
	bringToForeground(hwnd)
}

// bringToForeground forces the captcha window to the front and gives it focus.
// SetForegroundWindow alone is unreliable due to Windows' focus-stealing lock,
// so we briefly attach to the foreground thread's input queue and also do a
// topmost toggle to jump above other windows (without staying on top).
func bringToForeground(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	showWindow := user32.NewProc("ShowWindow")
	setForegroundWindow := user32.NewProc("SetForegroundWindow")
	bringWindowToTop := user32.NewProc("BringWindowToTop")
	setWindowPos := user32.NewProc("SetWindowPos")
	getForegroundWindow := user32.NewProc("GetForegroundWindow")
	getWindowThreadProcessId := user32.NewProc("GetWindowThreadProcessId")
	attachThreadInput := user32.NewProc("AttachThreadInput")
	getCurrentThreadId := kernel32.NewProc("GetCurrentThreadId")

	const (
		swRestore     = 9
		hwndTopmost   = ^uintptr(0) // (HWND)-1
		hwndNoTopmost = ^uintptr(1) // (HWND)-2
		swpNoMove     = 0x0002
	)

	_, _, _ = showWindow.Call(hwnd, swRestore)

	// Jump above other windows, then drop the always-on-top flag again.
	_, _, _ = setWindowPos.Call(hwnd, hwndTopmost, 0, 0, 0, 0, swpNoMove|swpNoSize|swpShowWindow)
	_, _, _ = setWindowPos.Call(hwnd, hwndNoTopmost, 0, 0, 0, 0, swpNoMove|swpNoSize|swpShowWindow)

	fg, _, _ := getForegroundWindow.Call()
	myTID, _, _ := getCurrentThreadId.Call()
	fgTID, _, _ := getWindowThreadProcessId.Call(fg, 0)
	if fg != 0 && fgTID != 0 && fgTID != myTID {
		_, _, _ = attachThreadInput.Call(myTID, fgTID, 1)
		_, _, _ = setForegroundWindow.Call(hwnd)
		_, _, _ = bringWindowToTop.Call(hwnd)
		_, _, _ = attachThreadInput.Call(myTID, fgTID, 0)
	} else {
		_, _, _ = setForegroundWindow.Call(hwnd)
		_, _, _ = bringWindowToTop.Call(hwnd)
	}
}
