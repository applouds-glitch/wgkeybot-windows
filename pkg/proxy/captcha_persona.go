/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// The captcha persona: the traits by which VK ties solve attempts to one device
// — browser_fp (and the adFp derived from it) and the height of the browser's
// window. Port of Android CaptchaPersona.kt / iOS captcha_persona.go.
//
// The balance is Android's: a fingerprint that changes on every attempt reads
// as a bot cycling identities, and one that never changes runs into VK's limits
// on one device. Here it never did: browser_fp was drawn once per process, and
// the tray lives for weeks, through every BOT and ERROR_LIMIT VK answered it
// with. So a persona lives one budget — captchaPersonaMaxAttempts attempts or
// captchaPersonaMaxAge, whichever comes first — and is burnt early as soon as
// VK refuses it.
//
// What differs on Windows (Codex consultation 24.10):
//   - What stays across personas is the machine: the screen and the taskbar
//     (captchaMachineViewport), the cores and the memory (captchaHardwareProfile),
//     drawn once per process — a PC's screen does not change between captchas,
//     and it used to change on every one, under the same browser_fp. A persona
//     is the browser: browser_fp, and how much of the screen its chrome takes
//     (toolbars, bookmarks bar), which sets innerHeight — the window height
//     Android varies with its navigation inset. The UA stays the session
//     identity's (vkSessionIdentity): its Chrome major picks the ClientHello.
//   - An attempt is explicit: one captcha VK put up, from the first rung of the
//     solve ladder to its token or its end (getTokenChain, captchaAttempt).
//     Android and iOS take every use within a 3/6-minute window for one attempt;
//     here the WebView2 rung waits for the user with no deadline
//     (RequestCaptcha), and a window would cut an attempt in two. The budget is
//     looked at only when an attempt begins: a persona never changes under a
//     captcha in progress for its age or count.
//   - In memory only: the process outlives the sessions, and a persona has
//     nothing to hand to another process.
//   - A burn names its persona (its generation). Two credential groups may run
//     their HTTP solves at once, and a late BOT of one attempt must burn that
//     attempt's persona, never one minted since for another.
//
// The WebView2 rung is a real browser and shows VK its own traits; nothing here
// reaches it.

const (
	// captchaPersonaMaxAttempts is how many captchas one persona meets (Android
	// MAX_ATTEMPTS).
	captchaPersonaMaxAttempts = 5
	// captchaPersonaMaxAge retires a persona whose attempt budget is not spent
	// yet (Android MAX_AGE_MS).
	captchaPersonaMaxAge = 6 * time.Hour
)

// captchaPersonaChrome is the range of the browser chrome's height in CSS
// pixels: tab strip, toolbar, bookmarks bar. innerHeight is the screen height
// minus this.
const (
	captchaPersonaChromeMin = 111
	captchaPersonaChromeMax = 141
)

// captchaPersona is one generation. The attempts that met it share the object,
// so its burn is seen by all of them and goes with the last of them to the GC —
// a map of burnt generations grew for the life of a process that lives for
// weeks (Codex review 24.10). Its fields change under captchaPersonas' lock;
// everyone else gets copies.
type captchaPersona struct {
	gen       uint64
	browserFp string
	chrome    int // px of browser chrome: innerHeight = screen height - chrome
	createdAt time.Time
	attempts  int
	burned    bool
}

// captchaPersonas holds the persona in force: nil until the first captcha and
// after a burn. burns counts them, for the tests.
var captchaPersonas = struct {
	sync.Mutex
	cur   *captchaPersona
	gen   uint64
	burns uint64
}{}

// captchaPersonaNow is the persona's clock; a test replaces it.
var captchaPersonaNow = time.Now

func randomBrowserFp() string {
	b := make([]byte, 16)
	if _, err := cryptorand.Read(b); err != nil {
		return fmt.Sprintf("%016x%016x", rand.Uint64(), rand.Uint64())
	}
	return hex.EncodeToString(b)
}

func mintCaptchaPersonaLocked(now time.Time) *captchaPersona {
	captchaPersonas.gen++
	p := &captchaPersona{
		gen:       captchaPersonas.gen,
		browserFp: randomBrowserFp(),
		chrome:    captchaPersonaChromeMin + rand.Intn(captchaPersonaChromeMax-captchaPersonaChromeMin+1),
		createdAt: now,
	}
	captchaPersonas.cur = p
	turnLog("[Captcha] New persona #%d: browser chrome %dpx, fp=%.8s", p.gen, p.chrome, p.browserFp)
	return p
}

// captchaAttempt is one captcha VK put up, solved or given up. It keeps the
// persona it began on for every solve of its own.
type captchaAttempt struct {
	p *captchaPersona // under captchaPersonas' lock
}

// beginCaptchaAttempt opens an attempt on the persona in force and spends one
// of its attempts, or on a new persona when the budget or the age is spent.
func beginCaptchaAttempt() *captchaAttempt {
	captchaPersonas.Lock()
	defer captchaPersonas.Unlock()
	now := captchaPersonaNow()
	p := captchaPersonas.cur
	if p != nil {
		// A negative age is a clock moved back: a new persona, not a reason to
		// stretch this one for an unknown time.
		if age := now.Sub(p.createdAt); p.attempts >= captchaPersonaMaxAttempts || age < 0 || age > captchaPersonaMaxAge {
			turnLog("[Captcha] Persona #%d spent (%d attempts, age %v) — rotating", p.gen, p.attempts, age.Round(time.Minute))
			p = nil
		}
	}
	if p == nil {
		p = mintCaptchaPersonaLocked(now)
	}
	p.attempts++
	return &captchaAttempt{p: p}
}

// persona is what the attempt's next solve presents: its own persona, unless VK
// refused it meanwhile — then the one in force, minted if there is none, so the
// attempt's later rungs do not show VK the device it has just refused (Android
// 15e811c7). A captcha session already running keeps the persona it was built
// with (newCaptchaNotRobotSession): the slider after a BOT check is the same
// session, and its fingerprint must not change before getContent.
func (a *captchaAttempt) persona() captchaPersona {
	captchaPersonas.Lock()
	defer captchaPersonas.Unlock()
	if a.p.burned {
		p := captchaPersonas.cur
		if p == nil {
			p = mintCaptchaPersonaLocked(captchaPersonaNow())
		}
		p.attempts++
		a.p = p
	}
	return *a.p
}

// burn retires the attempt's persona: VK refused it — a BOT status, an
// ERROR_LIMIT, the whole ladder unsolved — so whatever is left of its budget is
// of no use. Only that persona: one another attempt has minted since is not
// this verdict's. Safe on a nil attempt.
func (a *captchaAttempt) burn(reason string) {
	if a == nil {
		return
	}
	captchaPersonas.Lock()
	defer captchaPersonas.Unlock()
	if a.p.burned {
		return
	}
	a.p.burned = true
	captchaPersonas.burns++
	if captchaPersonas.cur == a.p {
		captchaPersonas.cur = nil
	}
	turnLog("[Captcha] Burning persona #%d: %s", a.p.gen, reason)
}

type captchaAttemptKey struct{}

// withCaptchaAttempt carries the attempt down to the captcha sessions its
// solves build.
func withCaptchaAttempt(ctx context.Context, a *captchaAttempt) context.Context {
	return context.WithValue(ctx, captchaAttemptKey{}, a)
}

func captchaAttemptOf(ctx context.Context) *captchaAttempt {
	a, _ := ctx.Value(captchaAttemptKey{}).(*captchaAttempt)
	return a
}

// captchaPersonaFor is the persona a captcha session built under ctx presents:
// its attempt's, or — for a solve outside any attempt — the persona in force,
// with no budget spent.
func captchaPersonaFor(ctx context.Context) captchaPersona {
	if a := captchaAttemptOf(ctx); a != nil {
		return a.persona()
	}
	captchaPersonas.Lock()
	defer captchaPersonas.Unlock()
	p := captchaPersonas.cur
	if p == nil {
		p = mintCaptchaPersonaLocked(captchaPersonaNow())
	}
	return *p
}

var (
	captchaMachineOnce sync.Once
	captchaMachine     captchaViewport
)

// captchaMachineViewport is the screen and the taskbar every captcha of this
// process reports, drawn once as the hardware is (captchaHardwareProfile).
func captchaMachineViewport() captchaViewport {
	captchaMachineOnce.Do(func() { captchaMachine = randomViewport() })
	return captchaMachine
}

// captchaViewportFor is the page the persona's browser shows on this machine's
// screen.
func captchaViewportFor(p captchaPersona) captchaViewport {
	vp := captchaMachineViewport()
	vp.InnerHeight = vp.Height - p.chrome
	return vp
}
