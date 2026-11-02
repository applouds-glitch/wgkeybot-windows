/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

// withCaptchaPersonas gives the test an empty persona store on a clock it moves.
func withCaptchaPersonas(t *testing.T) *time.Time {
	t.Helper()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	captchaPersonas.Lock()
	prevCur, prevBurns := captchaPersonas.cur, captchaPersonas.burns
	captchaPersonas.cur, captchaPersonas.burns = nil, 0
	captchaPersonas.Unlock()
	prevNow := captchaPersonaNow
	captchaPersonaNow = func() time.Time { return now }
	t.Cleanup(func() {
		captchaPersonaNow = prevNow
		captchaPersonas.Lock()
		captchaPersonas.cur, captchaPersonas.burns = prevCur, prevBurns
		captchaPersonas.Unlock()
	})
	return &now
}

// Five captchas meet one persona, the sixth a new one (Android MAX_ATTEMPTS).
func TestCaptchaPersonaLivesItsBudget(t *testing.T) {
	withCaptchaPersonas(t)
	first := beginCaptchaAttempt().persona()
	for i := 2; i <= captchaPersonaMaxAttempts; i++ {
		if got := beginCaptchaAttempt().persona(); got.gen != first.gen || got.browserFp != first.browserFp {
			t.Fatalf("attempt %d presented persona #%d, want #%d", i, got.gen, first.gen)
		}
	}
	next := beginCaptchaAttempt().persona()
	if next.gen == first.gen || next.browserFp == first.browserFp {
		t.Fatalf("attempt %d still on persona #%d", captchaPersonaMaxAttempts+1, first.gen)
	}
}

// Past captchaPersonaMaxAge, or on a clock moved back, the next captcha meets a
// new persona.
func TestCaptchaPersonaRetiresWithAgeOrABackwardClock(t *testing.T) {
	now := withCaptchaPersonas(t)
	first := beginCaptchaAttempt().persona()
	*now = now.Add(captchaPersonaMaxAge + time.Minute)
	aged := beginCaptchaAttempt().persona()
	if aged.gen == first.gen {
		t.Fatalf("a persona older than %v met another captcha", captchaPersonaMaxAge)
	}
	*now = now.Add(-time.Hour)
	if back := beginCaptchaAttempt().persona(); back.gen == aged.gen {
		t.Fatal("a clock moved back stretched the persona")
	}
}

// The budget is looked at when an attempt begins, never under one in progress:
// the WebView2 rung waits for the user with no deadline, and another credential
// group may begin its own attempt meanwhile.
func TestCaptchaAttemptKeepsItsPersonaWhileItLasts(t *testing.T) {
	now := withCaptchaPersonas(t)
	for i := 1; i < captchaPersonaMaxAttempts; i++ {
		beginCaptchaAttempt()
	}
	a := beginCaptchaAttempt() // the persona's last attempt
	mine := a.persona()
	other := beginCaptchaAttempt().persona()
	if other.gen == mine.gen {
		t.Fatal("the attempt past the budget did not rotate")
	}
	*now = now.Add(captchaPersonaMaxAge + time.Hour) // the user takes their time
	if got := a.persona(); got.gen != mine.gen || got.browserFp != mine.browserFp {
		t.Fatalf("an attempt in progress moved from persona #%d to #%d", mine.gen, got.gen)
	}
}

// A late verdict burns its own persona only: one minted since for another
// attempt is not its.
func TestCaptchaBurnTakesOnlyItsOwnPersona(t *testing.T) {
	withCaptchaPersonas(t)
	for i := 1; i < captchaPersonaMaxAttempts; i++ {
		beginCaptchaAttempt()
	}
	old := beginCaptchaAttempt()
	fresh := beginCaptchaAttempt() // rotates
	old.burn("BOT")
	if got := fresh.persona(); got.gen == old.p.gen {
		t.Fatal("the attempts shared a persona")
	}
	captchaPersonas.Lock()
	cur := captchaPersonas.cur
	captchaPersonas.Unlock()
	if cur == nil || cur.gen != fresh.p.gen {
		t.Fatalf("burning persona #%d took the one in force away", old.p.gen)
	}
	if got := beginCaptchaAttempt().persona(); got.gen != fresh.p.gen {
		t.Fatalf("the next captcha met persona #%d, want #%d", got.gen, fresh.p.gen)
	}
}

// After VK refused the persona, the attempt's later rungs present a fresh one
// (Android 15e811c7), and the next captcha meets that one too.
func TestABurntAttemptGoesOnUnderAFreshPersona(t *testing.T) {
	withCaptchaPersonas(t)
	a := beginCaptchaAttempt()
	refused := a.persona()
	a.burn("VK returned BOT for this device")
	a.burn("solve ladder exhausted") // a second verdict on the same persona changes nothing
	later := a.persona()
	if later.gen == refused.gen || later.browserFp == refused.browserFp {
		t.Fatal("the attempt kept showing VK the persona it refused")
	}
	if next := beginCaptchaAttempt().persona(); next.gen != later.gen {
		t.Fatalf("the next captcha met persona #%d, want #%d", next.gen, later.gen)
	}
	var none *captchaAttempt
	none.burn("no attempt") // safe
}

// A captcha session presents its attempt's persona: browser_fp, the adFp from
// it, and a page as high as the screen less the persona's browser chrome. The
// screen is the machine's and stays across personas.
func TestCaptchaSessionPresentsItsAttemptsPersona(t *testing.T) {
	withCaptchaPersonas(t)
	ep := captchaEndpointsFromRedirectURI("https://id.vk.ru/captcha?domain=vk.ru")
	var screens []captchaViewport
	for i := 0; i < 2; i++ {
		a := beginCaptchaAttempt()
		p := a.persona()
		s := newCaptchaNotRobotSession(withCaptchaAttempt(context.Background(), a), "token", ep, "hash", "debug", 0, nil, Profile{})
		if s.browserFp != p.browserFp || s.adFp != captchaAdFpFromBrowserFp(p.browserFp) {
			t.Fatalf("session fp=%s adFp=%s, persona fp=%s", s.browserFp, s.adFp, p.browserFp)
		}
		if s.viewport.InnerHeight != s.viewport.Height-p.chrome {
			t.Fatalf("page %d high on a %d screen, persona chrome %d", s.viewport.InnerHeight, s.viewport.Height, p.chrome)
		}
		screens = append(screens, s.viewport)
		a.burn("next persona")
	}
	if screens[0].Width != screens[1].Width || screens[0].Height != screens[1].Height || screens[0].AvailHeight != screens[1].AvailHeight {
		t.Fatalf("the screen changed with the persona: %+v, %+v", screens[0], screens[1])
	}
}

// BOT and ERROR_LIMIT judge the identity presented: the HTTP solve burns its
// attempt's persona on either.
func TestSolveVkCaptchaBurnsThePersonaVKRefused(t *testing.T) {
	for _, verdict := range []string{"BOT", "ERROR_LIMIT"} {
		t.Run(verdict, func(t *testing.T) {
			withCaptchaPersonas(t)
			page := `<html><script>const powInput = "challenge";</script></html>`
			client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
				if r.Method == "GET" {
					return &fhttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(page))}, nil
				}
				switch strings.TrimPrefix(r.URL.Path, "/method/") {
				case "captchaNotRobot.settings":
					return jsonHTTP(`{"response":{"captcha_settings":[]}}`), nil
				case "captchaNotRobot.componentDone":
					return jsonHTTP(`{"response":{"status":"OK"}}`), nil
				case "captchaNotRobot.check":
					return jsonHTTP(`{"response":{"status":"` + verdict + `"}}`), nil
				}
				return nil, errors.New("unexpected request " + r.URL.Path)
			}}
			a := beginCaptchaAttempt()
			gen := a.persona().gen
			captchaErr := &VkCaptchaError{RedirectURI: "https://id.vk.ru/not_robot_captcha?domain=vk.ru&session_token=s", SessionToken: "s"}
			if _, err := solveVkCaptcha(withCaptchaAttempt(context.Background(), a), captchaErr, 0, client, Profile{}, false); err == nil {
				t.Fatal("solved a refused captcha")
			}
			captchaPersonas.Lock()
			burned := a.p.burned && a.p.gen == gen
			captchaPersonas.Unlock()
			if !burned {
				t.Fatalf("%s left persona #%d in force", verdict, gen)
			}
		})
	}
}

// From VK's captcha to the end of the ladder: the HTTP rung presents the
// attempt's persona, a BOT there burns it before the WebView2 rung opens (the
// rung got the attempt), and a ladder that ends unsolved burns it in any case,
// so the next captcha meets a new one.
func TestTokenChainCarriesOnePersonaAndBurnsItWhenTheLadderEnds(t *testing.T) {
	for _, verdict := range []string{"ERROR", "BOT"} {
		t.Run(verdict, func(t *testing.T) {
			withCaptchaPersonas(t)
			t.Cleanup(resetCaptchaLockout)
			const link = "persona-ladder-link"
			t.Cleanup(func() { invalidateCaptchaToken(link) })

			page := `<html><script>const powInput = "challenge";</script></html>`
			var presented, inForce string
			client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
				if r.Method == "GET" {
					return &fhttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(page))}, nil
				}
				raw, _ := io.ReadAll(r.Body)
				switch {
				case r.URL.Host == "login.vk.ru":
					return jsonHTTP(`{"data":{"access_token":"t1"}}`), nil
				case strings.HasSuffix(r.URL.Path, "/calls.getAnonymousToken"):
					return jsonHTTP(`{"error":{"error_code":14,"error_msg":"Captcha needed","redirect_uri":"https://id.vk.ru/not_robot_captcha?domain=vk.ru&session_token=sess","captcha_ts":"1","captcha_attempt":"0"}}`), nil
				case strings.HasSuffix(r.URL.Path, "/captchaNotRobot.settings"):
					return jsonHTTP(`{"response":{"captcha_settings":[]}}`), nil
				case strings.HasSuffix(r.URL.Path, "/captchaNotRobot.componentDone"):
					return jsonHTTP(`{"response":{"status":"OK"}}`), nil
				case strings.HasSuffix(r.URL.Path, "/captchaNotRobot.check"):
					for _, kv := range strings.Split(string(raw), "&") {
						if v, ok := strings.CutPrefix(kv, "browser_fp="); ok {
							presented = v
						}
					}
					captchaPersonas.Lock()
					if captchaPersonas.cur != nil {
						inForce = captchaPersonas.cur.browserFp
					}
					captchaPersonas.Unlock()
					// ERROR is neither BOT nor a limit: only the ladder's end burns.
					return jsonHTTP(`{"response":{"status":"` + verdict + `"}}`), nil
				}
				return nil, errors.New("unexpected request " + r.URL.String())
			}}
			// The WebView2 rung: the user closes the window.
			atWebView := make(chan *captchaPersona, 1)
			go func() {
				for i := 0; i < 3000 && PendingCaptchaURL() == ""; i++ {
					time.Sleep(10 * time.Millisecond)
				}
				captchaPersonas.Lock()
				atWebView <- captchaPersonas.cur
				captchaPersonas.Unlock()
				PublishCaptchaAnswer("")
			}()

			_, _, _, _, err := getTokenChain(context.Background(), link, VKCredentials{ClientID: "1", ClientSecret: "s"}, client, Profile{})
			if !errors.Is(err, errCaptchaUnsolved) {
				t.Fatalf("want the ladder exhausted, got %v", err)
			}
			if presented == "" || presented != inForce {
				t.Fatalf("the HTTP rung presented browser_fp %q, the attempt's persona is %q", presented, inForce)
			}
			if cur := <-atWebView; (cur == nil) != (verdict == "BOT") {
				t.Fatalf("%s: persona in force when the WebView2 rung opened: %v", verdict, cur)
			}
			captchaPersonas.Lock()
			cur, burned := captchaPersonas.cur, captchaPersonas.burns
			captchaPersonas.Unlock()
			if cur != nil || burned != 1 {
				t.Fatalf("after an unsolved ladder: persona in force %v, %d burnt — want none and one", cur, burned)
			}
		})
	}
}

// chainClient is a VK that answers getAnonymousToken with what answer says for
// the n-th call (1-based) and token1 requests with a token. The captcha page is
// not served, so the HTTP rung fails at once — no verdict on the persona — and
// the ladder goes on to the WebView2 rung. cur records the persona in force at
// each getAnonymousToken.
func chainClient(answer func(n int) string, cur *[]*captchaPersona) scriptedHTTPClient {
	n := 0
	return scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		if r.URL.Host == "login.vk.ru" {
			return jsonHTTP(`{"data":{"access_token":"t1"}}`), nil
		}
		if strings.HasSuffix(r.URL.Path, "/calls.getAnonymousToken") {
			n++
			captchaPersonas.Lock()
			*cur = append(*cur, captchaPersonas.cur)
			captchaPersonas.Unlock()
			return jsonHTTP(answer(n)), nil
		}
		return nil, errors.New("unexpected request " + r.URL.String())
	}}
}

const chainCaptcha = `{"error":{"error_code":14,"error_msg":"Captcha needed","redirect_uri":"https://id.vk.ru/not_robot_captcha?domain=vk.ru&session_token=sess","captcha_ts":"1","captcha_attempt":"0"}}`

// answerWebView answers every WebView2 rung with answer until the test ends.
func answerWebView(t *testing.T, answer string) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(5 * time.Millisecond):
			}
			if PendingCaptchaURL() != "" {
				PublishCaptchaAnswer(answer)
			}
		}
	}()
}

func chainCleanup(t *testing.T, link string) {
	t.Cleanup(resetCaptchaLockout)
	t.Cleanup(func() { invalidateCaptchaToken(link) })
}

// A disconnect while the WebView2 window is open reads as an empty answer. It is
// our own teardown, not VK's verdict: no persona burnt, no lockout armed.
func TestACancelledLadderBurnsNoPersona(t *testing.T) {
	withCaptchaPersonas(t)
	const link = "persona-cancel-link"
	chainCleanup(t, link)
	var seen []*captchaPersona
	client := chainClient(func(int) string { return chainCaptcha }, &seen)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for i := 0; i < 3000 && PendingCaptchaURL() == ""; i++ {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	_, _, _, _, err := getTokenChain(ctx, link, VKCredentials{ClientID: "1", ClientSecret: "s"}, client, Profile{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want the cancellation back, got %v", err)
	}
	captchaPersonas.Lock()
	cur, burns := captchaPersonas.cur, captchaPersonas.burns
	captchaPersonas.Unlock()
	if burns != 0 || cur == nil {
		t.Fatalf("a cancelled ladder burnt %d persona(s), persona in force %v", burns, cur)
	}
	if left := captchaLockoutRemaining(); left != 0 {
		t.Fatalf("a cancelled ladder armed a %v lockout", left)
	}
}

// Error 10 between the HTTP rung and the WebView2 rung restarts the ladder on a
// fresh captcha: an attempt of its own, which spends the budget — the old one
// went on, and a sixth captcha met a spent persona (Codex review 24.10).
func TestErrorTenBetweenRungsBeginsANewAttempt(t *testing.T) {
	withCaptchaPersonas(t)
	const link = "persona-error10-link"
	chainCleanup(t, link)
	answerWebView(t, "")
	var seen []*captchaPersona
	client := chainClient(func(n int) string {
		if n == 2 {
			return `{"error":{"error_code":10,"error_msg":"Internal server error"}}`
		}
		return chainCaptcha
	}, &seen)
	_, _, _, _, err := getTokenChain(context.Background(), link, VKCredentials{ClientID: "1", ClientSecret: "s"}, client, Profile{})
	if !errors.Is(err, errCaptchaUnsolved) {
		t.Fatalf("want the ladder exhausted, got %v", err)
	}
	p := seen[len(seen)-1]
	captchaPersonas.Lock()
	attempts := p.attempts
	captchaPersonas.Unlock()
	if attempts != 2 {
		t.Fatalf("the captchas before and after error 10 spent %d attempt(s), want 2", attempts)
	}
}

// VK answers every token with another captcha until the chain's bound. The
// persona burnt is the one whose token VK refused last — not the one minted for
// the last captcha, whose token VK never saw (Codex review 24.10).
func TestAChainThatDoesNotConvergeBurnsTheRefusedPersona(t *testing.T) {
	withCaptchaPersonas(t)
	const link = "persona-chain-link"
	chainCleanup(t, link)
	answerWebView(t, "tok")
	beginCaptchaAttempt() // the persona met a captcha before this chain
	var seen []*captchaPersona
	client := chainClient(func(int) string { return chainCaptcha }, &seen)
	_, _, _, _, err := getTokenChain(context.Background(), link, VKCredentials{ClientID: "1", ClientSecret: "s"}, client, Profile{})
	if !errors.Is(err, errCaptchaUnsolved) {
		t.Fatalf("want the chain given up, got %v", err)
	}
	captchaPersonas.Lock()
	cur, burns := captchaPersonas.cur, captchaPersonas.burns
	var first *captchaPersona
	if len(seen) > 1 {
		first = seen[1]
	}
	firstBurned := first != nil && first.burned
	curGen, curBurned := uint64(0), false
	if cur != nil {
		curGen, curBurned = cur.gen, cur.burned
	}
	captchaPersonas.Unlock()
	if cur == nil || curGen == 1 || curBurned || !firstBurned || burns != 1 {
		t.Fatalf("persona in force #%d (burnt %v), first persona burnt %v, %d burn(s) — want #2 in force, #1 burnt, one burn",
			curGen, curBurned, firstBurned, burns)
	}
}
