/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"errors"
	fhttp "github.com/bogdanfinn/fhttp"
	"io"
	"net/url"
	"strings"
	"testing"
)

func TestCaptchaBFFBootstrapMetadataIsBoundedToVKGlobal(t *testing.T) {
	const id = "12345678-1234-1234-1234-123456789abc"
	page := `<script>window.vk = {api: '{"nested":"}"}', lang: 3, renamed_key: "` + id + `"}; window.lang={foo:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}; const powInput = "challenge";</script>`
	got, err := parseCaptchaBootstrapHTML(page)
	if err != nil || !got.IsBFF || got.DebugInfo != id || got.Lang != "3" {
		t.Fatalf("bootstrap=%+v err=%v", got, err)
	}
	old, err := parseCaptchaBootstrapHTML(`<script>const powInput = "challenge"; window.lang={foo:"` + id + `"};</script>`)
	if err != nil || old.IsBFF || old.DebugInfo != "" {
		t.Fatalf("legacy=%+v err=%v", old, err)
	}
	if block := captchaVKGlobal(`window.vk={key:"unterminated`); block != "" {
		t.Fatal("accepted malformed block")
	}
}

func TestCaptchaBFFSessionSequenceAndCheckFields(t *testing.T) {
	var methods []string
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		method := strings.TrimPrefix(r.URL.Path, "/method/")
		methods = append(methods, method)
		raw, _ := io.ReadAll(r.Body)
		values, err := url.ParseQuery(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		if values.Get("session_token") != "session" || values.Get("domain") != "vk.ru" {
			t.Fatal("session changed")
		}
		switch method {
		case "captchaNotRobot.initSession":
			if string(raw) != "session_token=session&domain=vk.ru&lang=3&access_token=" {
				t.Fatalf("init body: %s", raw)
			}
			return jsonHTTP(`{"response":{"show_captcha_type":"slider","content_settings":[{"type":"slider","settings_key":"opaque-key","settings":"stale"}]}}`), nil
		case "captchaNotRobot.settings":
			// A conflicting value for the same type: initSession's key must win
			// (Codex review 24.10 — an empty list let a swapped merge pass).
			return jsonHTTP(`{"response":{"captcha_settings":[{"type":"slider","settings":"from-settings"}]}}`), nil
		case "captchaNotRobot.componentDone":
			return jsonHTTP(`{"response":{"status":"OK"}}`), nil
		case "captchaNotRobot.check":
			if values.Get("debug_info") != "page-uuid" || values.Has("connectionRtt") || values.Has("connectionDownlink") {
				t.Fatalf("BFF fields mismatch")
			}
			return jsonHTTP(`{"response":{"status":"BOT"}}`), nil
		case "captchaNotRobot.getContent":
			if values.Get("captcha_settings") != "opaque-key" {
				t.Fatalf("lost initSession settings_key: %s", values.Get("captcha_settings"))
			}
			return jsonHTTP(`{"response":{"status":"ERROR_LIMIT"}}`), nil
		}
		t.Fatalf("unexpected request %s", method)
		return nil, nil
	}}
	_, err := callCaptchaNotRobotWithSliderPOC(context.Background(), "session", "hash", "page-uuid", 0, client, Profile{}, nil, captchaEndpointsFromRedirectURI("https://vk.ru/captcha"), &captchaBootstrap{IsBFF: true, Lang: "3"})
	if !errors.Is(err, errCaptchaRateLimit) {
		t.Fatalf("expected getContent limit: %v", err)
	}
	want := "captchaNotRobot.initSession,captchaNotRobot.settings,captchaNotRobot.componentDone,captchaNotRobot.check,captchaNotRobot.getContent"
	if strings.Join(methods, ",") != want {
		t.Fatalf("sequence: %v", methods)
	}
}

func TestCaptchaInitSessionRejectsErrorAndLegacyKeepsNetworkFields(t *testing.T) {
	for _, body := range []string{`{"error":{"error_code":100}}`, `{"response":{"status":"ERROR_LIMIT"}}`} {
		client := scriptedHTTPClient{do: func(*fhttp.Request) (*fhttp.Response, error) { return jsonHTTP(body), nil }}
		s := newCaptchaNotRobotSession(context.Background(), "token", captchaEndpointsFromRedirectURI("https://vk.com/captcha"), "hash", "debug", 0, client, Profile{})
		if _, err := s.requestInitSession(""); err == nil {
			t.Fatal("accepted initSession failure")
		}
	}
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		raw, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(raw))
		if !v.Has("connectionRtt") || !v.Has("connectionDownlink") {
			t.Fatal("legacy check fields removed")
		}
		return jsonHTTP(`{"response":{"status":"OK","success_token":"ok"}}`), nil
	}}
	s := newCaptchaNotRobotSession(context.Background(), "token", captchaEndpointsFromRedirectURI("https://vk.com/captcha"), "hash", "debug", 0, client, Profile{})
	if _, err := s.requestCheckboxCheck(); err != nil {
		t.Fatal(err)
	}
}

// initSession of a live BFF session declares slider and sound in
// content_settings even when show_captcha_type is checkbox, and the checkbox
// passes: no getContent, one initSession, one check (Codex review 24.10).
func TestCaptchaBFFCheckboxPassingNeedsNoContent(t *testing.T) {
	counts := map[string]int{}
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		method := strings.TrimPrefix(r.URL.Path, "/method/")
		counts[method]++
		switch method {
		case "captchaNotRobot.initSession":
			return jsonHTTP(`{"response":{"show_captcha_type":"checkbox","content_settings":[{"type":"slider","settings_key":"k1"},{"type":"sound","settings_key":"k2"}]}}`), nil
		case "captchaNotRobot.settings":
			return jsonHTTP(`{"response":{"captcha_settings":[]}}`), nil
		case "captchaNotRobot.componentDone", "captchaNotRobot.endSession":
			return jsonHTTP(`{"response":{"status":"OK"}}`), nil
		case "captchaNotRobot.check":
			return jsonHTTP(`{"response":{"status":"OK","success_token":"ok"}}`), nil
		}
		t.Fatalf("unexpected request %s", method)
		return nil, nil
	}}
	token, err := callCaptchaNotRobotWithSliderPOC(context.Background(), "session", "hash", "page-uuid", 0, client, Profile{}, nil, captchaEndpointsFromRedirectURI("https://vk.ru/captcha"), &captchaBootstrap{IsBFF: true})
	if err != nil || token != "ok" {
		t.Fatalf("token=%q err=%v", token, err)
	}
	if counts["captchaNotRobot.initSession"] != 1 || counts["captchaNotRobot.check"] != 1 || counts["captchaNotRobot.getContent"] != 0 {
		t.Fatalf("requests: %v", counts)
	}
}

// From the page to the token: a BFF page routes even a captcha with no slider
// advertised through the session solver, which opens with initSession, and the
// check carries the debug_info of the page's window.vk, not the fallback.
func TestSolveVkCaptchaTakesTheBFFPath(t *testing.T) {
	const id = "12345678-1234-1234-1234-123456789abc"
	page := `<html><script>window.vk = {lang: 0, k9: "` + id + `"};</script><script>const powInput = "challenge";</script></html>`
	var methods []string
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		if r.Method == "GET" {
			return &fhttp.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(page))}, nil
		}
		method := strings.TrimPrefix(r.URL.Path, "/method/")
		methods = append(methods, method)
		raw, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(raw))
		switch method {
		case "captchaNotRobot.initSession", "captchaNotRobot.settings":
			return jsonHTTP(`{"response":{"captcha_settings":[]}}`), nil
		case "captchaNotRobot.componentDone", "captchaNotRobot.endSession":
			return jsonHTTP(`{"response":{"status":"OK"}}`), nil
		case "captchaNotRobot.check":
			if values.Get("debug_info") != id || values.Has("connectionRtt") {
				t.Errorf("check: debug_info=%q connectionRtt=%v", values.Get("debug_info"), values.Has("connectionRtt"))
			}
			return jsonHTTP(`{"response":{"status":"OK","success_token":"ok"}}`), nil
		}
		t.Fatalf("unexpected request %s", method)
		return nil, nil
	}}
	captchaErr := &VkCaptchaError{RedirectURI: "https://id.vk.ru/not_robot_captcha?domain=vk.ru&session_token=session", SessionToken: "session"}
	token, err := solveVkCaptchaOnce(context.Background(), captchaErr, 0, client, Profile{}, false)
	if err != nil || token != "ok" {
		t.Fatalf("token=%q err=%v", token, err)
	}
	if len(methods) == 0 || methods[0] != "captchaNotRobot.initSession" {
		t.Fatalf("sequence: %v", methods)
	}
}
