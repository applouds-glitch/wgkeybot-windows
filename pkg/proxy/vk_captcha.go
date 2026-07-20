/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	neturl "net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/kiper292/tls-client"
)

// errSliderDetected signals that the settings response advertised a slider
// captcha, so the HTTP/checkbox path cannot solve it and a slider-aware
// solver (slider POC or WebView) must run instead.
var errSliderDetected = errors.New("slider_detected")

// errCaptchaBot is returned when the VK API responds with status "bot" on a
// checkbox check, signalling the account looks automated and a harder
// challenge (slider) should be tried instead.
var errCaptchaBot = errors.New("captcha_bot")

// errCaptchaRateLimit is returned when VK throttles the captcha endpoint
// (check or getContent status ERROR_LIMIT). A generic ERROR is kept distinct:
// it may indicate an invalid captcha state or request rather than throttling. The
// session is spent: retrying or escalating to another auto solver only burns
// more requests and digs the rate-limit hole deeper, so callers must stop
// hammering and fall back to the WebView instead.
var errCaptchaRateLimit = errors.New("captcha_rate_limit")

// isCaptchaSessionExhausted reports whether err means VK has throttled the
// captcha session (so further auto attempts are pointless). It matches the
// sentinel as well as the wrapped error strings the slider/checkbox paths
// produce, since those wrap the underlying status into fmt.Errorf chains.
func isCaptchaSessionExhausted(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errCaptchaRateLimit) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "error_limit") ||
		strings.Contains(msg, "captcha_rate_limit") ||
		strings.Contains(msg, "rate limit")
}

// captchaDebugInfoCache caches debug_info strings keyed by script URL so we
// only fetch the JS once per unique script version.
var captchaDebugInfoCache sync.Map

var (
	reCaptchaScriptSrc = regexp.MustCompile(`src="(https://[^"]+not_robot_captcha[^"]+)"`)
	reCaptchaDebugInfo = regexp.MustCompile(`debug_info:(?:[^"]*\|\|)?"([a-fA-F0-9]{64})"`)
)

// captchaHeaderOrder mirrors a real Chrome HTTP/2 header order so VK's bot
// detector sees a plausible browser fingerprint.
var captchaHeaderOrder = []string{
	"host", "content-length", "sec-ch-ua-platform", "accept-language",
	"sec-ch-ua", "content-type", "sec-ch-ua-mobile", "user-agent",
	"accept", "origin", "sec-fetch-site", "sec-fetch-mode",
	"sec-fetch-dest", "referer", "accept-encoding", "priority",
}
var captchaPHeaderOrder = []string{":method", ":path", ":authority", ":scheme"}

const captchaNotRobotAPIVersion = "5.131"

var captchaFormFieldOrder = map[string][]string{
	"captchaNotRobot.settings": {
		"session_token", "domain", "adFp", "access_token",
	},
	"captchaNotRobot.componentDone": {
		"session_token", "domain", "adFp", "browser_fp", "device", "access_token",
	},
	"captchaNotRobot.check": {
		"session_token", "domain", "adFp", "accelerometer", "gyroscope", "motion",
		"cursor", "taps", "connectionRtt", "connectionDownlink", "browser_fp",
		"hash", "answer", "debug_info", "access_token",
	},
	"captchaNotRobot.getContent": {
		"session_token", "domain", "adFp", "captcha_settings", "access_token",
	},
	"captchaNotRobot.endSession": {
		"session_token", "domain", "adFp", "access_token",
	},
}

// encodeCaptchaForm preserves the field order emitted by the VK captcha page.
// net/url.Values.Encode sorts keys alphabetically, which does not match the
// captured browser requests and creates an avoidable fingerprint difference.
func encodeCaptchaForm(method string, values neturl.Values) string {
	orderedKeys := captchaFormFieldOrder[method]
	seen := make(map[string]bool, len(values))
	parts := make([]string, 0, len(values))
	appendKey := func(key string) {
		for _, value := range values[key] {
			parts = append(parts, neturl.QueryEscape(key)+"="+neturl.QueryEscape(value))
		}
		seen[key] = true
	}
	for _, key := range orderedKeys {
		if _, ok := values[key]; ok {
			appendKey(key)
		}
	}
	remaining := make([]string, 0, len(values)-len(seen))
	for key := range values {
		if !seen[key] {
			remaining = append(remaining, key)
		}
	}
	sort.Strings(remaining)
	for _, key := range remaining {
		appendKey(key)
	}
	return strings.Join(parts, "&")
}

type VkCaptchaError struct {
	ErrorCode               int
	ErrorMsg                string
	CaptchaSid              string
	CaptchaImg              string
	RedirectURI             string
	IsSoundCaptchaAvailable bool
	SessionToken            string
	CaptchaTs               string
	CaptchaAttempt          string
}

func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	// Extract error_code
	codeFloat, ok := errData["error_code"].(float64)
	if !ok {
		turnLog("missing error_code in captcha error data")
		return nil
	}
	code := int(codeFloat)

	// Extract redirect_uri
	RedirectURI, ok := errData["redirect_uri"].(string)
	if !ok {
		turnLog("missing redirect_uri in captcha error data")
		return nil
	}

	// Extract captcha_sid (legacy image-captcha field). VK's modern
	// not_robot_captcha flow (error_code:14 + redirect_uri/session_token) no
	// longer sends it, so its absence must NOT fail the parse — the solve path
	// keys off redirect_uri/session_token, not the sid.
	captchaSid, ok := errData["captcha_sid"].(string)
	if !ok {
		// try numeric, otherwise leave empty (modern flow)
		if sidNum, ok2 := errData["captcha_sid"].(float64); ok2 {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		}
	}

	// Extract captcha_img (legacy image-captcha field; optional, see above).
	captchaImg, _ := errData["captcha_img"].(string)

	// Extract error_msg
	errorMsg, ok := errData["error_msg"].(string)
	if !ok {
		turnLog("missing error_msg in captcha error data")
		return nil
	}

	// Extract session token if redirect_uri present
	var sessionToken string
	if RedirectURI != "" {
		if parsed, err := neturl.Parse(RedirectURI); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		} else {
			turnLog("failed to parse redirect_uri: %v", err)
			return nil
		}
	}

	// Extract is_sound_captcha_available
	isSound, ok := errData["is_sound_captcha_available"].(bool)
	if !ok {
		isSound = false
	}

	// Extract captcha_ts
	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	// Extract captcha_attempt
	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	// Build VkCaptchaError
	return &VkCaptchaError{
		ErrorCode:               code,
		ErrorMsg:                errorMsg,
		CaptchaSid:              captchaSid,
		CaptchaImg:              captchaImg,
		RedirectURI:             RedirectURI,
		IsSoundCaptchaAvailable: isSound,
		SessionToken:            sessionToken,
		CaptchaTs:               captchaTs,
		CaptchaAttempt:          captchaAttempt,
	}
}

func (e *VkCaptchaError) IsCaptchaError() bool {
	return e.ErrorCode == 14 && e.RedirectURI != "" && e.SessionToken != ""
}

// captchaMutex serializes captcha solving to avoid multiple concurrent attempts
var captchaMutex sync.Mutex

/*
// solveVkCaptcha solves the VK Not Robot Captcha and returns success_token
// First tries automatic solution, falls back to WebView if it fails
func solveVkCaptcha(ctx context.Context, streamID int, client tlsclient.HttpClient, profile Profile, captchaErr *VkCaptchaError) (string, error) {
	// Serialize captcha solving to avoid multiple concurrent attempts
	captchaMutex.Lock()
	defer captchaMutex.Unlock()

	turnLog("[Captcha] Solving Not Robot Captcha...")

	// Step 1: Try automatic solution
	turnLog("[Captcha] Attempting automatic solution...")
	successToken, err := solveVkCaptchaAutomatic(ctx, streamID, client, profile, captchaErr)
	if err == nil && successToken != "" {
		turnLog("[Captcha] Automatic solution SUCCESS!")
		return successToken, nil
	}

	turnLog("[Captcha] Automatic solution FAILED: %v", err)
	turnLog("[Captcha] Falling back to WebView...")

	// Step 2: Fall back to manual captcha solving via host app.
	turnLog("[Captcha] Opening captcha for manual solving...")
	successToken = RequestCaptcha(captchaErr.RedirectUri)
	if successToken == "" {
		return "", fmt.Errorf("WebView captcha solving failed: returned empty token")
	}

	turnLog("[Captcha] WebView solution SUCCESS! Got success_token")
	return successToken, nil
}

// solveVkCaptchaAutomatic performs the automatic captcha solving without UI
func solveVkCaptchaAutomatic(ctx context.Context, streamID int, client tlsclient.HttpClient, profile Profile, captchaErr *VkCaptchaError) (string, error) {
	sessionToken := captchaErr.SessionToken
	if sessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}

	// Step 1: Fetch the captcha HTML page to get powInput
	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectUri, client, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	turnLog("[Captcha] PoW input: %s, difficulty: %d", bootstrap.PowInput, bootstrap.Difficulty)

	// Step 2: Solve PoW
	hash := solvePoW(bootstrap.PowInput, bootstrap.Difficulty)
	turnLog("[Captcha] PoW solved: hash=%s", hash)

	// Step 3: Call captchaNotRobot API with slider POC support
	successToken, err := callCaptchaNotRobotWithSliderPOC(
		ctx,
		captchaErr.SessionToken,
		hash,
		streamID,
		client,
		profile,
		bootstrap.Settings,
	)

	if err != nil {
		return "", fmt.Errorf("callCaptchaNotRobotWithSliderPOC API failed: %w", err)
	}

	turnLog("[Captcha] Success! Got success_token")
	return successToken, nil
}
*/

func solveVkCaptcha(ctx context.Context, captchaErr *VkCaptchaError, streamID int, client tlsclient.HttpClient, profile Profile, useSliderPOC bool) (string, error) {
	if captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri for auto-solve")
	}
	if captchaErr.RedirectURI == "" {
		return "", fmt.Errorf("no redirect_uri for auto-solve")
	}

	// Live diagnostics showed that a second check with the same session_token
	// immediately returns ERROR_LIMIT after the first BOT/getContent refusal.
	// A captcha session is therefore single-use for automatic solving.
	const maxAttempts = 1
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		token, err := solveVkCaptchaOnce(ctx, captchaErr, streamID, client, profile, useSliderPOC)
		if err == nil {
			return token, nil
		}
		lastErr = err
		turnLog("[STREAM %d] [Captcha] attempt %d/%d failed: %v", streamID, attempt, maxAttempts, err)
		// VK has throttled this captcha session: another attempt would only
		// burn more requests against the rate limit. Stop and let the caller
		// fall back to the WebView.
		if isCaptchaSessionExhausted(err) {
			turnLog("[STREAM %d] [Captcha] Session throttled (ERROR_LIMIT) — abandoning auto solve", streamID)
			return "", err
		}
		if attempt < maxAttempts {
			backoff := time.Duration(attempt) * 500 * time.Millisecond
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("captcha attempts exhausted")
}

func solveVkCaptchaOnce(ctx context.Context, captchaErr *VkCaptchaError, streamID int, client tlsclient.HttpClient, profile Profile, useSliderPOC bool) (string, error) {
	if useSliderPOC {
		turnLog("[STREAM %d] [Captcha] Solving captcha with slider POC...", streamID)
	} else {
		turnLog("[STREAM %d] [Captcha] Solving captcha...", streamID)
	}

	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectURI, client, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	turnLog("[STREAM %d] [Captcha] PoW difficulty: %d", streamID, bootstrap.Difficulty)
	hash := solvePoW(ctx, bootstrap.PowInput, bootstrap.Difficulty)
	if hash == "" {
		return "", fmt.Errorf("PoW solve failed or cancelled")
	}
	turnLog("[STREAM %d] [Captcha] PoW solved", streamID)

	debugInfo, err := fetchDebugInfoFromScript(ctx, bootstrap.ScriptURL, client, profile)
	if err != nil {
		turnLog("[STREAM %d] [Captcha] Warning: could not fetch debug_info dynamically: %v — using fallback", streamID, err)
		debugInfo = captchaDebugInfo
	}

	bootstrapHasSlider := false
	if bootstrap.Settings != nil {
		_, bootstrapHasSlider = bootstrap.Settings.SettingsByType[sliderCaptchaType]
	}

	// When VK offers a slider — either this is the explicit slider-POC mode, or
	// the bootstrap already advertised one — run the unified single-session
	// solver. It does settings → componentDone → checkbox check → slider on ONE
	// session_token, escalating to the slider in-place if the checkbox is
	// rejected as a bot. The old path ran a standalone checkbox solver first and
	// then spun up a *second* session for the slider, duplicating
	// settings/componentDone/check on the same token — which tripped VK's
	// per-token rate limit (ERROR_LIMIT) before the slider image could load.
	if useSliderPOC || bootstrapHasSlider {
		successToken, err := callCaptchaNotRobotWithSliderPOC(
			ctx, captchaErr.SessionToken, hash, debugInfo, streamID, client, profile, bootstrap.Settings,
		)
		if err != nil {
			return "", fmt.Errorf("captchaNotRobot slider POC failed: %w", err)
		}
		turnLog("[STREAM %d] [Captcha] Success! Got success_token (slider POC)", streamID)
		return successToken, nil
	}

	// No slider advertised — try the plain checkbox solver. If its own live
	// settings reveal a slider it returns errSliderDetected, and the caller
	// (vk.go) re-enters this with useSliderPOC=true for the unified path above.
	successToken, err := callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, debugInfo, streamID, client, profile)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}
	turnLog("[STREAM %d] [Captcha] Success! Got success_token", streamID)
	return successToken, nil
}

func applyBrowserProfileFhttp(req *fhttp.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", profileAcceptLanguage(profile))
	req.Header.Set("DNT", "1")
}

// profileAcceptLanguage returns the Accept-Language header for a profile,
// falling back to en-US when the profile predates the AcceptLanguage field.
func profileAcceptLanguage(profile Profile) string {
	if strings.TrimSpace(profile.AcceptLanguage) != "" {
		return profile.AcceptLanguage
	}
	return "en-US,en;q=0.9"
}

// captchaDeviceLanguages mirrors navigator.language / navigator.languages for
// the device fingerprint. It must stay consistent with the Accept-Language
// header (profileAcceptLanguage) — a ru-RU header paired with an en-US
// navigator.language is exactly the inconsistency VK's bot detector flags.
func captchaDeviceLanguages(profile Profile) (string, string) {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(profile.AcceptLanguage)), "ru") {
		return "ru-RU", `["ru-RU","ru","en-US"]`
	}
	return "en-US", `["en-US"]`
}

type captchaViewport struct {
	Width  int
	Height int
}

// randomViewport returns a randomized viewport matching real desktop Chrome variability.
func randomViewport() captchaViewport {
	widths := []int{1920, 1920, 1920, 1366, 1440, 1536, 1680, 2560} // 1920 weighted 3×
	heights := []int{1080, 1080, 1080, 768, 900, 864, 1050, 1440}
	idx := rand.Intn(len(widths))
	return captchaViewport{Width: widths[idx], Height: heights[idx]}
}

func generateBrowserFp(_ Profile, _ captchaViewport) string {
	b := make([]byte, 16)
	if _, err := cryptorand.Read(b); err != nil {
		return fmt.Sprintf("%x", rand.Int63())
	}
	return hex.EncodeToString(b)
}

// generateHumanCursor produces a realistic mouse trajectory with returns, pauses, and micro-jitter.
func generateHumanCursor() string {
	startX := 400 + rand.Intn(800) // wider range: 400-1200
	startY := 200 + rand.Intn(500) // 200-700
	startTime := time.Now().UnixMilli() - int64(rand.Intn(3000)+1500)
	numPoints := 20 + rand.Intn(15)
	points := make([]string, 0, numPoints)

	for i := 0; i < numPoints; i++ {
		// Micro-pause: sometimes repeat the same position for 2-3 frames
		if i > 2 && rand.Intn(8) == 0 {
			for repeat := 0; repeat < 1+rand.Intn(2); repeat++ {
				startTime += int64(rand.Intn(60) + 40)
				if len(points) < numPoints {
					points = append(points, fmt.Sprintf(`{"x":%d,"y":%d,"t":%d}`, startX, startY, startTime))
				}
			}
			continue
		}
		// Return movement: go backwards 2-8px every ~6 steps
		if i > 3 && rand.Intn(6) == 0 {
			startX -= rand.Intn(8) + 2
			startY -= rand.Intn(5) + 1
		} else {
			startX += rand.Intn(20) - 5 // -5..+14
			startY += rand.Intn(18) - 3 // -3..+14 — not always downward
		}
		startTime += int64(rand.Intn(50) + 15) // 15-65ms between points
		points = append(points, fmt.Sprintf(`{"x":%d,"y":%d,"t":%d}`, startX, startY, startTime))
	}
	return "[" + strings.Join(points, ",") + "]"
}

// generateConnectionMetrics mirrors the captured captcha-page requests: RTT was
// unavailable, while NetworkInformation.downlink was sampled repeatedly at a
// fixed value during the page lifetime (22 and 30 samples respectively).
func generateConnectionMetrics() (rtt string, downlink string) {
	rtt = "[]"
	dlValues := make([]string, 22+rand.Intn(9))
	value := math.Round((8.0+rand.Float64()*2.5)*10) / 10
	formatted := strconv.FormatFloat(value, 'f', -1, 64)
	for i := range dlValues {
		dlValues[i] = formatted
	}
	downlink = "[" + strings.Join(dlValues, ",") + "]"
	return
}

func fetchCaptchaBootstrap(ctx context.Context, redirectURI string, client tlsclient.HttpClient, profile Profile) (*captchaBootstrap, error) {
	parsedURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return nil, err
	}
	domain := parsedURL.Hostname()

	req, err := fhttp.NewRequestWithContext(ctx, "GET", redirectURI, nil)
	if err != nil {
		return nil, err
	}

	req.Host = domain
	applyBrowserProfileFhttp(req, profile)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseCaptchaBootstrapHTML(string(body))
}

func buildCaptchaDeviceJSON(profile Profile, vp captchaViewport) string {
	availHeight := vp.Height - 40 - rand.Intn(21)  // taskbar: 40-60px
	innerHeight := vp.Height - 111 - rand.Intn(31) // browser chrome: 111-141px
	devicePixelRatio := 1
	if vp.Width >= 2560 {
		devicePixelRatio = 2
	}
	language, languages := captchaDeviceLanguages(profile)

	// navigator.platform must agree with the profile's UA and client hints — a
	// macOS UA reporting "Win32" is a bot signal on its own.
	platform := profile.Platform
	if platform == "" {
		platform = "Win32"
	}

	return fmt.Sprintf(
		`{"screenWidth":%d,"screenHeight":%d,"screenAvailWidth":%d,"screenAvailHeight":%d,"innerWidth":%d,"innerHeight":%d,"devicePixelRatio":%d,"language":"%s","languages":%s,"webdriver":false,"hardwareConcurrency":%d,"deviceMemory":%d,"connectionEffectiveType":"4g","notificationsPermission":"default","userAgent":"%s","platform":"%s"}`,
		vp.Width, vp.Height, vp.Width, availHeight, vp.Width, innerHeight,
		devicePixelRatio,
		language, languages,
		8+rand.Intn(9),  // 8-16 cores
		8+rand.Intn(25), // 8-32 GB
		profile.UserAgent,
		platform,
	)
}

func solvePoW(ctx context.Context, powInput string, difficulty int) string {
	if powInput == "" || difficulty <= 0 {
		return ""
	}
	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10000000; nonce++ {
		if nonce%4096 == 0 {
			select {
			case <-ctx.Done():
				return ""
			default:
			}
		}
		hash := sha256.Sum256([]byte(powInput + strconv.Itoa(nonce)))
		hexHash := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hexHash, target) {
			return hexHash
		}
	}
	return ""
}

// fetchDebugInfoFromScript downloads the captcha JS bundle and extracts the
// debug_info hash embedded in it.  Results are cached by script URL so we only
// pay the fetch cost once per unique script version.
func fetchDebugInfoFromScript(ctx context.Context, scriptURL string, client tlsclient.HttpClient, profile Profile) (string, error) {
	if scriptURL == "" {
		return "", fmt.Errorf("empty script URL")
	}
	if cached, ok := captchaDebugInfoCache.Load(scriptURL); ok {
		if v, ok := cached.(string); ok {
			return v, nil
		}
		captchaDebugInfoCache.Delete(scriptURL)
	}

	req, err := fhttp.NewRequestWithContext(ctx, "GET", scriptURL, nil)
	if err != nil {
		return "", err
	}
	applyBrowserProfileFhttp(req, profile)
	req.Header.Set("Accept", "text/javascript,*/*")
	req.Header.Set("Referer", "https://id.vk.com/")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header[fhttp.HeaderOrderKey] = captchaHeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = captchaPHeaderOrder

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	m := reCaptchaDebugInfo.FindSubmatch(body)
	if len(m) < 2 {
		return "", fmt.Errorf("debug_info not found in captcha script")
	}
	v := string(m[1])
	captchaDebugInfoCache.Store(scriptURL, v)
	turnLog("[Captcha] debug_info fetched from script: %.12s...", v)
	return v, nil
}

func callCaptchaNotRobot(ctx context.Context, sessionToken, hash, debugInfo string, streamID int, client tlsclient.HttpClient, profile Profile) (string, error) {
	vkReq := func(method string, values neturl.Values) (map[string]interface{}, error) {
		reqURL := "https://api.vk.com/method/" + method + "?v=" + captchaNotRobotAPIVersion
		req, err := fhttp.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(encodeCaptchaForm(method, values)))
		if err != nil {
			return nil, err
		}
		applyBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://id.vk.com")
		req.Header.Set("Referer", "https://id.vk.com/")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Priority", "u=1, i")
		req.Header[fhttp.HeaderOrderKey] = captchaHeaderOrder
		req.Header[fhttp.PHeaderOrderKey] = captchaPHeaderOrder

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = httpResp.Body.Close() }()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}
		return resp, nil
	}

	vp := randomViewport()
	baseValues := func() neturl.Values {
		values := neturl.Values{}
		values.Set("session_token", sessionToken)
		values.Set("domain", "vk.com")
		values.Set("adFp", "")
		values.Set("access_token", "")
		return values
	}

	turnLog("[STREAM %d] [Captcha] Step 1/4: settings", streamID)
	settingsResp, err := vkReq("captchaNotRobot.settings", baseValues())
	if err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}
	if parsedSettings, perr := parseCaptchaSettingsResponse(settingsResp); perr == nil && parsedSettings != nil {
		if _, hasSlider := parsedSettings.SettingsByType[sliderCaptchaType]; hasSlider {
			turnLog("[STREAM %d] [Captcha] Slider detected in settings — aborting HTTP solve", streamID)
			return "", errSliderDetected
		}
	}

	time.Sleep(time.Duration(500+rand.Intn(300)) * time.Millisecond)

	turnLog("[STREAM %d] [Captcha] Step 2/4: componentDone (viewport=%dx%d)", streamID, vp.Width, vp.Height)
	browserFp := generateBrowserFp(profile, vp)
	deviceJSON := buildCaptchaDeviceJSON(profile, vp)
	componentDoneData := baseValues()
	componentDoneData.Set("browser_fp", browserFp)
	componentDoneData.Set("device", deviceJSON)

	if _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}

	time.Sleep(time.Duration(500+rand.Intn(300)) * time.Millisecond)

	turnLog("[STREAM %d] [Captcha] Step 3/4: check", streamID)
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))

	connRtt, connDownlink := generateConnectionMetrics()
	checkData := baseValues()
	// Desktop profile: no motion sensors exist, so the sensor arrays stay empty
	// (a desktop UA paired with accelerometer/gyroscope readings is a stronger
	// bot signal than their absence). The mouse trajectory is the desktop
	// equivalent of the touch data a phone would send, so it stays populated.
	checkData.Set("accelerometer", "[]")
	checkData.Set("gyroscope", "[]")
	checkData.Set("motion", "[]")
	checkData.Set("cursor", generateHumanCursor())
	checkData.Set("taps", "[]")
	checkData.Set("connectionRtt", connRtt)
	checkData.Set("connectionDownlink", connDownlink)
	checkData.Set("browser_fp", browserFp)
	checkData.Set("hash", hash)
	checkData.Set("answer", answer)
	checkData.Set("debug_info", debugInfo)

	checkResp, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("check failed: %w", err)
	}

	respObj, ok := checkResp["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid check response: %v", checkResp)
	}
	status, _ := respObj["status"].(string)
	switch strings.ToUpper(status) {
	case "OK":
		// continue below
	case "BOT":
		turnLog("[STREAM %d] [Captcha] check returned BOT status", streamID)
		return "", errCaptchaBot
	case "ERROR_LIMIT":
		turnLog("[STREAM %d] [Captcha] check returned ERROR_LIMIT — session throttled", streamID)
		return "", errCaptchaRateLimit
	default:
		return "", fmt.Errorf("check status: %s", status)
	}
	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
		return "", fmt.Errorf("success_token not found")
	}

	time.Sleep(time.Duration(500+rand.Intn(300)) * time.Millisecond)

	turnLog("[STREAM %d] [Captcha] Step 4/4: endSession", streamID)
	if _, err := vkReq("captchaNotRobot.endSession", baseValues()); err != nil {
		turnLog("[STREAM %d] [Captcha] Warning: endSession failed: %v", streamID, err)
	}

	return successToken, nil
}
