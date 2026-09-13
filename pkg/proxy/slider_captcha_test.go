package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestCaptchaFormMatchesCapturedCheckboxOrder(t *testing.T) {
	values := url.Values{}
	values.Set("session_token", "token")
	values.Set("domain", "vk.com")
	values.Set("adFp", "")
	values.Set("accelerometer", "[]")
	values.Set("gyroscope", "[]")
	values.Set("motion", "[]")
	values.Set("cursor", "[]")
	values.Set("taps", "[]")
	values.Set("connectionRtt", "[]")
	values.Set("connectionDownlink", "[9.2,9.2]")
	values.Set("browser_fp", "fingerprint")
	values.Set("hash", "v2.hash")
	values.Set("answer", "e30=")
	values.Set("debug_info", "debug")
	values.Set("access_token", "")

	got := encodeCaptchaForm("captchaNotRobot.check", values)
	want := "session_token=token&domain=vk.com&adFp=&accelerometer=%5B%5D" +
		"&gyroscope=%5B%5D&motion=%5B%5D&cursor=%5B%5D&taps=%5B%5D" +
		"&connectionRtt=%5B%5D&connectionDownlink=%5B9.2%2C9.2%5D" +
		"&browser_fp=fingerprint&hash=v2.hash&answer=e30%3D&debug_info=debug&access_token="
	if got != want {
		t.Fatalf("unexpected encoded checkbox form:\n got: %s\nwant: %s", got, want)
	}
}

// The sample count is what ties the check to the time actually spent between
// componentDone and check — a count decoupled from that window is exactly the
// inconsistency the arrays exist to avoid. Both arrays are populated: the UA
// claims desktop Chrome, which exposes NetworkInformation.rtt as well as
// .downlink, and each is sampled at one constant value per session.
func TestNetworkSamplesMatchTheRequestedWindow(t *testing.T) {
	for _, n := range []int{1, 7, 33} {
		rtt, downlink := generateNetworkSamples(n)
		for name, raw := range map[string]string{"connectionRtt": rtt, "connectionDownlink": downlink} {
			var samples []float64
			if err := json.Unmarshal([]byte(raw), &samples); err != nil {
				t.Fatalf("%s: invalid JSON: %v", name, err)
			}
			if len(samples) != n {
				t.Fatalf("%s: got %d samples, want %d", name, len(samples), n)
			}
			for _, sample := range samples[1:] {
				if sample != samples[0] {
					t.Fatalf("%s: the browser repeats one value per session, got %v", name, samples)
				}
			}
			if samples[0] == 0 {
				t.Fatalf("%s: a desktop browser reports a real value, got %v", name, samples)
			}
		}
	}
	// A zero-length window still has to produce one sample rather than an empty
	// array the page would never send.
	rtt, _ := generateNetworkSamples(0)
	if rtt == "[]" {
		t.Fatal("a zero window produced an empty array")
	}
}

func TestCaptchaUsesCapturedAPIVersion(t *testing.T) {
	if captchaNotRobotAPIVersion != "5.131" {
		t.Fatalf("unexpected captcha API version: %s", captchaNotRobotAPIVersion)
	}
}

func TestParseSliderCaptchaContentResponseDistinguishesGenericError(t *testing.T) {
	_, err := parseSliderCaptchaContentResponse(map[string]interface{}{
		"response": map[string]interface{}{
			"status": "ERROR",
			"reason": "invalid state",
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, errCaptchaRateLimit) {
		t.Fatalf("generic ERROR must not be classified as rate limit: %v", err)
	}
	if !strings.Contains(err.Error(), "status: ERROR") || !strings.Contains(err.Error(), "response_keys=reason,status") {
		t.Fatalf("diagnostic detail missing: %v", err)
	}
}

func TestParseSliderCaptchaContentResponsePreservesRateLimit(t *testing.T) {
	_, err := parseSliderCaptchaContentResponse(map[string]interface{}{
		"response": map[string]interface{}{
			"status": "ERROR_LIMIT",
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errCaptchaRateLimit) {
		t.Fatalf("ERROR_LIMIT must retain rate-limit sentinel: %v", err)
	}
}

func TestCaptchaSessionExhaustedDoesNotTreatGenericGetContentErrorAsRateLimit(t *testing.T) {
	if isCaptchaSessionExhausted(errors.New("slider getContent status: ERROR")) {
		t.Fatal("generic getContent ERROR must not be treated as rate limit")
	}
	if !isCaptchaSessionExhausted(errors.New("slider getContent status: ERROR_LIMIT")) {
		t.Fatal("ERROR_LIMIT must be treated as an exhausted captcha session")
	}
}

// The v2 detection is what decides whether the check's hash param is a bare
// digest or a "v2." payload, and getting it wrong is silent: the solve just
// comes back BOT. Both page formats are pinned here.
func TestParseCaptchaBootstrapHTMLDetectsPowFormat(t *testing.T) {
	const v2Page = `<html><head>` +
		`<script src="https://st.vk.ru/not_robot_captcha/app.js"></script>` +
		`<script>!function(){window.captchaPowResult=null;var a=1}("71nXj0guqjgqJj9H", 3, "pow_timeout");</script>` +
		`</head></html>`
	const legacyPage = `<html><head>` +
		`<script src="https://st.vk.ru/not_robot_captcha/app.js"></script>` +
		`<script>const powInput = "legacyChallenge"; if (h.startsWith('0'.repeat(4))) {}</script>` +
		`</head></html>`

	v2, err := parseCaptchaBootstrapHTML(v2Page)
	if err != nil {
		t.Fatalf("v2 page: %v", err)
	}
	if !v2.PowV2 {
		t.Error("v2 page was read as the legacy format")
	}
	if v2.PowInput != "71nXj0guqjgqJj9H" {
		t.Errorf("v2 powInput = %q", v2.PowInput)
	}
	if v2.Difficulty != 3 {
		t.Errorf("v2 difficulty = %d, want the value from the IIFE arguments", v2.Difficulty)
	}

	legacy, err := parseCaptchaBootstrapHTML(legacyPage)
	if err != nil {
		t.Fatalf("legacy page: %v", err)
	}
	if legacy.PowV2 {
		t.Error("legacy page was read as v2")
	}
	if legacy.PowInput != "legacyChallenge" {
		t.Errorf("legacy powInput = %q", legacy.PowInput)
	}
	if legacy.Difficulty != 4 {
		t.Errorf("legacy difficulty = %d, want the value from the repeat() expression", legacy.Difficulty)
	}

	if _, err := parseCaptchaBootstrapHTML(`<html><script>nothing here</script></html>`); err == nil {
		t.Error("a page with no challenge at all parsed successfully")
	}
}

// A v2 result must be the "v2."-prefixed payload, and its tel_hash must be the
// digest of the telemetry as it is actually serialized — VK recomputes both.
func TestSolvePoWEncodesV2Payload(t *testing.T) {
	ep := captchaEndpointsFromRedirectURI("https://id.vk.ru/not_robot_captcha?domain=vk.com")
	profile, _ := vkSessionIdentity()

	got := solvePoW(context.Background(), "challenge", 2, true, profile, ep)
	if !strings.HasPrefix(got, "v2.") {
		t.Fatalf("v2 solve produced %.32q, want a v2. payload", got)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "v2."))
	if err != nil {
		t.Fatalf("v2 payload is not base64: %v", err)
	}
	var payload struct {
		Hash      string                 `json:"hash"`
		Nonce     int                    `json:"nonce"`
		Telemetry map[string]interface{} `json:"telemetry"`
		TelHash   string                 `json:"tel_hash"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("v2 payload is not JSON: %v (%s)", err, raw)
	}
	if !strings.HasPrefix(payload.Hash, "00") {
		t.Errorf("digest %q does not meet difficulty 2", payload.Hash)
	}
	canonical, err := marshalLikeJSONStringify(payload.Telemetry)
	if err != nil {
		t.Fatalf("re-encode telemetry: %v", err)
	}
	sum := sha256.Sum256(canonical)
	if want := hex.EncodeToString(sum[:]); payload.TelHash != want {
		t.Errorf("tel_hash = %s, want %s (digest of the telemetry as serialized)", payload.TelHash, want)
	}

	// The legacy format must stay a bare digest.
	if legacy := solvePoW(context.Background(), "challenge", 2, false, profile, ep); strings.HasPrefix(legacy, "v2.") {
		t.Errorf("legacy solve produced a v2 payload: %.32q", legacy)
	}
}
