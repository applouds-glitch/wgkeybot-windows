package proxy

import (
	"math/rand"
	"regexp"
	"strconv"
)

type Profile struct {
	UserAgent       string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
	// Platform is the navigator.platform value reported in the captcha device
	// fingerprint. Must stay consistent with UserAgent / SecChUaPlatform
	// (e.g. "Win32", "MacIntel", "Linux x86_64").
	Platform string
	// AcceptLanguage is the Accept-Language header and navigator.language(s)
	// reported for this profile. A Russian VK user on a desktop device sends
	// ru-RU; an en-US value paired with a vk.ru session is a bot signal.
	AcceptLanguage string
}

// profiles contain paired User-Agent and Client Hints strings to harden bot detection.
var profile = []Profile{
	// Windows Chrome
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		Platform:        "Win32",
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Google Chrome";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		Platform:        "Win32",
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="144", "Not-A.Brand";v="8", "Google Chrome";v="144"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		Platform:        "Win32",
	},

	// Windows Edge
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Microsoft Edge";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		Platform:        "Win32",
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Microsoft Edge";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		Platform:        "Win32",
	},

	// macOS Chrome
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
		Platform:        "MacIntel",
	},
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="145", "Not-A.Brand";v="99", "Google Chrome";v="145"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
		Platform:        "MacIntel",
	},

	// Linux Chrome
	{
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
		Platform:        "Linux x86_64",
	},
	{
		UserAgent:       "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="144", "Not-A.Brand";v="8", "Google Chrome";v="144"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
		Platform:        "Linux x86_64",
	},
}

// getRandomProfile returns a paired User-Agent and Client Hints profile.
func getRandomProfile() Profile {
	return profile[rand.Intn(len(profile))]
}

// vkFallbackChromeMajor is the Chrome major a VK session claims when its own
// User-Agent carries none. It is a major the TLS fork ships a spec for, so the
// fallback identity is as internally consistent as the normal one.
const vkFallbackChromeMajor = 146

var reChromeMajorInUA = regexp.MustCompile(`Chrome/(\d+)\.`)

// chromeMajorFromUA extracts the Chrome major version out of a User-Agent, or
// 0 when the string carries none.
func chromeMajorFromUA(ua string) int {
	match := reChromeMajorInUA.FindStringSubmatch(ua)
	if len(match) < 2 {
		return 0
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return 0
	}
	return major
}

// vkSessionIdentity returns the browser identity every phase of one VK session
// presents, together with the Chrome major it claims. The major is what selects
// the ClientHello (vkChromeClientProfile), so both come from here and can never
// drift apart: a UA saying one version over a JA3 saying another is exactly the
// contradiction the bot detector is looking for.
//
// One identity for the whole fetch, not one per request: the trigger chain and
// the captcha phase are the same session as far as VK is concerned, and a
// second draw would present two browsers to one detector.
func vkSessionIdentity() (Profile, int) {
	p := Profile{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
		SecChUa:         `"Not(A:Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		Platform:        "Win32",
		AcceptLanguage:  "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
	}
	major := chromeMajorFromUA(p.UserAgent)
	if major <= 0 {
		return p, vkFallbackChromeMajor
	}
	return p, major
}
