/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"strings"
	"testing"
)

// VK echoes request_params — tokens and client secrets included — in its error
// object. The description keeps only code and message, and keeps the
// "error_code:29" spelling the rate-limit check in fetchVkCreds matches on.
func TestVKAPIErrorDescriptionDropsRequestParams(t *testing.T) {
	errObj := map[string]interface{}{
		"error_code": float64(29),
		"error_msg":  "Rate limit reached",
		"request_params": []interface{}{
			map[string]interface{}{"key": "access_token", "value": "secret-token"},
		},
	}
	got := vkAPIErrorDescription(errObj)
	if strings.Contains(got, "secret-token") {
		t.Fatalf("request_params leaked: %s", got)
	}
	if !strings.Contains(got, "error_code:29") || !strings.Contains(got, "Rate limit reached") {
		t.Fatalf("code or message lost: %s", got)
	}
}

func TestCaptchaURLForLogDropsQuery(t *testing.T) {
	for raw, want := range map[string]string{
		"https://id.vk.ru/not_robot_captcha?domain=vk.com&session_token=abc.def#frag": "https://id.vk.ru/not_robot_captcha",
		"http://127.0.0.1:51234/captcha?session_token=abc":                            "http://127.0.0.1:51234/captcha",
		"not a url with session_token=abc":                                            "<captcha URL>",
		"":                                                                            "<captcha URL>",
	} {
		if got := CaptchaURLForLog(raw); got != want {
			t.Errorf("CaptchaURLForLog(%q) = %q, want %q", raw, got, want)
		}
	}
}
