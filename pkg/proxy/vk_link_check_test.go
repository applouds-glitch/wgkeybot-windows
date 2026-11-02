/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"errors"
	"testing"

	fhttp "github.com/bogdanfinn/fhttp"
)

// TestJoinHashReducesEveryLinkShape pins the one reduction the start and the
// link check share: a check must judge exactly the hash the start joins with.
func TestJoinHashReducesEveryLinkShape(t *testing.T) {
	for raw, want := range map[string]string{
		"https://vk.ru/call/join/abc_-123":          "abc_-123",
		"https://vk.com/call/join/abc_-123?x=1#top": "abc_-123",
		"https://vk.com/call/join/abc_-123/":        "abc_-123",
		"  vk.com/call/join/abc_-123  ":             "abc_-123",
		"abc_-123":                                  "abc_-123",
		"":                                          "",
	} {
		if got := joinHash(raw); got != want {
			t.Errorf("joinHash(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestCheckVKLinkVerdicts maps every outcome of the captcha-free flow to the
// code the expert mode window shows. The legacy chain is never entered: a check
// must not open a captcha for a link the user is merely looking at.
func TestCheckVKLinkVerdicts(t *testing.T) {
	cases := []struct {
		name      string
		step1     string
		transport error
		want      int32
	}{
		{"live call", "", nil, linkCheckOK},
		{"call ended", `{"error":{"error_code":951,"error_msg":"not found"}}`, nil, linkCheckUnavailable},
		{"link invalid", `{"error":{"error_code":954,"error_msg":"expired link"}}`, nil, linkCheckUnavailable},
		{"login required", `{"error":{"error_code":9005,"error_msg":"auth"}}`, nil, linkCheckRequiresAuth},
		{"captcha gate", `{"error":{"error_code":14,"error_msg":"Captcha needed"}}`, nil, linkCheckCaptcha},
		{"VK busy", `{"error":{"error_code":6,"error_msg":"Too many requests"}}`, nil, linkCheckTemporary},
		{"VK unreachable", "", errors.New("dial tcp: no route to host"), linkCheckTemporary},
		{"refused", `{"error":{"error_code":100,"error_msg":"param"}}`, nil, linkCheckRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := scriptedVKAnswer(t, tc.step1, tc.transport)
			if got := checkVKLink(context.Background(), "hash", client, Profile{}); got != tc.want {
				t.Fatalf("verdict = %d, want %d", got, tc.want)
			}
		})
	}
}

// A check whose deadline runs out is "try later", not a verdict on the call.
func TestCheckVKLinkDeadlineIsTemporary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		return nil, r.Context().Err()
	}}
	if got := checkVKLink(ctx, "hash", client, Profile{}); got != linkCheckTemporary {
		t.Fatalf("verdict = %d, want %d", got, linkCheckTemporary)
	}
}
