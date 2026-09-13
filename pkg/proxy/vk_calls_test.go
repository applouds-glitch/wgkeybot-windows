/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"errors"
	"fmt"
	"testing"
)

// VK's documented "come back later" codes are worth repeating; a captcha gate is
// a verdict, and repeating it just burns another anonymous device.
func TestIsRetryableVKCode(t *testing.T) {
	for _, code := range []int{1, 6, 10} {
		if !isRetryableVKCode(code) {
			t.Fatalf("code %d should be retryable", code)
		}
	}
	// 14 is the captcha gate: only the legacy chain can answer it.
	// 951/954 are terminal. 0 is not an error at all.
	for _, code := range []int{0, 14, 951, 954, 9005} {
		if isRetryableVKCode(code) {
			t.Fatalf("code %d must not be retryable", code)
		}
	}
}

// The transient marker has to survive wrapping: getVKCredsViaVKCalls decides
// whether to retry by inspecting an error that came back through five steps.
func TestIsTransientVKCallsSurvivesWrapping(t *testing.T) {
	err := transientVKCallsf("step2: HTTP %d", 503)
	if !isTransientVKCalls(err) {
		t.Fatal("freshly built transient error not recognised")
	}
	// The request-failed and read-response call sites put their own %w in the
	// format string on top of transientVKCallsf's own %w for errVKCallsTransient
	// — fmt.Errorf must resolve both, and the sentinel must still be found
	// alongside the wrapped cause, not instead of it.
	cause := errors.New("connection refused")
	doubleWrapped := transientVKCallsf("step1: request failed: %w", cause)
	if !isTransientVKCalls(doubleWrapped) {
		t.Fatal("transient marker lost when the format string carries its own %w")
	}
	if !errors.Is(doubleWrapped, cause) {
		t.Fatal("wrapped cause lost alongside the transient marker")
	}
	wrapped := fmt.Errorf("getVKCredsViaVKCalls: %w", err)
	if !isTransientVKCalls(wrapped) {
		t.Fatal("transient marker lost through wrapping")
	}
	if isTransientVKCalls(errors.New("plain failure")) {
		t.Fatal("plain error must not look transient")
	}
	// A captcha gate must never be mistaken for a hiccup.
	if isTransientVKCalls(fmt.Errorf("VK error_code 14: captcha needed")) {
		t.Fatal("captcha gate must not look transient")
	}
}
