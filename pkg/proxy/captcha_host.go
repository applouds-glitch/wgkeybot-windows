package proxy

import (
	"context"
	"sync"
	"time"
)

// captcha_host.go — pull-модель для передачи captcha между Go-кодом
// (vk.go, vk_captcha.go) и host-приложением:
//
//  1. Go вызывает RequestCaptcha(url) — блокирующий вызов.
//  2. Tunnel.PendingCaptchaURL() начинает возвращать url.
//  3. WaitReady возвращает ReadyStatusCaptchaRequired.
//  4. Host открывает браузер/WebView и вызывает PublishCaptchaAnswer(token).
//  5. PublishCaptchaAnswer разблокирует RequestCaptcha.

// captchaState — глобальный синглтон (vk-код использует глобальные функции).
var (
	captchaMu       sync.Mutex
	captchaPending  string
	captchaAnswerCh chan string

	// captchaNotifyCh fires (non-blocking send) whenever RequestCaptcha is
	// called.  WaitReady selects on it so it can return ReadyStatusCaptchaRequired
	// while StartProxy is still blocked inside prefetchWg.Wait().
	captchaNotifyCh = make(chan struct{}, 1)
)

// CaptchaNotifyChan returns the channel that fires when a captcha is pending.
// Used by WaitReady to detect captcha state before StartProxy returns.
func CaptchaNotifyChan() <-chan struct{} { return captchaNotifyCh }

// RequestCaptcha блокирует вызывающую goroutine до получения ответа от host'а
// или до отмены контекста. Возвращает "" при таймауте/отмене.
func RequestCaptcha(redirectURI string) string {
	return RequestCaptchaCtx(context.Background(), redirectURI, 5*time.Minute)
}

// RequestCaptchaCtx — расширенная версия с контекстом и таймаутом.
func RequestCaptchaCtx(ctx context.Context, redirectURI string, timeout time.Duration) string {
	ch := make(chan string, 1)

	captchaMu.Lock()
	if captchaAnswerCh != nil {
		// Уже есть pending captcha — отбрасываем старую (вряд ли актуальна).
		close(captchaAnswerCh)
	}
	captchaPending = redirectURI
	captchaAnswerCh = ch
	captchaMu.Unlock()

	// Wake up WaitReady so it can return ReadyStatusCaptchaRequired.
	select {
	case captchaNotifyCh <- struct{}{}:
	default:
	}

	defer func() {
		captchaMu.Lock()
		if captchaAnswerCh == ch {
			captchaAnswerCh = nil
			captchaPending = ""
		}
		captchaMu.Unlock()
	}()

	turnLog("[Captcha] Requesting host solve: %s", redirectURI)
	select {
	case answer, ok := <-ch:
		if !ok {
			return ""
		}
		return answer
	case <-ctx.Done():
		return ""
	case <-time.After(timeout):
		turnLog("[Captcha] Host solve timed out after %v", timeout)
		return ""
	}
}

// PendingCaptchaURL возвращает URL ожидающей капчи или "".
func PendingCaptchaURL() string {
	captchaMu.Lock()
	defer captchaMu.Unlock()
	return captchaPending
}

// PublishCaptchaAnswer доставляет ответ ожидающей RequestCaptcha goroutine.
// Безопасно вызывать когда нет pending captcha (no-op).
func PublishCaptchaAnswer(answer string) {
	captchaMu.Lock()
	ch := captchaAnswerCh
	captchaMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- answer:
		turnLog("[Captcha] Answer published (%d bytes)", len(answer))
	default:
		// Канал уже принял ответ — дубликат, игнорируем.
	}
}
