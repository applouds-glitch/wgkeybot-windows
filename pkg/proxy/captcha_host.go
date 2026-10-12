package proxy

import (
	"context"
	neturl "net/url"
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

// CaptchaURLForLog — адрес капчи без query и fragment: в query VK кладёт
// session_token, а лог пользователи присылают в поддержку. Схемы, хоста и пути
// достаточно, чтобы отличить одну страницу капчи от другой.
func CaptchaURLForLog(raw string) string {
	u, err := neturl.Parse(raw)
	if err != nil || u.Host == "" {
		return "<captcha URL>"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// CaptchaNotifyChan returns the channel that fires when a captcha is pending.
// Used by WaitReady to detect captcha state before StartProxy returns.
func CaptchaNotifyChan() <-chan struct{} { return captchaNotifyCh }

// RequestCaptcha блокирует вызывающую goroutine до получения ответа от host'а
// или до отмены ctx (disconnect). Без внутреннего дедлайна — пользователь решает
// капчу в своём темпе, единственный способ прервать ожидание — отменить ctx.
// Возвращает "" при отмене или если запрос вытеснен более новой капчей.
func RequestCaptcha(ctx context.Context, redirectURI string) string {
	return RequestCaptchaCtx(ctx, redirectURI, 0)
}

// RequestCaptchaCtx — расширенная версия с контекстом и опциональным таймаутом.
// timeout <= 0 означает «без таймаута» (ждать до ответа или отмены ctx).
func RequestCaptchaCtx(ctx context.Context, redirectURI string, timeout time.Duration) string {
	ch := make(chan string, 1)

	captchaMu.Lock()
	if captchaAnswerCh != nil {
		// Уже есть pending captcha. С requestCaptchaSerialized (vk.go) этот путь
		// недостижим — решение капчи сериализовано выше по стеку, — но если он
		// когда-нибудь оживёт, вытесненный вызывающий получает "" и не может
		// отличить это от «пользователь не решил». Логируем, чтобы такой ложный
		// отказ не пришлось искать по косвенным признакам.
		turnLog("[Captcha] Pending request for %s evicted by a newer one (%s)", CaptchaURLForLog(captchaPending), CaptchaURLForLog(redirectURI))
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

	turnLog("[Captcha] Requesting host solve: %s", CaptchaURLForLog(redirectURI))

	// timeout <= 0 → ждём бессрочно (только ответ или отмена ctx).
	var timeoutCh <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		timeoutCh = t.C
	}

	select {
	case answer, ok := <-ch:
		if !ok {
			return ""
		}
		return answer
	case <-ctx.Done():
		return ""
	case <-timeoutCh:
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
//
// Отправка — строго под captchaMu: close() чужого канала в RequestCaptchaCtx
// тоже происходит под captchaMu и атомарно заменяет captchaAnswerCh на свежий
// канал, поэтому сериализованный sender закрытый канал увидеть не может.
// Отправка вне mutex здесь была гонкой send-on-closed-channel (panic).
// Канал буферизован (cap 1) и send идёт через select/default — под mutex
// не блокируемся.
func PublishCaptchaAnswer(answer string) {
	captchaMu.Lock()
	defer captchaMu.Unlock()
	if captchaAnswerCh == nil {
		return
	}
	select {
	case captchaAnswerCh <- answer:
		turnLog("[Captcha] Answer published (%d bytes)", len(answer))
	default:
		// Канал уже принял ответ — дубликат, игнорируем.
	}
}
