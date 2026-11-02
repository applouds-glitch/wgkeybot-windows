// Package connlink — что вставляют в диалог импорта: токен из бота или ссылку
// wgkeybot:// (порт Android TokenFormat и ConnectionLink, c93ca812, 9aa4a4b3).
//
// Формат токена намеренно широкий: бот может выдавать не только UUID, поэтому
// годится любая URL-safe строка вменяемой длины. Класс символов заодно даёт
// свойство безопасности: в годном токене нет `/`, `.`, `?` и `#`, так что он не
// может переписать путь запроса /api/v1/init/{token}, в который подставляется.
package connlink

import (
	"regexp"
	"strings"
	"unicode"
)

// ServiceHost — хост control plane. Ссылки на него несут токен в конце пути:
// /open/<токен>, /api/v1/init/<токен>.
const ServiceHost = "key.shadowgate.online"

const (
	linkPrefix = "wgkeybot://"
	// zeroWidth — невидимые символы, которыми мессенджеры украшают скопированный текст.
	zeroWidth = "\u200B\u200C\u200D\uFEFF"
)

var (
	validToken = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	// tokenParam достаёт токен только из своих ссылок: в ссылках бота
	// (t.me/…?start=…) токена не бывает.
	tokenParam = regexp.MustCompile(`[?&]token=([^&#]+)`)
	httpHost   = regexp.MustCompile(`(?i)^https?://([^/?#]+)`)
)

// IsValidToken отвечает, годится ли строка в токены.
func IsValidToken(token string) bool { return validToken.MatchString(token) }

// Normalize убирает пробелы и невидимые символы. Регистр и дефисы значимы и остаются.
func Normalize(raw string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || strings.ContainsRune(zeroWidth, r) {
			return -1
		}
		return r
	}, raw)
}

// ExtractToken достаёт токен из вставленного текста: сам токен,
// wgkeybot://config?token=… или ссылка на наш хост с токеном в конце пути.
//
// Чужие ссылки не разбираются: люди вставляют страницу загрузки, и
// …/wgkeybot-windows/releases превращался в запрос токена `releases` — поход на
// сервер, который кончался непонятным 404.
func ExtractToken(text string) (string, bool) {
	clean := Normalize(text)
	if IsValidToken(clean) {
		return clean, true
	}
	if !isServiceLink(clean) {
		return "", false
	}
	if m := tokenParam.FindStringSubmatch(clean); m != nil && IsValidToken(m[1]) {
		return m[1], true
	}
	path, _, _ := strings.Cut(clean, "?")
	path, _, _ = strings.Cut(path, "#")
	if last := path[strings.LastIndexByte(path, '/')+1:]; IsValidToken(last) {
		return last, true
	}
	return "", false
}

func isServiceLink(clean string) bool {
	return hasPrefixFold(clean, linkPrefix) || linkHost(clean) == ServiceHost
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// linkHost — хост http(s)-ссылки в нижнем регистре, пусто для всего остального.
func linkHost(clean string) string {
	if m := httpHost.FindStringSubmatch(clean); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

// foreignLinkFailure говорит, что за чужую ссылку вставили, чтобы ошибка могла
// её назвать.
func foreignLinkFailure(clean string) Failure {
	host := linkHost(clean)
	switch {
	case host == "github.com" || strings.HasSuffix(host, ".github.com"):
		return FailAppDownloadLink
	case host == "t.me" || host == "telegram.me" || strings.HasSuffix(host, ".t.me"):
		return FailBotLink
	default:
		return FailInvalidFormat
	}
}
