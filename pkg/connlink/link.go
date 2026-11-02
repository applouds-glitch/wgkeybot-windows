package connlink

import (
	"net/url"
	"strings"
)

// MaxLinkLength — предел длины вставленного текста, как у бота (android_links.py).
const MaxLinkLength = 32768

// Failure — почему вставленный текст не удалось разобрать.
type Failure int

const (
	FailEmpty Failure = iota + 1
	FailInvalidFormat
	FailMissingToken
	// FailAppDownloadLink и FailBotLink: вместо токена вставили страницу
	// загрузки или самого бота.
	FailAppDownloadLink
	FailBotLink
	FailInvalidData
	FailUnsupportedVersion
	FailInvalidConfig
)

// Error — ошибка разбора. Текст показывается пользователю и никогда не содержит
// ничего из вставленного: там может быть ключ устройства.
type Error struct{ Reason Failure }

func (e *Error) Error() string {
	const where = "«Подключить устройство» → Windows."
	switch e.Reason {
	case FailEmpty:
		return "Введите токен из бота."
	case FailMissingToken:
		return "В ссылке нет токена. Токен показывает бот: " + where
	case FailAppDownloadLink:
		return "Это ссылка на скачивание приложения, а не токен. Токен показывает бот: " + where
	case FailBotLink:
		return "Это ссылка на бота, а не токен. Откройте её в Telegram: токен показывает бот, " + where
	case FailInvalidData:
		return "Данные подключения повреждены или скопированы не полностью. Скопируйте ссылку из бота ещё раз."
	case FailUnsupportedVersion:
		return "Формат данных подключения не поддерживается. Обновите приложение."
	case FailInvalidConfig:
		return "Данные подключения содержат некорректный конфиг WireGuard. Получите новую ссылку в боте."
	default:
		return "Это не похоже на токен. Токен показывает бот: " + where
	}
}

func fail(reason Failure) (Input, error) { return Input{}, &Error{Reason: reason} }

// Input — разобранный ввод: либо токен, либо конфиг из самой ссылки.
type Input struct {
	// Token — токен для /api/v1/init.
	Token string
	// Embedded — конфиг и сессия из ссылки с data; сервер для импорта не нужен.
	Embedded *Embedded
}

// Parse разбирает то, что вставили в диалог импорта. Возвращает только *Error.
func Parse(raw string) (Input, error) {
	if len(raw) > MaxLinkLength {
		return fail(FailInvalidFormat)
	}
	clean := Normalize(raw)
	if clean == "" {
		return fail(FailEmpty)
	}
	if strings.HasPrefix(clean, linkPrefix) {
		return parseLink(clean)
	}
	token, ok := ExtractToken(clean)
	if !ok {
		return fail(foreignLinkFailure(clean))
	}
	return Input{Token: token}, nil
}

func parseLink(link string) (Input, error) {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "wgkeybot" || u.Host != "config" || u.User != nil ||
		u.Path != "" || strings.Contains(link, "#") {
		return fail(FailInvalidFormat)
	}
	params, ok := linkParams(u.RawQuery)
	if !ok {
		return fail(FailInvalidFormat)
	}
	// data главнее токена: повреждённая офлайн-ссылка не становится запросом к
	// серверу, даже если рядом годный токен.
	if data, ok := params["data"]; ok {
		if token, ok := params["token"]; ok && !IsValidToken(token) {
			return fail(FailInvalidData)
		}
		embedded, err := decodeData(data)
		if err != nil {
			return Input{}, err
		}
		return Input{Embedded: embedded}, nil
	}
	rawToken, ok := params["token"]
	if !ok || rawToken == "" {
		return fail(FailMissingToken)
	}
	token, ok := ExtractToken(rawToken)
	if !ok {
		return fail(FailInvalidFormat)
	}
	return Input{Token: token}, nil
}

// linkParams читает token и data. Повтор ключа — отказ: иначе одна и та же ссылка
// значила бы разное для разных разборщиков. Остальные ключи пропускаются.
func linkParams(query string) (map[string]string, bool) {
	params := make(map[string]string, 2)
	for _, part := range strings.Split(query, "&") {
		rawKey, rawValue, hasValue := strings.Cut(part, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return nil, false
		}
		if key != "token" && key != "data" {
			continue
		}
		if _, dup := params[key]; dup || !hasValue {
			return nil, false
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			return nil, false
		}
		params[key] = value
	}
	return params, true
}
