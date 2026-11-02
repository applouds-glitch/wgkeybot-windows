package connlink

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxPayloadBytes — предел распакованного JSON, как у бота (android_links.py).
// Он же защита от zip-бомбы: больше этого не распаковывается.
const MaxPayloadBytes = 65536

// Embedded — конфиг из ссылки wgkeybot://config?data=… (порт Android
// ConnectionLink, 13b428fc): страница и токен обращаются к одному серверу, а
// такая ссылка импортируется без него. Base64 и zlib — кодирование, а не
// шифрование: внутри приватный ключ устройства и токен его сессии.
type Embedded struct {
	AccessToken string
	Config      string
}

var (
	dataAlphabet   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	integerLiteral = regexp.MustCompile(`^-?[0-9]+$`)
	expiryFormat   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

// decodeData разбирает значение data строго: повреждённая ссылка не должна
// импортироваться наполовину. Android здесь же отбивает комментарии, одинарные
// кавычки и глубокую вложенность, которые пропускает его JSONTokener; encoding/json
// их и так не принимает, а глубину ограничивает ошибкой.
func decodeData(encoded string) (*Embedded, error) {
	payload, ok := inflateData(encoded)
	if !ok || !utf8.Valid(payload) {
		return nil, &Error{Reason: FailInvalidData}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil || fields == nil {
		return nil, &Error{Reason: FailInvalidData}
	}
	// В схеме только скаляры.
	for _, value := range fields {
		if len(value) > 0 && (value[0] == '{' || value[0] == '[') {
			return nil, &Error{Reason: FailInvalidData}
		}
	}

	switch version := string(fields["version"]); {
	case version == "1":
	case integerLiteral.MatchString(version):
		return nil, &Error{Reason: FailUnsupportedVersion}
	default:
		return nil, &Error{Reason: FailInvalidData}
	}

	accessToken, ok := stringField(fields, "access_token")
	if !ok || !IsValidToken(accessToken) {
		return nil, &Error{Reason: FailInvalidData}
	}
	// Срок подписки на Windows не показывается, но ссылка с битым сроком — битая
	// ссылка, как и на остальных клиентах.
	expires, ok := stringField(fields, "subscription_expires_at")
	if !ok || !validExpiry(expires) {
		return nil, &Error{Reason: FailInvalidData}
	}
	config, ok := stringField(fields, "config")
	if !ok || strings.TrimSpace(config) == "" || strings.ContainsRune(config, 0) ||
		!strings.Contains(config, "[Interface]") || !strings.Contains(config, "[Peer]") {
		return nil, &Error{Reason: FailInvalidConfig}
	}
	return &Embedded{AccessToken: accessToken, Config: config}, nil
}

// inflateData снимает Base64URL без padding и zlib. Хвост за потоком zlib и
// неканоничный Base64 — отказ: так выглядит обрезанная или склеенная ссылка.
func inflateData(encoded string) ([]byte, bool) {
	if !dataAlphabet.MatchString(encoded) {
		return nil, false
	}
	compressed, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, false
	}
	// bytes.Reader умеет ReadByte, поэтому zlib не читает лишнего и Len после
	// конца потока показывает настоящий хвост.
	source := bytes.NewReader(compressed)
	reader, err := zlib.NewReader(source)
	if err != nil {
		return nil, false
	}
	defer reader.Close()
	payload, err := io.ReadAll(io.LimitReader(reader, MaxPayloadBytes+1))
	if err != nil || len(payload) > MaxPayloadBytes || source.Len() != 0 {
		return nil, false
	}
	return payload, true
}

func stringField(fields map[string]json.RawMessage, name string) (string, bool) {
	raw := fields[name]
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

// validExpiry — строго UTC с секундами. Regexp нужен до time.Parse: тот принимает
// дробные секунды, даже когда их нет в раскладке.
func validExpiry(value string) bool {
	if !expiryFormat.MatchString(value) {
		return false
	}
	_, err := time.Parse("2006-01-02T15:04:05Z", value)
	return err == nil
}
