package connlink

import (
	"errors"
	"strings"
	"testing"
)

const (
	uuidToken  = "550e8400-e29b-41d4-a716-446655440000"
	shortToken = "fjsyalvjdufndhs"
)

func TestTokenShapesTheBotCanHandOut(t *testing.T) {
	for _, token := range []string{
		uuidToken, "550e8400e29b41d4a716446655440000", shortToken, "Xk9_2mQ-7bZaQv",
		strings.Repeat("a", 8), strings.Repeat("a", 64),
	} {
		if !IsValidToken(token) {
			t.Errorf("IsValidToken(%q) = false", token)
		}
	}
}

func TestTokenRejectsLengthsOutsideTheWindow(t *testing.T) {
	for _, token := range []string{"", strings.Repeat("a", 7), strings.Repeat("a", 65)} {
		if IsValidToken(token) {
			t.Errorf("IsValidToken(%q) = true", token)
		}
	}
}

func TestTokenCannotReshapeTheRequestPath(t *testing.T) {
	for _, token := range []string{
		"../open/fjsyalvjdufndhs", "fjsyalvjdufndhs/../open", "fjsyalvjdufndhs?x=1",
		"fjsyalvjdufndhs#frag", "token with spaces", "fjsyalvjdufndhs\nGET /open", shortToken + "\n",
	} {
		if IsValidToken(token) {
			t.Errorf("IsValidToken(%q) = true", token)
		}
	}
}

func TestNormalizeDropsWhitespaceAndInvisibleCharacters(t *testing.T) {
	for _, raw := range []string{"  " + shortToken + "\n", "fjsyalv jdufndhs", "\u200Bfjsyalvjdufndhs\uFEFF", "fjsy\u00A0alvjdufndhs"} {
		if got := Normalize(raw); got != shortToken {
			t.Errorf("Normalize(%q) = %q", raw, got)
		}
	}
	if got := Normalize(" Xk9_2mQ-7bZaQv "); got != "Xk9_2mQ-7bZaQv" {
		t.Errorf("case and dashes must stay, got %q", got)
	}
}

func TestExtractTokenUnwrapsOurLinks(t *testing.T) {
	for raw, want := range map[string]string{
		" " + shortToken + " ":                                                  shortToken,
		"wgkeybot://config?token=" + shortToken:                                 shortToken,
		"wgkeybot://config?token=" + uuidToken + "&x=1":                         uuidToken,
		"https://key.shadowgate.online/api/v1/init/" + shortToken:               shortToken,
		"https://key.shadowgate.online/open/" + uuidToken + "?platform=windows": uuidToken,
		"\u200Bhttps://KEY.shadowgate.online/open/" + uuidToken + "#top":        uuidToken,
	} {
		if got, ok := ExtractToken(raw); !ok || got != want {
			t.Errorf("ExtractToken(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
}

func TestExtractTokenFindsNothingInGarbage(t *testing.T) {
	for _, raw := range []string{
		"", "hello", "../open/short", "wgkeybot://config?token=short",
		"https://key.shadowgate.online/", "https://key.shadowgate.online/open/short",
	} {
		if got, ok := ExtractToken(raw); ok {
			t.Errorf("ExtractToken(%q) = %q", raw, got)
		}
	}
}

// Страницу загрузки вставляют в поле токена: …/releases становился запросом
// токена `releases` и непонятным 404 с сервера.
func TestExtractTokenNeverMinesSomeoneElsesLink(t *testing.T) {
	for _, raw := range []string{
		"https://github.com/applouds-glitch/wgkeybot-windows/releases",
		"https://t.me/wg_key_bot?start=" + shortToken,
		"https://t.me/wg_key_bot?start=android",
		"https://example.com/" + uuidToken,
		"https://example.com/x?token=" + uuidToken,
		"https://key.shadowgate.online.example.com/open/" + uuidToken,
	} {
		if got, ok := ExtractToken(raw); ok {
			t.Errorf("ExtractToken(%q) = %q", raw, got)
		}
	}
}

func parseFailure(t *testing.T, raw string) Failure {
	t.Helper()
	input, err := Parse(raw)
	var parseErr *Error
	if !errors.As(err, &parseErr) {
		t.Fatalf("Parse(%q) = %+v, %v; want *Error", raw, input, err)
	}
	return parseErr.Reason
}

func TestParseNamesWhatWasPastedInstead(t *testing.T) {
	for raw, want := range map[string]Failure{
		"https://github.com/applouds-glitch/wgkeybot-windows/releases": FailAppDownloadLink,
		" https://t.me/wg_key_bot?start=android ":                      FailBotLink,
		"https://telegram.me/wg_key_bot":                               FailBotLink,
		"https://example.com/" + uuidToken:                             FailInvalidFormat,
		"https://key.shadowgate.online/open/short":                     FailInvalidFormat,
		"hello":                         FailInvalidFormat,
		" \u200B\n":                     FailEmpty,
		"wgkeybot://config":             FailMissingToken,
		"wgkeybot://config?token=":      FailMissingToken,
		"wgkeybot://config?token=short": FailInvalidFormat,
	} {
		if got := parseFailure(t, raw); got != want {
			t.Errorf("Parse(%q) failed with %d, want %d", raw, got, want)
		}
	}
}

func TestParseResolvesTokensAndTokenLinks(t *testing.T) {
	for _, raw := range []string{
		uuidToken, "wgkeybot://config?token=" + uuidToken, "https://key.shadowgate.online/api/v1/init/" + uuidToken,
		"wgkeybot://config?platform=windows&token=" + uuidToken,
	} {
		input, err := Parse(raw)
		if err != nil || input.Token != uuidToken {
			t.Errorf("Parse(%q) = %+v, %v", raw, input, err)
		}
	}
}

func TestParseRejectsAnUnexpectedLinkShape(t *testing.T) {
	valid := "wgkeybot://config?token=" + uuidToken
	for _, raw := range []string{
		valid + "#fragment", valid + "&token=" + shortToken,
		"wgkeybot://config/path?token=" + uuidToken, "wgkeybot://user@config?token=" + uuidToken,
		"wgkeybot://config:123?token=" + uuidToken, "wgkeybot://other?token=" + uuidToken,
		"wgkeybot://config?token", "wgkeybot://config?token=%%%%",
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q) accepted", raw)
		}
	}
}

func TestParseRefusesWhatIsTooLong(t *testing.T) {
	if got := parseFailure(t, strings.Repeat(" ", MaxLinkLength-len(uuidToken)+1)+uuidToken); got != FailInvalidFormat {
		t.Fatalf("over the limit failed with %d", got)
	}
	padded := strings.Repeat(" ", MaxLinkLength-len(uuidToken)) + uuidToken
	if input, err := Parse(padded); err != nil || input.Token != uuidToken {
		t.Fatalf("at the limit: %+v, %v", input, err)
	}
}

// Текст ошибки уходит в окно и может уйти в журнал: во вставленном может быть
// ключ устройства.
func TestParseErrorsNeverEchoTheInput(t *testing.T) {
	const secret = "private-key-secret-123456789"
	for _, raw := range []string{
		"https://example.com/" + secret, "https://github.com/" + secret, "https://t.me/" + secret,
		"wgkeybot://config?token=/" + secret, "wgkeybot://other?token=" + secret,
	} {
		_, err := Parse(raw)
		if err == nil {
			t.Fatalf("Parse(%q) accepted", raw)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("Parse(%q) echoed the input: %v", raw, err)
		}
	}
}
