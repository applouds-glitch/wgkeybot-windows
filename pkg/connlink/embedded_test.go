package connlink

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	linkToken   = "12345678-1234-1234-1234-123456789abc"
	linkExpires = "2099-09-14T00:00:00Z"
	linkConfig  = "[Interface]\n# тест UTF-8\n[Peer]\n"
)

func linkPayload() map[string]any {
	return map[string]any{"version": 1, "access_token": linkToken, "subscription_expires_at": linkExpires, "config": linkConfig}
}

func deflate(t *testing.T, payload []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := zlib.NewWriter(&out)
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func encodeData(compressed []byte) string { return base64.RawURLEncoding.EncodeToString(compressed) }

func rawJSONLink(t *testing.T, payload string) string {
	t.Helper()
	return "wgkeybot://config?token=primary-token&data=" + encodeData(deflate(t, []byte(payload)))
}

func marshalPayload(t *testing.T, fields map[string]any) string {
	t.Helper()
	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func mapLink(t *testing.T, fields map[string]any) string {
	t.Helper()
	return rawJSONLink(t, marshalPayload(t, fields))
}

func with(name string, value any) map[string]any {
	fields := linkPayload()
	fields[name] = value
	return fields
}

func without(name string) map[string]any {
	fields := linkPayload()
	delete(fields, name)
	return fields
}

func embeddedOf(t *testing.T, raw string) *Embedded {
	t.Helper()
	input, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if input.Embedded == nil {
		t.Fatalf("Parse gave no embedded config: %+v", input)
	}
	return input.Embedded
}

func assertRejected(t *testing.T, raw string, want Failure) {
	t.Helper()
	_, err := Parse(raw)
	var parseErr *Error
	if !errors.As(err, &parseErr) {
		t.Fatalf("Parse accepted or gave a foreign error: %v", err)
	}
	if parseErr.Reason != want {
		t.Fatalf("Parse failed with %d, want %d", parseErr.Reason, want)
	}
}

// Настоящая ссылка из make_android_link бота: тот же файл проверяет Android.
func TestPythonGeneratedBotLinkPreservesConfigExactly(t *testing.T) {
	raw, err := os.ReadFile("testdata/python-connection-link.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]string
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	got := embeddedOf(t, fixture["link"])
	if got.Config != fixture["config"] || got.AccessToken != fixture["access_token"] {
		t.Fatalf("decoded %+v", got)
	}
	if !strings.Contains(got.Config, "#@wgt:VKLink = https://vk.com/call/join/example") {
		t.Fatal("TURN settings lost")
	}
}

func TestPastingKeepsTheWholeEmbeddedLink(t *testing.T) {
	got := embeddedOf(t, " \n"+mapLink(t, linkPayload())+"\n ")
	if got.Config != linkConfig || got.AccessToken != linkToken {
		t.Fatalf("decoded %+v", got)
	}
}

func TestEmbeddedDataWorksWithoutTheLegacyToken(t *testing.T) {
	link := strings.Replace(mapLink(t, linkPayload()), "token=primary-token&", "", 1)
	if got := embeddedOf(t, link); got.AccessToken != linkToken {
		t.Fatalf("decoded %+v", got)
	}
}

// data главнее токена: со сломанным data молча уйти за конфигом на сервер нельзя.
func TestBrokenDataNeverFallsBackToTheLegacyToken(t *testing.T) {
	for _, data := range []string{"", "a", "abc=", "hello"} {
		assertRejected(t, "wgkeybot://config?token="+linkToken+"&data="+data, FailInvalidData)
	}
	if _, err := Parse("wgkeybot://config?token=" + linkToken + "&data=%%%%"); err == nil {
		t.Fatal("bad escape accepted")
	}
	assertRejected(t, strings.Replace(mapLink(t, linkPayload()), "primary-token", "short", 1), FailInvalidData)
}

func TestLinkLengthLimitAcceptsTheBoundary(t *testing.T) {
	start := mapLink(t, linkPayload()) + "&padding="
	boundary := start + strings.Repeat("x", MaxLinkLength-len(start))
	embeddedOf(t, boundary)
	assertRejected(t, boundary+"x", FailInvalidFormat)
}

// Предел считается в байтах распакованного JSON, а не в символах.
func TestPayloadLimitIsExactAndCountsBytes(t *testing.T) {
	fields := linkPayload()
	size := len(marshalPayload(t, fields))
	fields["config"] = linkConfig + strings.Repeat("x", MaxPayloadBytes-size)
	if got := len(marshalPayload(t, fields)); got != MaxPayloadBytes {
		t.Fatalf("payload is %d bytes", got)
	}
	embeddedOf(t, mapLink(t, fields))

	for name, pad := range map[string]string{
		"one byte over": strings.Repeat("x", MaxPayloadBytes-size+1),
		"utf-8 bytes":   strings.Repeat("я", (MaxPayloadBytes-size)/2+1),
	} {
		t.Run(name, func(t *testing.T) {
			link := mapLink(t, with("config", linkConfig+pad))
			if len(link) >= MaxLinkLength {
				t.Fatalf("link of %d chars would fail for its length", len(link))
			}
			assertRejected(t, link, FailInvalidData)
		})
	}
}

func TestTruncatedCorruptAndTrailingBytesAreRejected(t *testing.T) {
	compressed := deflate(t, []byte(marshalPayload(t, linkPayload())))
	corrupt := bytes.Clone(compressed)
	corrupt[len(corrupt)-1] ^= 1
	for name, data := range map[string][]byte{
		"truncated":     compressed[:len(compressed)-1],
		"corrupt":       corrupt,
		"trailing byte": append(bytes.Clone(compressed), 0),
		"second stream": append(bytes.Clone(compressed), compressed...),
	} {
		t.Run(name, func(t *testing.T) {
			assertRejected(t, "wgkeybot://config?token="+linkToken+"&data="+encodeData(data), FailInvalidData)
		})
	}
}

func TestBase64MustBeCanonicalUnpaddedURLEncoding(t *testing.T) {
	good := encodeData(deflate(t, []byte(marshalPayload(t, linkPayload()))))
	for _, bad := range []string{good + "=", good + "+", good + "/", "%2B" + good} {
		assertRejected(t, "wgkeybot://config?data="+bad, FailInvalidData)
	}
}

// Лишние биты в последнем символе: те же байты, записанные неканонично.
func TestBase64WithStrayBitsInTheLastCharacterIsRejected(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var compressed []byte
	for pad := 0; len(compressed)%3 == 0; pad++ {
		compressed = deflate(t, []byte(marshalPayload(t, with("pad", strings.Repeat("x", pad)))))
	}
	good := encodeData(compressed)
	last := strings.IndexByte(alphabet, good[len(good)-1])
	bad := good[:len(good)-1] + string(alphabet[last+1])
	lenient, err := base64.RawURLEncoding.DecodeString(bad)
	if err != nil || !bytes.Equal(lenient, compressed) {
		t.Fatalf("test link is not the same bytes: %v", err)
	}
	embeddedOf(t, "wgkeybot://config?data="+good)
	assertRejected(t, "wgkeybot://config?data="+bad, FailInvalidData)
}

func TestInvalidUTF8AndExtraJSONAreRejected(t *testing.T) {
	payload := marshalPayload(t, linkPayload())
	for name, body := range map[string][]byte{
		"bad utf-8":  append([]byte(payload), 0xc3, 0x28),
		"extra json": []byte(payload + " {}"),
		"array":      []byte("[]"),
		"null":       []byte("null"),
	} {
		t.Run(name, func(t *testing.T) {
			assertRejected(t, "wgkeybot://config?data="+encodeData(deflate(t, body)), FailInvalidData)
		})
	}
}

func TestVersionRequiresTheSupportedInteger(t *testing.T) {
	for _, version := range []any{2, 0} {
		assertRejected(t, mapLink(t, with("version", version)), FailUnsupportedVersion)
	}
	for _, version := range []any{"1", 1.5, nil} {
		assertRejected(t, mapLink(t, with("version", version)), FailInvalidData)
	}
	assertRejected(t, mapLink(t, without("version")), FailInvalidData)
	spelledFloat := strings.Replace(marshalPayload(t, linkPayload()), `"version":1`, `"version":1.0`, 1)
	assertRejected(t, rawJSONLink(t, spelledFloat), FailInvalidData)
	spaced := strings.Replace(marshalPayload(t, linkPayload()), `"version":1`, `"version" : 1 `, 1)
	embeddedOf(t, rawJSONLink(t, spaced))
}

func TestEmbeddedAccessTokenMustBeAValidToken(t *testing.T) {
	for _, bad := range []any{"", "short", "../private-key-secret", "contains a space", 12345, nil} {
		assertRejected(t, mapLink(t, with("access_token", bad)), FailInvalidData)
	}
	assertRejected(t, mapLink(t, without("access_token")), FailInvalidData)
}

func TestExpiryRequiresStrictValidUTCSeconds(t *testing.T) {
	for _, bad := range []any{
		"", "2099-02-30T00:00:00Z", "2099-09-14T24:00:00Z", "2099-09-14T00:00:60Z",
		"2099-09-14T00:00:00+00:00", "2099-09-14T00:00:00.000Z", "2099-09-14", 12345, nil,
	} {
		assertRejected(t, mapLink(t, with("subscription_expires_at", bad)), FailInvalidData)
	}
	assertRejected(t, mapLink(t, without("subscription_expires_at")), FailInvalidData)
}

func TestConfigMustHaveInterfaceAndPeer(t *testing.T) {
	for _, bad := range []any{"", " ", "[Interface]", "[Peer]", linkConfig + "\x00", 12345, nil} {
		assertRejected(t, mapLink(t, with("config", bad)), FailInvalidConfig)
	}
	assertRejected(t, mapLink(t, without("config")), FailInvalidConfig)
}

func TestAmbiguousQueryAndUnexpectedShapeAreRejected(t *testing.T) {
	valid := mapLink(t, linkPayload())
	for _, bad := range []string{
		valid + "&data=bad", valid + "&token=" + linkToken, valid + "#fragment",
		strings.Replace(valid, "//config?", "//config/path?", 1),
		strings.Replace(valid, "//config?", "//user@config?", 1),
		strings.Replace(valid, "//config?", "//config:123?", 1),
	} {
		assertRejected(t, bad, FailInvalidFormat)
	}
}

func TestNestingIsRejected(t *testing.T) {
	const depth = 10_000
	nested := strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth)
	for name, payload := range map[string]string{
		"deep arrays":   nested,
		"deep objects":  strings.Repeat(`{"a":`, depth) + "0" + strings.Repeat("}", depth),
		"nested field":  strings.Replace(marshalPayload(t, linkPayload()), `"version":1`, `"version":1,"x":{"y":1}`, 1),
		"array field":   strings.Replace(marshalPayload(t, linkPayload()), `"version":1`, `"version":1,"x":[1]`, 1),
		"single quotes": fmt.Sprintf(`{'x':'"', 'y':%s, 'z':'"'}`, nested),
		"comments":      fmt.Sprintf(`{"x":0 /* " */, "y":%s, "z":0 /* " */}`, nested),
	} {
		t.Run(name, func(t *testing.T) {
			assertRejected(t, rawJSONLink(t, payload), FailInvalidData)
		})
	}
}

func TestUnknownScalarFieldsAreIgnored(t *testing.T) {
	embeddedOf(t, mapLink(t, with("future_field", "x")))
}

func TestJSONCharactersInsideConfigStayIntact(t *testing.T) {
	config := linkConfig + `# User's example / {"x":[1,2]} \ escaped` + "\n"
	if got := embeddedOf(t, mapLink(t, with("config", config))); got.Config != config {
		t.Fatalf("decoded %q", got.Config)
	}
}

// Текст ошибки уходит в окно: в ссылке приватный ключ.
func TestParserErrorsNeverExposeLinkSecrets(t *testing.T) {
	const secret = "private-key-secret-123456789"
	for _, bad := range []string{
		"wgkeybot://config?token=" + linkToken + "&data=" + secret,
		mapLink(t, with("config", secret)),
	} {
		_, err := Parse(bad)
		if err == nil {
			t.Fatal("accepted")
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(fmt.Sprintf("%+v", err), secret) {
			t.Fatalf("exposed the secret: %v", err)
		}
		if errors.Unwrap(err) != nil {
			t.Fatalf("carries a cause: %v", errors.Unwrap(err))
		}
	}
}

func TestLinkWithOnlyAToken(t *testing.T) {
	input, err := Parse("wgkeybot://config?token=" + linkToken)
	if err != nil || input.Token != linkToken || input.Embedded != nil {
		t.Fatalf("Parse = %+v, %v", input, err)
	}
}
