package winbridge

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wgkeybot/windows/pkg/proxy"
)

// TunnelConfig — полная конфигурация тоннеля, прочитанная из .conf-файла.
type TunnelConfig struct {
	// Стандартный WireGuard [Interface]
	PrivateKey string
	Address    []string // CIDR-адреса интерфейса
	DNS        []string
	MTU        int

	// Стандартный WireGuard [Peer]
	PublicKey           string
	PresharedKey        string
	Endpoint            string // оригинальный endpoint из конфига
	AllowedIPs          []string
	PersistentKeepalive int

	// TURN-настройки (из #@wgt: комментариев)
	TURN proxy.Config

	// Имя тоннеля (имя файла без .conf)
	Name string
}

// ParseConfFile читает .conf файл WireGuard с опциональными #@wgt: расширениями.
func ParseConfFile(path string) (*TunnelConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfBytes(data, path)
}

// parseConfBytes парсит WireGuard конфиг из байтов.
// path используется только для извлечения имени тоннеля.
func parseConfBytes(data []byte, path string) (*TunnelConfig, error) {
	cfg := &TunnelConfig{MTU: 1280}

	// Имя тоннеля = имя файла без расширения
	base := path
	if idx := strings.LastIndexAny(base, `/\`); idx >= 0 {
		base = base[idx+1:]
	}
	// Убираем любое расширение (.conf, .wgkbot, ...)
	if idx := strings.LastIndex(base, "."); idx >= 0 {
		base = base[:idx]
	}
	cfg.Name = base

	var section string
	var wgtLines []string

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#@wgt:") {
			wgtLines = append(wgtLines, line)
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)

		switch section {
		case "interface":
			switch strings.ToLower(k) {
			case "privatekey":
				cfg.PrivateKey = v
			case "address":
				cfg.Address = append(cfg.Address, splitCSV(v)...)
			case "dns":
				cfg.DNS = append(cfg.DNS, splitCSV(v)...)
			case "mtu":
				if n, err := strconv.Atoi(v); err == nil {
					cfg.MTU = n
				}
			}
		case "peer":
			switch strings.ToLower(k) {
			case "publickey":
				cfg.PublicKey = v
			case "presharedkey":
				cfg.PresharedKey = v
			case "endpoint":
				cfg.Endpoint = v
			case "allowedips":
				cfg.AllowedIPs = append(cfg.AllowedIPs, splitCSV(v)...)
			case "persistentkeepalive":
				if n, err := strconv.Atoi(v); err == nil {
					cfg.PersistentKeepalive = n
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	parseTURNSettings(wgtLines, &cfg.TURN)
	return cfg, nil
}

// parseTURNSettings заполняет proxy.Config из списка #@wgt: строк.
func parseTURNSettings(lines []string, t *proxy.Config) {
	for _, line := range lines {
		if !strings.HasPrefix(line, "#@wgt:") {
			continue
		}
		k, v, ok := strings.Cut(line[6:], "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "enableturn":
			// Флаг включения — просто наличие @wgt: секции уже подразумевает включение
		case "vklink":
			t.VKLink = v
		case "useudp":
			t.UseUDP = strings.EqualFold(v, "true")
		case "streamnum":
			if n, err := strconv.Atoi(v); err == nil {
				t.StreamsTotal = clamp(n, 1, 128)
			}
		case "localport":
			if n, err := strconv.Atoi(v); err == nil {
				t.ListenAddr = fmt.Sprintf("127.0.0.1:%d", clamp(n, 1, 65535))
			}
		case "ipport":
			t.PeerAddr = v
		case "turnip":
			t.TurnIP = v
		case "turnport":
			if n, err := strconv.Atoi(v); err == nil {
				t.TurnPort = clamp(n, 1, 65535)
			}
		case "peertype":
			t.PeerType = v
		case "streamspercred":
			if n, err := strconv.Atoi(v); err == nil {
				t.StreamsPerCred = clamp(n, 1, 16)
			}
		case "watchdogtimeout":
			if n, err := strconv.Atoi(v); err == nil && n >= 5 {
				t.WatchdogSecs = n
			}
		case "wrapkey":
			t.WrapKey = v
		}
	}
}

// BuildWGUAPIConfig строит строку конфигурации в формате WireGuard UAPI.
// listenAddr — адрес TURN-прокси (127.0.0.1:PORT), заменяет оригинальный Endpoint.
func (c *TunnelConfig) BuildWGUAPIConfig(listenAddr string) string {
	var sb strings.Builder

	// [Interface]
	sb.WriteString("private_key=" + keyToHex(c.PrivateKey) + "\n")

	// [Peer]
	sb.WriteString("public_key=" + keyToHex(c.PublicKey) + "\n")
	if c.PresharedKey != "" {
		sb.WriteString("preshared_key=" + keyToHex(c.PresharedKey) + "\n")
	}

	endpoint := listenAddr
	if endpoint == "" {
		endpoint = c.Endpoint
	}
	sb.WriteString("endpoint=" + endpoint + "\n")

	for _, a := range c.AllowedIPs {
		sb.WriteString("allowed_ip=" + strings.TrimSpace(a) + "\n")
	}
	if c.PersistentKeepalive > 0 {
		sb.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", c.PersistentKeepalive))
	}

	return sb.String()
}

// FetchConfigFromToken загружает конфиг с key.shadowgate.online по токену.
// API возвращает JSON: {"ok": true, "config": "[Interface]\n..."}.
func FetchConfigFromToken(token string) ([]byte, error) {
	apiURL := "https://key.shadowgate.online/api/config/" + strings.TrimSpace(token)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var result struct {
		OK     bool   `json:"ok"`
		Config string `json:"config"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if !result.OK {
		if result.Error != "" {
			return nil, fmt.Errorf("server error: %s", result.Error)
		}
		return nil, fmt.Errorf("server returned ok=false")
	}
	if result.Config == "" {
		return nil, fmt.Errorf("empty config in response")
	}
	return []byte(result.Config), nil
}

// DefaultConfigDir возвращает директорию хранения конфигов.
func DefaultConfigDir() string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = os.TempDir()
	}
	return appData + `\WgKeyBot`
}

// DefaultConfigPath возвращает путь к единственному конфигу приложения.
// Приложение хранит ровно один конфиг — без выбора между несколькими.
func DefaultConfigPath() string {
	return DefaultConfigDir() + `\config.wgkbot`
}

// SaveConfig шифрует конфиг через DPAPI и сохраняет в единственный файл
// config.wgkbot. Файл нечитаем без Windows-аккаунта пользователя.
// Любые устаревшие конфиги удаляются — должен остаться только один.
func SaveConfig(data []byte) (string, error) {
	dir := DefaultConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}
	path := DefaultConfigPath()

	encrypted, err := encryptDPAPI(data)
	if err != nil {
		return "", fmt.Errorf("encrypt config: %w", err)
	}

	if _, err := os.Stat(path); err == nil {
		os.Rename(path, path+".bak")
	}
	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}

	// Удаляем устаревшие конфиги (в т.ч. со старыми именами по токену),
	// чтобы в директории остался ровно один config.wgkbot.
	if old, _ := ListConfigs(); len(old) > 0 {
		for _, p := range old {
			if p != path {
				os.Remove(p)
			}
		}
	}
	return path, nil
}

// ParseEncryptedConfig расшифровывает .wgkbot файл и парсит его как WireGuard конфиг.
func ParseEncryptedConfig(path string) (*TunnelConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	plaintext, err := decryptDPAPI(raw)
	if err != nil {
		return nil, fmt.Errorf("decrypt config: %w", err)
	}
	return parseConfBytes(plaintext, path)
}

// ListConfigs возвращает пути ко всем .wgkbot файлам в DefaultConfigDir.
func ListConfigs() ([]string, error) {
	dir := DefaultConfigDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".wgkbot") {
			paths = append(paths, dir+`\`+e.Name())
		}
	}
	return paths, nil
}

// splitCSV разбивает строку через запятую, убирая пробелы.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// keyToHex converts a base64-encoded WireGuard key to lowercase hex.
// wireguard-go IpcSet only accepts hex for private_key/public_key/preshared_key.
func keyToHex(b64key string) string {
	b64key = strings.TrimSpace(b64key)
	if b64key == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil {
		// Try without padding (some configs omit it)
		raw, err = base64.RawStdEncoding.DecodeString(b64key)
		if err != nil {
			return b64key // already hex or unknown format — pass through
		}
	}
	return hex.EncodeToString(raw)
}

// ValidateEndpoint проверяет, что строка является корректным host:port.
func ValidateEndpoint(ep string) error {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return err
	}
	if host == "" || port == "" {
		return fmt.Errorf("empty host or port in endpoint %q", ep)
	}
	return nil
}
