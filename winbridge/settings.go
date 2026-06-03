package winbridge

import (
	"encoding/json"
	"os"
)

// Mode определяет, как поднимать туннель: полноценный VPN или локальный SOCKS-прокси.
type Mode string

const (
	// ModeVPN — wintun-интерфейс + системная маршрутизация (весь трафик в туннеле).
	ModeVPN Mode = "vpn"
	// ModeSOCKS — userspace netstack + локальный SOCKS5 на 127.0.0.1:SocksPort.
	ModeSOCKS Mode = "socks"
)

// DefaultSocksPort — порт локального SOCKS5-сервера по умолчанию.
const DefaultSocksPort = 1080

// AppSettings хранит пользовательские настройки приложения.
type AppSettings struct {
	AutoConnect bool `json:"auto_connect"`
	// AccessToken — Bearer-токен для /api/v1/config, полученный при init.
	AccessToken string `json:"access_token,omitempty"`
	// Mode — режим работы туннеля (vpn / socks). По умолчанию vpn.
	Mode Mode `json:"mode"`
	// SocksPort — порт локального SOCKS5-сервера в режиме socks.
	SocksPort int `json:"socks_port"`
}

// normalize проставляет дефолты для отсутствующих/некорректных полей.
func (s *AppSettings) normalize() {
	if s.Mode != ModeVPN && s.Mode != ModeSOCKS {
		s.Mode = ModeVPN
	}
	if s.SocksPort < 1 || s.SocksPort > 65535 {
		s.SocksPort = DefaultSocksPort
	}
}

// LoadSettings загружает настройки из %APPDATA%\WgKeyBot\settings.json.
func LoadSettings() AppSettings {
	path := DefaultConfigDir() + `\settings.json`
	data, err := os.ReadFile(path)
	if err != nil {
		s := AppSettings{}
		s.normalize()
		return s
	}
	var s AppSettings
	if json.Unmarshal(data, &s) != nil {
		s = AppSettings{}
	}
	s.normalize()
	return s
}

// SaveSettings сохраняет настройки в %APPDATA%\WgKeyBot\settings.json.
func SaveSettings(s AppSettings) {
	dir := DefaultConfigDir()
	os.MkdirAll(dir, 0700)
	data, _ := json.MarshalIndent(s, "", "  ")
	os.WriteFile(dir+`\settings.json`, data, 0600)
}
