package winbridge

import (
	"encoding/json"
	"os"
)

// AppSettings хранит пользовательские настройки приложения.
type AppSettings struct {
	AutoConnect bool   `json:"auto_connect"`
	LastConfig  string `json:"last_config"`
}

// LoadSettings загружает настройки из %APPDATA%\WgKeyBot\settings.json.
func LoadSettings() AppSettings {
	path := DefaultConfigDir() + `\settings.json`
	data, err := os.ReadFile(path)
	if err != nil {
		return AppSettings{}
	}
	var s AppSettings
	if json.Unmarshal(data, &s) != nil {
		return AppSettings{}
	}
	return s
}

// SaveSettings сохраняет настройки в %APPDATA%\WgKeyBot\settings.json.
func SaveSettings(s AppSettings) {
	dir := DefaultConfigDir()
	os.MkdirAll(dir, 0700)
	data, _ := json.MarshalIndent(s, "", "  ")
	os.WriteFile(dir+`\settings.json`, data, 0600)
}
