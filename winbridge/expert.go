//go:build windows

package winbridge

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"github.com/wgkeybot/windows/pkg/expert"
	"github.com/wgkeybot/windows/pkg/proxy"
)

// ExpertStored — режим эксперта в settings.json (см. pkg/expert). Ссылки на
// звонки лежат под DPAPI: join-ссылка пускает в звонок кого угодно, а
// settings.json — обычный файл в профиле.
type ExpertStored struct {
	Enabled bool   `json:"enabled,omitempty"`
	MTU     int    `json:"mtu,omitempty"`
	DNS     string `json:"dns,omitempty"`
	VKLinks string `json:"vk_links_dpapi,omitempty"` // base64(DPAPI(текст ссылок))
}

// ExpertSettings возвращает настройки режима эксперта. Ссылки, которые не
// расшифровались (профиль перенесён на другую машину), считаются пустыми —
// подключение возьмёт ссылки из конфига.
func (s AppSettings) ExpertSettings() expert.Settings {
	e := expert.Settings{Enabled: s.Expert.Enabled, MTU: s.Expert.MTU, DNS: s.Expert.DNS}
	if s.Expert.VKLinks == "" {
		return e
	}
	blob, err := base64.StdEncoding.DecodeString(s.Expert.VKLinks)
	if err == nil {
		var text []byte
		if text, err = decryptDPAPI(blob); err == nil {
			e.VKLinks = string(text)
		}
	}
	if err != nil {
		log.Printf("[Expert] own VK links unreadable (%v) — the config's links are used", err)
	}
	return e
}

// SetExpertSettings записывает настройки режима эксперта (сохраняет их на диск
// вызывающий — SaveSettings).
func (s *AppSettings) SetExpertSettings(e expert.Settings) error {
	stored := ExpertStored{Enabled: e.Enabled, MTU: e.MTU, DNS: strings.TrimSpace(e.DNS)}
	if links := strings.TrimSpace(e.VKLinks); links != "" {
		blob, err := encryptDPAPI([]byte(links))
		if err != nil {
			return fmt.Errorf("шифрование ссылок: %w", err)
		}
		stored.VKLinks = base64.StdEncoding.EncodeToString(blob)
	}
	s.Expert = stored
	return nil
}

// ApplyExpert накладывает режим эксперта на копию cfg — ту, с которой поднимется
// подключение (и с которой переподключится watchdog). Сохранённый конфиг и его
// хеш не трогаются: обновление конфига сравнивает их с тем, что выдал бот.
// expertOn — режим включён и что-то переопределил.
func ApplyExpert(cfg *TunnelConfig, e expert.Settings) (out *TunnelConfig, expertOn bool) {
	o, ok := e.Overrides()
	if !ok || o.Empty() {
		return cfg, false
	}
	c := *cfg
	mtu, dns, links := "из конфига", "из конфига", "из конфига"
	if o.MTU != 0 {
		mtu = fmt.Sprintf("%d (конфиг %d)", o.MTU, cfg.MTU)
		c.MTU = o.MTU
	}
	if len(o.DNS) > 0 {
		dns = fmt.Sprintf("%s (в конфиге %d)", strings.Join(o.DNS, ", "), len(cfg.DNS))
		c.DNS = append([]string(nil), o.DNS...)
	}
	if len(o.VKLinks) > 0 {
		links = fmt.Sprintf("%d своих (в конфиге %d)", len(o.VKLinks), len(expert.SplitConfigLinks(cfg.TURN.VKLink)))
		c.TURN.VKLink = strings.Join(o.VKLinks, ",")
	}
	// Ссылки в журнал не пишутся — только их число.
	log.Printf("[Expert] Режим эксперта: MTU %s, DNS %s, ссылки VK %s", mtu, dns, links)
	return &c, true
}

// CheckVKLink спрашивает VK, жив ли звонок по ссылке (proxy.CheckVKLink): только
// бескапчевый поток, без кеша кредов, при поднятом туннеле — мимо него.
func CheckVKLink(ctx context.Context, link string) int32 {
	return proxy.CheckVKLink(ctx, link)
}

// Вердикты CheckVKLink.
const (
	LinkCheckOK           = proxy.LinkCheckOK
	LinkCheckTemporary    = proxy.LinkCheckTemporary
	LinkCheckRequiresAuth = proxy.LinkCheckRequiresAuth
	LinkCheckCaptcha      = proxy.LinkCheckCaptcha
	LinkCheckUnavailable  = proxy.LinkCheckUnavailable
	LinkCheckRefused      = proxy.LinkCheckRefused
)
