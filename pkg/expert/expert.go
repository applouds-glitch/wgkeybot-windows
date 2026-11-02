// Package expert — режим эксперта: переопределения того, что говорит конфиг
// бота, для ближайшего подключения (порт Android ExpertSettings/ExpertOverrides/
// VkLinks, 90e408ec).
//
// Почему не правкой .conf: бот перевыдаёт конфиг (обновление сравнивает хеши и
// перезаписывает файл), и правка тихо пропала бы при следующем обновлении.
// Хранятся отдельно (winbridge, settings.json, ссылки под DPAPI) и
// накладываются на копию конфига при каждом подключении; сохранённый конфиг не
// трогается. Пока режим выключен, ни одно значение не действует, но и не
// стирается: включение возвращает их как были.
package expert

import (
	"net/netip"
	"regexp"
	"strings"
)

const (
	// MaxLinks — сколько ссылок читает прокси (parseLinks берёт до восьми).
	MaxLinks = 8

	// MTUMin и MTUMax — границы своего MTU. Нижняя — с запасом над минимумом
	// WireGuard для странных путей у операторов (туннели бота IPv4, так что
	// 1280 для IPv6 не обязателен), верхняя — Ethernet: поверх TURN каждый
	// внутренний пакет прибавляет на проводе ~110 байт, и всё выше только
	// фрагментируется.
	MTUMin = 1000
	MTUMax = 1500
)

// Settings — то, что хранится между запусками.
type Settings struct {
	Enabled bool
	MTU     int    // 0 — из конфига
	DNS     string // IPv4 через запятую; "" — из конфига
	VKLinks string // ссылки как их ввёл пользователь; "" — из конфига
}

// Overrides — что ближайшее подключение берёт вместо значений конфига. Нулевое
// поле — «как в конфиге».
type Overrides struct {
	MTU     int
	DNS     []string
	VKLinks []string // хеши join-ссылок
}

// Empty — ничего не переопределено.
func (o Overrides) Empty() bool { return o.MTU == 0 && len(o.DNS) == 0 && len(o.VKLinks) == 0 }

// Overrides — переопределения для ближайшего подключения; ok=false, пока режим
// выключен. Сохранённое значение, которое больше не разбирается (окно такого не
// пишет, но хранилище — не парсер), считается «из конфига».
func (s Settings) Overrides() (o Overrides, ok bool) {
	if !s.Enabled {
		return Overrides{}, false
	}
	if ValidMTU(s.MTU) {
		o.MTU = s.MTU
	}
	if dns, bad := ParseDNS(s.DNS); len(bad) == 0 {
		o.DNS = dns
	}
	o.VKLinks = ParseLinks(s.VKLinks).Hashes
	return o, true
}

// ValidMTU — MTU в допустимых границах.
func ValidMTU(mtu int) bool { return mtu >= MTUMin && mtu <= MTUMax }

// ParseDNS разбирает IPv4-адреса через запятую (пробелы вокруг допустимы).
// Пустой текст — пустой список. bad — записи, которые не IPv4-адрес: имена
// (резолвер сам не может быть именем), адреса с портом, IPv6 — туннель
// прокладывает в себя только IPv4, и IPv6-резолвер на адаптере ушёл бы мимо
// него.
func ParseDNS(text string) (servers, bad []string) {
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil || !addr.Is4() {
			bad = append(bad, part)
			continue
		}
		servers = append(servers, addr.String())
	}
	return servers, bad
}

// linkHashShape — форма хеша join-ссылки. Широкая нарочно: хеши VK
// непрозрачны, а слишком строгая проверка отвергла бы живой звонок; живую
// ссылку от сломанной отличает проверка у самого VK.
var linkHashShape = regexp.MustCompile(`^[A-Za-z0-9_-]{6,128}$`)

// LinkHash сводит ссылку на звонок (или голый хеш) к хешу, как это делает
// прокси (joinHash), — ссылка, принятая здесь, ровно та строка, с которой
// подключение пойдёт в звонок. ok=false — текст не ссылка на звонок.
func LinkHash(raw string) (hash string, ok bool) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return "", false
	}
	if i := strings.LastIndex(text, "join/"); i >= 0 {
		text = text[i+len("join/"):]
	}
	if i := strings.IndexAny(text, "/?#"); i >= 0 {
		text = text[:i]
	}
	if !linkHashShape.MatchString(text) {
		return "", false
	}
	return text, true
}

// ParsedLinks — что лежит в поле ссылок.
type ParsedLinks struct {
	Hashes    []string // по порядку, без повторов, не больше MaxLinks
	Invalid   []string // записи, которые не ссылка на звонок
	Truncated bool     // что-то отрезано по MaxLinks
}

// ParseLinks разбирает поле ссылок: записи разделяются переводами строк,
// запятыми, вертикальной чертой и пробелами.
func ParseLinks(text string) ParsedLinks {
	var p ParsedLinks
	entries := strings.FieldsFunc(text, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == '|' || r == ' ' || r == '\t'
	})
	for _, entry := range entries {
		hash, ok := LinkHash(entry)
		switch {
		case !ok:
			p.Invalid = append(p.Invalid, entry)
		case !contains(p.Hashes, hash):
			p.Hashes = append(p.Hashes, hash)
		}
	}
	if len(p.Hashes) > MaxLinks {
		p.Hashes, p.Truncated = p.Hashes[:MaxLinks], true
	}
	return p
}

// SplitConfigLinks делит значение #@wgt:VKLink так же, как прокси.
func SplitConfigLinks(vkLink string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(vkLink, func(r rune) bool { return r == ',' || r == '|' }) {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
