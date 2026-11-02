//go:build windows

package tray

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/wgkeybot/windows/pkg/expert"
	"github.com/wgkeybot/windows/winbridge"
)

// Окно режима эксперта (порт Android AppSettingsActivity/VkLinksActivity,
// 90e408ec): свои MTU и DNS туннеля и свои ссылки на VK-звонки поверх конфига
// бота, с проверкой ссылок у VK без капчи. Всё действует со следующего
// подключения; выключение режима возвращает конфиг таким, каким его выдал бот,
// значения при этом сохраняются.

const (
	idExpEnabled = 200 + iota
	idExpMTUConfig
	idExpMTU1200
	idExpMTU1280
	idExpMTUCustom
	idExpDNSConfig
	idExpDNSCustom
	idExpDNSPreset0 // + индекс в dnsPresets
	_
	_
	_
	_
	idExpCheckOwn
	idExpCheckConfig
	idExpSave
)

// dnsPresets — резолверы, которые подставляются в поле одной кнопкой.
var dnsPresets = []struct{ name, servers string }{
	{"Cloudflare", "1.1.1.1, 1.0.0.1"},
	{"Google", "8.8.8.8, 8.8.4.4"},
	{"Quad9", "9.9.9.9, 149.112.112.112"},
	{"AdGuard", "94.140.14.14, 94.140.15.15"},
	{"Яндекс", "77.88.8.8, 77.88.8.1"},
}

var pGetWindowTextLength = user32dll.NewProc("GetWindowTextLengthW")

// editText читает текст поля ввода.
func editText(c *nativeControl) string {
	n, _, _ := pGetWindowTextLength.Call(c.hwnd)
	buf := make([]uint16, n+1)
	pGetWindowText.Call(c.hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf)
}

// setEditText пишет в поле ввода мимо кеша setText: пользователь мог изменить
// текст, и кеш о нём не знает.
func setEditText(c *nativeControl, text string) {
	c.text = text
	pSetWindowText.Call(c.hwnd, uintptr(unsafe.Pointer(nativeString(text))))
}

// linkCheckState — идущая (или последняя) проверка ссылок. Одна за раз; живёт
// дольше окна, как VkLinkChecker на Android: закрытое окно не обрывает
// проверку, открытое снова показывает её итог.
type linkCheckState struct {
	mu      sync.Mutex
	running bool
	text    string
}

func (s *linkCheckState) snapshot() (running bool, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running, s.text
}

// runLinkCheck проверяет links по очереди; false — предыдущая проверка ещё идёт.
func (a *App) runLinkCheck(title string, links []string) bool {
	s := &a.linkCheck
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return false
	}
	s.running = true
	s.text = title
	s.mu.Unlock()
	go func() {
		lines := []string{title}
		for i, link := range links {
			s.mu.Lock()
			s.text = strings.Join(append(lines, fmt.Sprintf("Проверяем %d из %d…", i+1, len(links))), "\r\n")
			s.mu.Unlock()
			lines = append(lines, linkVerdictText(i+1, winbridge.CheckVKLink(context.Background(), link)))
		}
		s.mu.Lock()
		s.running = false
		s.text = strings.Join(lines, "\r\n")
		s.mu.Unlock()
	}()
	return true
}

func linkVerdictText(n int, code int32) string {
	switch code {
	case winbridge.LinkCheckOK:
		return fmt.Sprintf("Ссылка %d: звонок жив", n)
	case winbridge.LinkCheckRequiresAuth:
		return fmt.Sprintf("Ссылка %d: звонок требует входа в VK", n)
	case winbridge.LinkCheckUnavailable:
		return fmt.Sprintf("Ссылка %d: звонок завершён или ссылка неверна", n)
	case winbridge.LinkCheckCaptcha:
		return fmt.Sprintf("Ссылка %d: VK требует капчу, проверить нельзя", n)
	case winbridge.LinkCheckTemporary:
		return fmt.Sprintf("Ссылка %d: VK не ответил, попробуйте позже", n)
	default:
		return fmt.Sprintf("Ссылка %d: VK отклонил запрос", n)
	}
}

// openExpert показывает окно режима эксперта, открывая его при необходимости.
func (a *App) openExpert() {
	if hwnd := a.expertWindow.Load(); hwnd != 0 {
		pPostMessage.Call(hwnd, wmShowDashboard, 0, 0)
		return
	}
	if !a.expertOpening.CompareAndSwap(false, true) {
		return
	}
	go a.runExpertWindow()
}

func (a *App) runExpertWindow() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer a.expertOpening.Store(false)

	a.mu.Lock()
	settings := a.settings
	saved := a.savedConfig
	a.mu.Unlock()
	e := settings.ExpertSettings()

	cfgMTU := "Из конфига"
	cfgDNS := "Из конфига"
	var configLinks []string
	if saved != nil {
		cfgMTU = fmt.Sprintf("Из конфига (%d)", saved.MTU)
		if len(saved.DNS) > 0 {
			cfgDNS = fmt.Sprintf("Из конфига (%s)", strings.Join(saved.DNS, ", "))
		}
		configLinks = expert.SplitConfigLinks(saved.TURN.VKLink)
	}

	w, err := newNativeWindow("Режим эксперта", 600, 562, 0)
	if err != nil {
		log.Printf("[UI] expert: %v", err)
		go ShowError("Режим эксперта", "Не удалось открыть окно.")
		return
	}
	defer w.dispose()
	a.expertWindow.Store(w.hwnd)
	defer a.expertWindow.Store(0)

	const editStyle = 0x00800000 | 0x0080 | wsTabstop                                 // WS_BORDER | ES_AUTOHSCROLL
	const multiStyle = 0x00800000 | 0x00200000 | 0x0004 | 0x0040 | 0x1000 | wsTabstop // + WS_VSCROLL, ES_MULTILINE, ES_AUTOVSCROLL, ES_WANTRETURN

	w.label("Режим эксперта", 24, 14, 552, 30, 1)
	enabled := w.add("BUTTON", "Переопределить настройки из конфига бота", bsCheckbox|wsTabstop|wsGroup, idExpEnabled, 24, 48, 552, 24, 0)
	w.label("Действует при следующем подключении. Выключение режима возвращает конфиг таким, каким его выдал бот; значения сохраняются.", 24, 74, 552, 36, 0)

	w.add("BUTTON", "MTU туннеля", bsGroupbox, 0, 24, 114, 552, 72, 0)
	mtuRadios := []*nativeControl{
		w.add("BUTTON", cfgMTU, bsRadiobutton|wsTabstop|wsGroup, idExpMTUConfig, 40, 136, 190, 24, 0),
		w.add("BUTTON", "1200", bsRadiobutton|wsTabstop, idExpMTU1200, 236, 136, 70, 24, 0),
		w.add("BUTTON", "1280", bsRadiobutton|wsTabstop, idExpMTU1280, 310, 136, 70, 24, 0),
		w.add("BUTTON", "Своё:", bsRadiobutton|wsTabstop, idExpMTUCustom, 386, 136, 76, 24, 0),
	}
	mtuEdit := w.add("EDIT", "", editStyle|0x2000, 0, 466, 134, 94, 26, 0) // ES_NUMBER
	w.label("1200 — запас для сотовых сетей, 1280 — как выдаёт бот, своё — от 1000 до 1500", 40, 162, 520, 20, 0)

	w.add("BUTTON", "DNS внутри туннеля", bsGroupbox, 0, 24, 192, 552, 100, 0)
	dnsConfig := w.add("BUTTON", cfgDNS, bsRadiobutton|wsTabstop|wsGroup, idExpDNSConfig, 40, 214, 520, 24, 0)
	dnsCustom := w.add("BUTTON", "Свои:", bsRadiobutton|wsTabstop, idExpDNSCustom, 40, 240, 72, 24, 0)
	dnsEdit := w.add("EDIT", "", editStyle, 0, 116, 238, 444, 26, 0)
	var presets []*nativeControl
	for i, p := range dnsPresets {
		presets = append(presets, w.add("BUTTON", p.name, wsTabstop, idExpDNSPreset0+i, 40+i*104, 266, 96, 24, 0))
	}

	w.add("BUTTON", "Ссылки на VK-звонки", bsGroupbox, 0, 24, 298, 552, 212, 0)
	w.label("Свои ссылки — по одной на строку, до 8; пусто — ссылки из конфига. Каждая ссылка — отдельные креды, а каждые креды могут стоить капчи.", 40, 318, 520, 36, 0)
	linksEdit := w.add("EDIT", "", multiStyle, 0, 40, 356, 520, 58, 0)
	pSendMessage.Call(linksEdit.hwnd, 0x00c5, 4096, 0) // EM_SETLIMITTEXT
	checkOwn := w.add("BUTTON", "Проверить", wsTabstop, idExpCheckOwn, 40, 420, 120, 28, 0)
	checkConfig := w.add("BUTTON", fmt.Sprintf("Проверить ссылки из конфига (%d)", len(configLinks)), wsTabstop, idExpCheckConfig, 170, 420, 280, 28, 0)
	results := w.add("EDIT", "", 0x00800000|0x00200000|0x0004|0x0040|0x0800|wsTabstop, 0, 40, 454, 520, 50, 0) // read-only

	status := w.label("", 24, 520, 330, 36, 0)
	w.add("BUTTON", "Сохранить", bsPushbutton|wsTabstop|wsGroup, idExpSave, 372, 522, 100, 30, 0)
	w.add("BUTTON", "Закрыть", wsTabstop, 2, 480, 522, 96, 30, 0)

	// Состояние окна — только на его потоке.
	on := e.Enabled
	mtuMode := 0
	switch e.MTU {
	case 0:
	case 1200:
		mtuMode = 1
	case 1280:
		mtuMode = 2
	default:
		mtuMode = 3
		setEditText(mtuEdit, strconv.Itoa(e.MTU))
	}
	dnsMode := 0
	if e.DNS != "" {
		dnsMode = 1
		setEditText(dnsEdit, e.DNS)
	}
	setEditText(linksEdit, strings.ReplaceAll(strings.ReplaceAll(e.VKLinks, "\r\n", "\n"), "\n", "\r\n"))

	refresh := func() {
		enabled.check(on)
		for i, r := range mtuRadios {
			r.check(i == mtuMode)
			r.enable(on)
		}
		mtuEdit.enable(on && mtuMode == 3)
		dnsConfig.check(dnsMode == 0)
		dnsCustom.check(dnsMode == 1)
		dnsConfig.enable(on)
		dnsCustom.enable(on)
		dnsEdit.enable(on && dnsMode == 1)
		for _, p := range presets {
			p.enable(on)
		}
		linksEdit.enable(on)
	}
	refresh()

	save := func() {
		next := expert.Settings{Enabled: on}
		switch mtuMode {
		case 1:
			next.MTU = 1200
		case 2:
			next.MTU = 1280
		case 3:
			mtu, err := strconv.Atoi(strings.TrimSpace(editText(mtuEdit)))
			if err != nil || !expert.ValidMTU(mtu) {
				status.setText("Введите MTU — число от 1000 до 1500")
				return
			}
			next.MTU = mtu
		}
		if dnsMode == 1 {
			text := editText(dnsEdit)
			servers, bad := expert.ParseDNS(text)
			if len(bad) > 0 {
				status.setText("Не IPv4-адрес: " + strings.Join(bad, ", "))
				return
			}
			if len(servers) == 0 {
				status.setText("Укажите IPv4-адреса через запятую")
				return
			}
			next.DNS = strings.Join(servers, ", ")
		}
		next.VKLinks = strings.TrimSpace(editText(linksEdit))
		parsed := expert.ParseLinks(next.VKLinks)
		if len(parsed.Invalid) > 0 {
			status.setText("Не ссылка на VK-звонок: " + strings.Join(parsed.Invalid, ", "))
			return
		}
		a.mu.Lock()
		err := a.settings.SetExpertSettings(next)
		if err == nil {
			winbridge.SaveSettings(a.settings)
		}
		a.mu.Unlock()
		switch {
		case err != nil:
			status.setText("Не удалось сохранить: " + err.Error())
		case parsed.Truncated:
			status.setText("Сохранено. Не больше 8 ссылок, лишние отброшены")
		default:
			status.setText("Сохранено. Действует при следующем подключении")
		}
	}

	w.close = func() { pDestroyWindow.Call(w.hwnd) }
	w.command = func(id int) {
		switch {
		case id == 2:
			w.close()
		case id == idExpEnabled:
			on = !on
		case id >= idExpMTUConfig && id <= idExpMTUCustom:
			mtuMode = id - idExpMTUConfig
			if mtuMode == 3 {
				pSetFocus.Call(mtuEdit.hwnd)
			}
		case id == idExpDNSConfig:
			dnsMode = 0
		case id == idExpDNSCustom:
			dnsMode = 1
			pSetFocus.Call(dnsEdit.hwnd)
		case id >= idExpDNSPreset0 && id < idExpDNSPreset0+len(dnsPresets):
			dnsMode = 1
			setEditText(dnsEdit, dnsPresets[id-idExpDNSPreset0].servers)
		case id == idExpCheckOwn:
			parsed := expert.ParseLinks(editText(linksEdit))
			switch {
			case len(parsed.Invalid) > 0:
				status.setText("Не ссылка на VK-звонок: " + strings.Join(parsed.Invalid, ", "))
			case len(parsed.Hashes) == 0:
				status.setText("Ссылок нет")
			case !a.runLinkCheck("Свои ссылки:", parsed.Hashes):
				status.setText("Предыдущая проверка ещё идёт")
			default:
				status.setText("")
			}
		case id == idExpCheckConfig:
			switch {
			case len(configLinks) == 0:
				status.setText("Ссылок в конфиге нет")
			case !a.runLinkCheck("Ссылки из конфига:", configLinks):
				status.setText("Предыдущая проверка ещё идёт")
			default:
				status.setText("")
			}
		case id == idExpSave:
			save()
		}
		refresh()
	}
	w.tick = func() {
		running, text := a.linkCheck.snapshot()
		results.setText(text)
		checkOwn.enable(!running)
		checkConfig.enable(!running)
	}
	pSetTimer.Call(w.hwnd, 1, 300, 0)
	if err := w.run(); err != nil {
		log.Printf("[UI] expert loop: %v", err)
	}
}
