//go:build windows

package tray

import (
	"fmt"
	"log"
	"runtime"
	"strings"
	"time"

	"github.com/wgkeybot/windows/winbridge"
)

const (
	idConnect = 100 + iota
	idDisconnect
	idVPN
	idSOCKS
	idImport
	idRefresh
	idAutoConnect
	idAutoRefresh
	idCheckUpdate
)

// Stats are sampled off the window's message thread. Config keys and tokens
// are never included in display text.
type dashboardSnapshot struct {
	status, hint, config, configNote, received, sent, total, session string
	busy, canConnect, canDisconnect, refreshing, checkingUpdate      bool
	settings                                                         winbridge.AppSettings
}

func (a *App) loadConfigInfo() {
	path, err := a.resolveConfig()
	var cfg *winbridge.TunnelConfig
	if err == nil {
		cfg, err = winbridge.ParseEncryptedConfig(path)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.savedConfig = cfg
	a.configError = ""
	if err != nil {
		a.configError = "Конфиг недоступен. Импортируйте токен для подключения."
	}
}

func (a *App) dashboardSnapshot() dashboardSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := dashboardSnapshot{settings: a.settings, busy: a.manager != nil || a.connecting || a.disconnecting,
		canDisconnect: a.cancel != nil, refreshing: a.refreshing.Load(), checkingUpdate: a.checkingUpdate.Load()}
	s.canConnect = !s.busy && !s.refreshing && a.savedConfig != nil
	s.status = "Отключено"
	s.hint = "VPN направляет системный трафик по маршрутам конфига."
	if a.settings.Mode == winbridge.ModeSOCKS {
		s.hint = fmt.Sprintf("SOCKS5 · 127.0.0.1:%d · настройте прокси в нужном приложении.", a.settings.SocksPort)
	}
	s.session = "Трафик текущего соединения · сброс при подключении"
	if a.disconnecting {
		s.status = "Отключение…"
	} else if a.connecting {
		s.status = "Подключение…"
	} else if a.manager != nil && a.stats.Connected {
		s.status = "Подключено"
		if a.stats.LastHandshake.IsZero() {
			s.status = "Ожидание ответа WireGuard…"
		} else if time.Since(a.stats.LastHandshake) > 3*time.Minute {
			s.status = "Восстановление связи…"
		}
		s.session = "В сети: " + formatDuration(time.Since(a.connectedAt)) + " · трафик текущего соединения"
	} else if a.stats.RxBytes != 0 || a.stats.TxBytes != 0 {
		s.session = "Трафик последнего соединения · сброс при подключении"
	}
	s.received, s.sent = humanBytes(a.stats.RxBytes), humanBytes(a.stats.TxBytes)
	s.total = humanBytes(a.stats.RxBytes + a.stats.TxBytes)
	cfg := a.savedConfig
	s.configNote = "Сохранённый конфиг"
	if a.manager != nil && a.cfg != nil {
		cfg = a.cfg
		s.configNote = "Активный конфиг"
		if a.activeConfigHash != a.settings.LastConfigHash {
			s.configNote += " · есть обновление для следующего подключения"
		}
	}
	if cfg == nil {
		s.config = a.configError
	} else {
		endpoint := cfg.Endpoint
		if cfg.TURN.PeerAddr != "" {
			endpoint = cfg.TURN.PeerAddr
		}
		s.config = fmt.Sprintf("Сервер: %s\r\nАдрес: %s\r\nDNS: %s · MTU: %d\r\nМаршруты: %s",
			endpoint, strings.Join(cfg.Address, ", "), strings.Join(cfg.DNS, ", "), cfg.MTU, strings.Join(cfg.AllowedIPs, ", "))
		if !a.settings.LastRefresh.IsZero() {
			s.config += "\r\nПроверен: " + a.settings.LastRefresh.Local().Format("02.01.2006 15:04")
		}
	}
	return s
}

func (a *App) runDashboard() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	w, err := newNativeWindow("WgKeyBot", 660, 548, 0)
	if err != nil {
		log.Printf("[UI] dashboard: %v", err)
		go ShowError("WgKeyBot", "Не удалось открыть главное окно. Приложение доступно в трее.")
		return
	}
	defer w.dispose()
	a.dashboard.Store(w.hwnd)
	defer a.dashboard.Store(0)
	if a.exiting.Load() {
		return
	}

	w.label("WgKeyBot", 24, 16, 350, 32, 1)
	w.label("v"+Version, 380, 26, 90, 22, 0)
	checkUpdate := w.add("BUTTON", "Проверить обновление", wsTabstop, idCheckUpdate, 470, 20, 166, 30, 0)
	status := w.label("Отключено", 24, 58, 612, 28, 2)
	w.add("BUTTON", "Режим подключения", bsGroupbox, 0, 24, 94, 612, 96, 0)
	vpn := w.add("BUTTON", "&VPN", bsRadiobutton|wsTabstop|wsGroup, idVPN, 40, 116, 84, 26, 0)
	socks := w.add("BUTTON", "SOCKS5 &прокси", bsRadiobutton|wsTabstop, idSOCKS, 130, 116, 174, 26, 0)
	connect := w.add("BUTTON", "Подключить", bsPushbutton|wsTabstop|wsGroup, idConnect, 336, 112, 138, 32, 0)
	disconnect := w.add("BUTTON", "Отключить", bsPushbutton|wsTabstop, idDisconnect, 484, 112, 136, 32, 0)
	hint := w.label("", 40, 154, 576, 26, 0)
	w.add("BUTTON", "Трафик WireGuard", bsGroupbox, 0, 24, 200, 612, 104, 0)
	w.label("Получено", 40, 222, 170, 20, 0)
	w.label("Отправлено", 240, 222, 170, 20, 0)
	w.label("Всего", 440, 222, 172, 20, 0)
	rx := w.label("0 Б", 40, 242, 172, 26, 2)
	tx := w.label("0 Б", 240, 242, 172, 26, 2)
	total := w.label("0 Б", 440, 242, 172, 26, 2)
	session := w.label("", 40, 276, 576, 22, 0)
	note := w.label("Сохранённый конфиг", 24, 316, 612, 22, 0)
	// Read-only edit gives long config values scrolling and standard copy support.
	config := w.add("EDIT", "", 0x00800000|0x00200000|0x0800|0x0004|0x0040|wsTabstop, 0, 24, 342, 612, 98, 0)
	importButton := w.add("BUTTON", "&Импорт токена…", wsTabstop, idImport, 24, 452, 178, 32, 0)
	refresh := w.add("BUTTON", "Обновить конфиг", wsTabstop, idRefresh, 212, 452, 178, 32, 0)
	autoConnect := w.add("BUTTON", "Подключаться при запуске", bsCheckbox|wsTabstop, idAutoConnect, 24, 490, 292, 26, 0)
	autoRefresh := w.add("BUTTON", "Автообновление конфига", bsCheckbox|wsTabstop, idAutoRefresh, 338, 490, 298, 26, 0)
	w.label("Закрытие окна сворачивает приложение в трей. Выход — через меню трея.", 24, 524, 612, 22, 0)
	w.close = func() { pShowWindow.Call(w.hwnd, 0) }
	w.command = func(id int) {
		if id == 2 {
			w.close()
			return
		}
		var action func()
		switch id {
		case idConnect:
			action = func() { go a.doConnect() }
		case idDisconnect:
			action = func() { go a.doDisconnect() }
		case idVPN:
			action = func() { a.doSetMode(winbridge.ModeVPN) }
		case idSOCKS:
			action = func() { a.doSetMode(winbridge.ModeSOCKS) }
		case idImport:
			action = func() { go a.doImport() }
		case idRefresh:
			action = func() { go a.doUpdate() }
		case idAutoConnect:
			action = a.doAutoConnectToggle
		case idAutoRefresh:
			action = a.doAutoRefreshToggle
		case idCheckUpdate:
			action = func() { go a.doCheckUpdate() }
		}
		if action != nil {
			select {
			case a.actions <- action:
			default:
			}
		}
	}
	w.tick = func() {
		s := a.dashboardSnapshot()
		status.setText(s.status)
		hint.setText(s.hint)
		note.setText(s.configNote)
		config.setText(s.config)
		rx.setText(s.received)
		tx.setText(s.sent)
		total.setText(s.total)
		session.setText(s.session)
		vpn.check(s.settings.Mode == winbridge.ModeVPN)
		socks.check(s.settings.Mode == winbridge.ModeSOCKS)
		vpn.enable(!s.busy)
		socks.enable(!s.busy)
		connect.enable(s.canConnect)
		disconnect.enable(s.canDisconnect)
		importButton.enable(!s.refreshing)
		refresh.enable(!s.refreshing && s.settings.AccessToken != "")
		autoConnect.check(s.settings.AutoConnect)
		autoRefresh.check(!s.settings.AutoRefreshDisabled)
		checkUpdate.enable(!s.checkingUpdate)
		if s.checkingUpdate {
			checkUpdate.setText("Проверяем…")
		} else {
			checkUpdate.setText("Проверить обновление")
		}
		if s.refreshing {
			refresh.setText("Обработка…")
		} else {
			refresh.setText("Обновить конфиг")
		}
	}
	pSetTimer.Call(w.hwnd, 1, 500, 0)
	if err := w.run(); err != nil {
		log.Printf("[UI] dashboard loop: %v", err)
		go ShowError("WgKeyBot", "Не удалось открыть главное окно. Приложение доступно в трее.")
	}
}
