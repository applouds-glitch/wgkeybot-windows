//go:build windows

package tray

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/systray"
	"github.com/wgkeybot/windows/assets"
	"github.com/wgkeybot/windows/winbridge"
)

// Version отображается в пункте «О программе».
// Значение подставляется при сборке через -ldflags "-X .../tray.Version=...".
var Version = "dev"

// App manages the system tray icon and tunnel lifecycle.
type App struct {
	mu      sync.Mutex
	manager *winbridge.Manager
	cfg     *winbridge.TunnelConfig
	cancel  context.CancelFunc
	debug   bool

	settings winbridge.AppSettings

	connectedAt  time.Time
	statsRunning bool

	mConnect    *systray.MenuItem
	mDisconnect *systray.MenuItem
	mImport     *systray.MenuItem
	mUpdate     *systray.MenuItem
	mAutoConn   *systray.MenuItem
	mModeVPN    *systray.MenuItem
	mModeSOCKS  *systray.MenuItem
	mLog        *systray.MenuItem // nil when not in debug mode
	mAbout      *systray.MenuItem
	mQuit       *systray.MenuItem

	stopBlink      func() // stops connecting blink animation, nil when not blinking
	solvingCaptcha atomic.Bool
	connecting     bool // true while doConnect is in progress, prevents double-connect
}

// New creates the tray App. Pass debug=true to enable log file and log menu item.
func New(debug bool) *App {
	return &App{
		debug:    debug,
		settings: winbridge.LoadSettings(),
	}
}

// OnReady is called by systray when the tray is initialized.
func (a *App) OnReady() {
	if a.debug {
		winbridge.InitLogging()
	}

	systray.SetIcon(assets.IconDisconnected())
	systray.SetTooltip("Отключено")

	a.mConnect = systray.AddMenuItem("Подключить...", "Выбрать .conf и подключиться")
	a.mDisconnect = systray.AddMenuItem("Отключить", "Остановить VPN туннель")
	a.mDisconnect.Disable()
	systray.AddSeparator()
	a.mImport = systray.AddMenuItem("Импорт токена...", "Получить конфиг по токену")
	a.mUpdate = systray.AddMenuItem("Обновить конфиг", "Перезагрузить конфиг по сохранённому токену")
	a.mAutoConn = systray.AddMenuItem("Подключаться при запуске", "Автоматически поднимать VPN при старте")
	if a.settings.AutoConnect {
		a.mAutoConn.Check()
	}
	systray.AddSeparator()
	mMode := systray.AddMenuItem("Режим", "Выбор режима работы")
	a.mModeVPN = mMode.AddSubMenuItemCheckbox("VPN", "Весь трафик через туннель (нужны права администратора)", a.settings.Mode == winbridge.ModeVPN)
	a.mModeSOCKS = mMode.AddSubMenuItemCheckbox(
		fmt.Sprintf("SOCKS прокси (127.0.0.1:%d)", a.settings.SocksPort),
		"Локальный SOCKS5-прокси без захвата системы",
		a.settings.Mode == winbridge.ModeSOCKS,
	)
	systray.AddSeparator()
	a.mAbout = systray.AddMenuItem("О программе", "")
	if a.debug {
		systray.AddSeparator()
		a.mLog = systray.AddMenuItem("Открыть лог", "Открыть wgkeybot.log в блокноте")
	}
	systray.AddSeparator()
	a.mQuit = systray.AddMenuItem("Выход", "Закрыть WgKeyBot")

	go a.eventLoop()

	if a.settings.AutoConnect {
		go a.doAutoConnect()
	}
}

// OnExit is called by systray on exit — clean up the tunnel.
func (a *App) OnExit() {
	a.mu.Lock()
	mgr := a.manager
	cancel := a.cancel
	a.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if mgr != nil {
		mgr.Disconnect()
	}
}

func (a *App) eventLoop() {
	var logCh <-chan struct{}
	if a.mLog != nil {
		logCh = a.mLog.ClickedCh
	}

	for {
		select {
		case <-a.mConnect.ClickedCh:
			go a.doConnect()
		case <-a.mDisconnect.ClickedCh:
			go a.doDisconnect()
		case <-a.mImport.ClickedCh:
			go a.doImport()
		case <-a.mUpdate.ClickedCh:
			go a.doUpdate()
		case <-a.mAutoConn.ClickedCh:
			a.doAutoConnectToggle()
		case <-a.mModeVPN.ClickedCh:
			a.doSetMode(winbridge.ModeVPN)
		case <-a.mModeSOCKS.ClickedCh:
			a.doSetMode(winbridge.ModeSOCKS)
		case <-a.mAbout.ClickedCh:
			ShowInfo("О программе",
				fmt.Sprintf("WgKeyBot v%s\n\nWireGuard VPN клиент\nс TURN/DTLS прокси\n\n© 2026 WgKeyBot", Version))
		case <-logCh:
			go OpenFile(winbridge.LogPath)
		case <-a.mQuit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

// ── Actions ────────────────────────────────────────────────────────────────────

func (a *App) doAutoConnectToggle() {
	if a.mAutoConn.Checked() {
		a.mAutoConn.Uncheck()
		a.settings.AutoConnect = false
	} else {
		a.mAutoConn.Check()
		a.settings.AutoConnect = true
	}
	winbridge.SaveSettings(a.settings)
}

// doSetMode переключает режим работы (vpn / socks). Запрещено при активном
// туннеле — сначала нужно отключиться.
func (a *App) doSetMode(mode winbridge.Mode) {
	a.mu.Lock()
	busy := a.manager != nil || a.connecting
	a.mu.Unlock()

	if busy {
		// Восстанавливаем отметки — клик не должен менять состояние «на лету».
		a.refreshModeChecks()
		go ShowInfo("Смена режима", "Сначала отключитесь, затем выберите режим.")
		return
	}

	a.settings.Mode = mode
	winbridge.SaveSettings(a.settings)
	a.refreshModeChecks()
}

// refreshModeChecks выставляет галочки подменю в соответствии с a.settings.Mode.
func (a *App) refreshModeChecks() {
	if a.settings.Mode == winbridge.ModeSOCKS {
		a.mModeSOCKS.Check()
		a.mModeVPN.Uncheck()
	} else {
		a.mModeVPN.Check()
		a.mModeSOCKS.Uncheck()
	}
}

func (a *App) doAutoConnect() {
	a.mu.Lock()
	if a.manager != nil || a.connecting {
		a.mu.Unlock()
		return
	}
	a.connecting = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.connecting = false
		a.mu.Unlock()
	}()

	confPath, err := a.resolveConfig()
	if err != nil {
		return
	}

	cfg, err := winbridge.ParseEncryptedConfig(confPath)
	if err != nil {
		return
	}

	mgr := winbridge.NewManager(cfg)
	mgr.SetMode(a.settings.Mode, a.settings.SocksPort)
	ctx, cancel := context.WithCancel(context.Background())

	a.mu.Lock()
	a.manager = mgr
	a.cfg = cfg
	a.cancel = cancel
	a.mu.Unlock()

	a.setConnecting()

	if err := mgr.Connect(ctx); err != nil {
		log.Printf("[Tray] auto-connect error: %v", err)
		a.mu.Lock()
		a.manager = nil
		a.cancel = nil
		a.mu.Unlock()
		cancel()
		a.setDisconnected()
		return
	}

	a.setConnected()
	go a.watchStatus(ctx)
	mgr.StartWatchdog(ctx, func() { go a.doWatchdogReconnect() })
}

func (a *App) doConnect() {
	a.mu.Lock()
	if a.manager != nil || a.connecting {
		a.mu.Unlock()
		return
	}
	a.connecting = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.connecting = false
		a.mu.Unlock()
	}()

	confPath, err := a.resolveConfig()
	if err != nil {
		log.Printf("[Tray] config resolve error: %v", err)
		go ShowError("Ошибка выбора конфига", err.Error())
		return
	}
	if confPath == "" {
		return
	}

	cfg, err := winbridge.ParseEncryptedConfig(confPath)
	if err != nil {
		go ShowError("Ошибка конфига", err.Error())
		return
	}

	mgr := winbridge.NewManager(cfg)
	mgr.SetMode(a.settings.Mode, a.settings.SocksPort)
	ctx, cancel := context.WithCancel(context.Background())

	a.mu.Lock()
	a.manager = mgr
	a.cfg = cfg
	a.cancel = cancel
	a.mu.Unlock()

	a.setConnecting()

	if err := mgr.Connect(ctx); err != nil {
		log.Printf("[Tray] connect error: %v", err)
		a.mu.Lock()
		a.manager = nil
		a.cancel = nil
		a.mu.Unlock()
		cancel()
		a.setDisconnected()
		if !errors.Is(err, context.Canceled) {
			go ShowError("Ошибка подключения", err.Error())
		}
		return
	}

	a.setConnected()
	go a.watchStatus(ctx)
	mgr.StartWatchdog(ctx, func() { go a.doWatchdogReconnect() })
}

// doWatchdogReconnect вызывается watchdog'ом когда WG handshake умер.
// Отключает текущий туннель и переподключается с тем же конфигом.
func (a *App) doWatchdogReconnect() {
	a.mu.Lock()
	cfg := a.cfg
	mode := a.settings.Mode
	socksPort := a.settings.SocksPort
	if a.connecting || cfg == nil {
		a.mu.Unlock()
		return
	}
	a.connecting = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.connecting = false
		a.mu.Unlock()
	}()

	log.Printf("[Tray] Watchdog triggered reconnect")
	a.teardown()

	// Остаёмся в "connecting" состоянии — кнопка "Отключить" остаётся активной.
	a.setConnecting()
	go Notify("WgKeyBot", "Соединение потеряно — переподключение...", niifWarning)

	// Прерываемая 3-секундная пауза: храним cancel в a.cancel, чтобы
	// doDisconnect мог прервать ожидание через teardown().
	delayCtx, delayCancel := context.WithCancel(context.Background())
	a.mu.Lock()
	a.cancel = delayCancel
	a.mu.Unlock()

	select {
	case <-delayCtx.Done():
		// Пользователь нажал "Отключить" — teardown уже почистил a.cancel.
		a.setDisconnected()
		return
	case <-time.After(3 * time.Second):
	}

	// Снимаем cancel паузы и переходим к реальному подключению.
	// (Если сюда дошли, значит time.After сработал раньше teardown — пауза прошла.)
	a.mu.Lock()
	a.cancel = nil
	a.mu.Unlock()
	delayCancel()

	mgr := winbridge.NewManager(cfg)
	mgr.SetMode(mode, socksPort)
	ctx, cancel := context.WithCancel(context.Background())

	a.mu.Lock()
	a.manager = mgr
	a.cfg = cfg
	a.cancel = cancel
	a.mu.Unlock()

	if err := mgr.Connect(ctx); err != nil {
		log.Printf("[Tray] watchdog reconnect error: %v", err)
		a.mu.Lock()
		a.manager = nil
		a.cancel = nil
		a.mu.Unlock()
		cancel()
		a.setDisconnected()
		return
	}

	a.setConnected()
	go a.watchStatus(ctx)
	mgr.StartWatchdog(ctx, func() { go a.doWatchdogReconnect() })
}

func (a *App) doDisconnect() {
	if a.teardown() {
		a.setDisconnected()
	}
}

// teardown синхронно останавливает активный туннель, если он есть.
// Возвращает true, если была отменена любая активность (туннель или ожидающий
// reconnect), чтобы doDisconnect мог перейти в disconnected-состояние.
func (a *App) teardown() bool {
	a.mu.Lock()
	mgr := a.manager
	cancel := a.cancel
	a.manager = nil
	a.cancel = nil
	a.mu.Unlock()

	hadActivity := cancel != nil
	if cancel != nil {
		cancel()
	}
	if mgr != nil {
		mgr.Disconnect()
		hadActivity = true
	}
	return hadActivity
}

func (a *App) doImport() {
	token, err := InputDialog("WgKeyBot Импорт", "Введите токен WgKeyBot:")
	if err != nil {
		log.Printf("[Tray] input dialog error: %v", err)
		return
	}
	if token == "" {
		return
	}

	data, err := winbridge.FetchConfigFromToken(token)
	if err != nil {
		go ShowError("Ошибка импорта", err.Error())
		return
	}

	if _, err := winbridge.SaveConfig(data); err != nil {
		go ShowError("Ошибка сохранения", err.Error())
		return
	}

	// Сохраняем токен, чтобы потом можно было обновить конфиг без повторного ввода.
	a.settings.Token = token
	winbridge.SaveSettings(a.settings)

	go Notify("Импорт", "Настройки подключения получены", niifInfo)
}

// doUpdate перезагружает конфиг по сохранённому токену.
func (a *App) doUpdate() {
	if a.settings.Token == "" {
		go ShowError("Обновление конфига",
			"Токен не сохранён.\nСначала выполните «Импорт токена...».")
		return
	}

	data, err := winbridge.FetchConfigFromToken(a.settings.Token)
	if err != nil {
		go ShowError("Ошибка обновления", err.Error())
		return
	}

	if _, err := winbridge.SaveConfig(data); err != nil {
		go ShowError("Ошибка сохранения", err.Error())
		return
	}

	// Если VPN активен — переподключаемся на свежий конфиг.
	a.mu.Lock()
	connected := a.manager != nil
	a.mu.Unlock()

	if connected {
		go Notify("Обновление", "Конфиг обновлён, переподключение...", niifInfo)
		a.teardown()
		a.doConnect()
		return
	}

	go Notify("Обновление", "Конфиг обновлён", niifInfo)
}

// ── Status monitoring ──────────────────────────────────────────────────────────

func (a *App) watchStatus(ctx context.Context) {
	a.mu.Lock()
	a.statsRunning = true
	a.mu.Unlock()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		a.mu.Lock()
		mgr := a.manager
		connAt := a.connectedAt
		a.mu.Unlock()
		if mgr == nil {
			return
		}

		if url := mgr.PendingCaptchaURL(); url != "" && !a.solvingCaptcha.Swap(true) {
			go func() {
				defer a.solvingCaptcha.Store(false)
				a.handleCaptcha(ctx, mgr, url)
			}()
		}

		mgr.CheckNetworkChange()

		systray.SetTooltip(buildTooltip(time.Since(connAt), mgr.Stats(), a.settings))
	}
}

// buildTooltip формирует понятную обычному пользователю подсказку для иконки.
func buildTooltip(uptime time.Duration, st winbridge.TunnelStats, settings winbridge.AppSettings) string {
	if !st.Connected {
		return "Отключено"
	}

	header := "Защита включена"
	if settings.Mode == winbridge.ModeSOCKS {
		header = fmt.Sprintf("SOCKS прокси 127.0.0.1:%d", settings.SocksPort)
	}
	// Если рукопожатия не было дольше 3 минут — связь с сервером потеряна.
	if st.LastHandshake.IsZero() || time.Since(st.LastHandshake) > 3*time.Minute {
		header = "Восстановление связи…"
	}

	line2 := "В сети: " + formatDuration(uptime)
	line3 := fmt.Sprintf("↓ %s  ↑ %s",
		humanBytes(st.RxBytes), humanBytes(st.TxBytes))

	return header + "\n" + line2 + "\n" + line3
}

// humanBytes форматирует размер в привычных пользователю единицах.
func humanBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f ГБ", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f МБ", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f КБ", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d Б", b)
	}
}

func (a *App) handleCaptcha(ctx context.Context, mgr *winbridge.Manager, url string) {
	log.Printf("[Tray] Captcha required during operation")
	token, err := winbridge.SolveCaptchaProxy(ctx, url)
	if err != nil {
		log.Printf("[Tray] Captcha solve error: %v", err)
		return
	}
	mgr.SolveCaptcha(token)
}

// ── UI state ───────────────────────────────────────────────────────────────────

func (a *App) setConnecting() {
	a.cancelBlink()
	systray.SetIcon(assets.IconConnecting())
	systray.SetTooltip("Подключение…")
	a.mConnect.Disable()
	a.mDisconnect.Enable()

	done := make(chan struct{})
	a.stopBlink = func() { close(done) }
	go func() {
		ticker := time.NewTicker(600 * time.Millisecond)
		defer ticker.Stop()
		on := true
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if on {
					systray.SetIcon(assets.IconDisconnected())
				} else {
					systray.SetIcon(assets.IconConnecting())
				}
				on = !on
			}
		}
	}()
}

func (a *App) setConnected() {
	a.cancelBlink()
	a.mu.Lock()
	a.connectedAt = time.Now()
	a.mu.Unlock()
	systray.SetIcon(assets.IconConnected())
	if a.settings.Mode == winbridge.ModeSOCKS {
		addr := fmt.Sprintf("127.0.0.1:%d", a.settings.SocksPort)
		systray.SetTooltip("SOCKS прокси " + addr)
		go Notify("SOCKS прокси", "Запущен на "+addr, niifInfo)
	} else {
		systray.SetTooltip("Защита включена")
		go Notify("VPN", "Подключено", niifInfo)
	}
	a.mConnect.Disable()
	a.mDisconnect.Enable()
}

func (a *App) setDisconnected() {
	a.cancelBlink()
	systray.SetIcon(assets.IconDisconnected())
	systray.SetTooltip("Отключено")
	a.mConnect.Enable()
	a.mDisconnect.Disable()
	go Notify("VPN", "Отключено", niifInfo)
}

func (a *App) cancelBlink() {
	if a.stopBlink != nil {
		a.stopBlink()
		a.stopBlink = nil
	}
}

// ── Config ─────────────────────────────────────────────────────────────────────

// resolveConfig возвращает путь к единственному конфигу. Выбора между
// несколькими конфигами нет — приложение хранит ровно один.
func (a *App) resolveConfig() (string, error) {
	path := winbridge.DefaultConfigPath()
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	// Миграция: старые сборки хранили конфиг под именем по токену.
	// Если новый config.wgkbot ещё не создан, берём первый найденный.
	if configs, _ := winbridge.ListConfigs(); len(configs) > 0 {
		return configs[0], nil
	}

	return "", fmt.Errorf(
		"Конфиг не найден.\n\nИспользуйте «Импорт токена...» чтобы добавить конфиг.",
	)
}

func formatDuration(d time.Duration) string {
	m := int(d.Minutes())
	if m < 1 {
		return "<1м"
	}
	h := m / 60
	m = m % 60
	if h > 0 {
		return fmt.Sprintf("%dч%02dм", h, m)
	}
	return fmt.Sprintf("%dм", m)
}
