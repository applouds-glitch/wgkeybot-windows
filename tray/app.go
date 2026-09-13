//go:build windows

package tray

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
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

	connectedAt      time.Time
	stats            winbridge.TunnelStats
	savedConfig      *winbridge.TunnelConfig
	configError      string
	activeConfigHash string
	dashboard        atomic.Uintptr
	exiting          atomic.Bool
	actions          chan func()
	disconnecting    bool
	blinkMu          sync.Mutex

	mOpen *systray.MenuItem

	mConnect    *systray.MenuItem
	mDisconnect *systray.MenuItem
	mImport     *systray.MenuItem
	mUpdate     *systray.MenuItem
	mAutoConn   *systray.MenuItem
	mAutoRefr   *systray.MenuItem
	mModeVPN    *systray.MenuItem
	mModeSOCKS  *systray.MenuItem
	mLog        *systray.MenuItem // nil when not in debug mode
	mAbout      *systray.MenuItem
	mQuit       *systray.MenuItem

	stopBlink      func() // stops connecting blink animation, nil when not blinking
	solvingCaptcha atomic.Bool
	connecting     bool // true while doConnect is in progress, prevents double-connect

	// refreshing — идёт запрос конфига (ручной или фоновый); второй параллельный
	// не запускается. nextAutoRefresh — unix-время, раньше которого фоновое
	// обновление не пробует снова: после неудачи, чтобы не долбить control plane
	// каждые 5 секунд опроса статуса.
	refreshing      atomic.Bool
	nextAutoRefresh atomic.Int64
}

const (
	// autoRefreshInterval — как часто фоновое обновление ходит за конфигом.
	// Как на Android: раз в 12 часов, только через поднятый туннель.
	autoRefreshInterval = 12 * time.Hour
	// autoRefreshRetry — пауза после неудачной фоновой попытки.
	autoRefreshRetry = 30 * time.Minute
)

// New creates the tray App. Pass debug=true to enable log file and log menu item.
func New(debug bool) *App {
	winbridge.AppVersion = Version
	return &App{
		debug:    debug,
		settings: winbridge.LoadSettings(),
		actions:  make(chan func(), 32),
	}
}

// OnReady is called by systray when the tray is initialized.
func (a *App) OnReady() {
	if a.debug {
		winbridge.InitLogging()
	}

	systray.SetIcon(assets.IconDisconnected())
	systray.SetTooltip("Отключено")

	a.mOpen = systray.AddMenuItem("Открыть WgKeyBot", "Состояние, конфиг и трафик")
	systray.AddSeparator()
	a.mConnect = systray.AddMenuItem("Подключить", "Подключиться с сохранённым конфигом")
	a.mDisconnect = systray.AddMenuItem("Отключить", "Остановить VPN туннель")
	a.mDisconnect.Disable()
	systray.AddSeparator()
	a.mImport = systray.AddMenuItem("Импорт токена...", "Получить конфиг по токену")
	a.mUpdate = systray.AddMenuItem("Обновить конфиг", "Перезагрузить конфиг по сохранённому токену")
	a.mAutoConn = systray.AddMenuItem("Подключаться при запуске", "Автоматически поднимать VPN при старте")
	if a.settings.AutoConnect {
		a.mAutoConn.Check()
	}
	a.mAutoRefr = systray.AddMenuItem("Обновлять конфиг автоматически", "Раз в 12 часов проверять конфиг через поднятый туннель")
	if !a.settings.AutoRefreshDisabled {
		a.mAutoRefr.Check()
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

	a.loadConfigInfo()
	go a.runDashboard()
	go a.eventLoop()

	if a.settingsSnapshot().AutoConnect {
		go a.doAutoConnect()
	}
}

// OnExit is called by systray on exit — clean up the tunnel.
func (a *App) OnExit() {
	a.exiting.Store(true)
	if hwnd := a.dashboard.Load(); hwnd != 0 {
		pPostMessage.Call(hwnd, wmDispose, 0, 0)
	}
	a.cancelBlink()
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
		case action := <-a.actions:
			action()
		case <-a.mOpen.ClickedCh:
			if hwnd := a.dashboard.Load(); hwnd != 0 {
				pPostMessage.Call(hwnd, wmShowDashboard, 0, 0)
			}
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
		case <-a.mAutoRefr.ClickedCh:
			a.doAutoRefreshToggle()
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
	a.mu.Lock()
	a.settings.AutoConnect = !a.settings.AutoConnect
	winbridge.SaveSettings(a.settings)
	enabled := a.settings.AutoConnect
	a.mu.Unlock()
	if enabled {
		a.mAutoConn.Check()
	} else {
		a.mAutoConn.Uncheck()
	}
}

func (a *App) doAutoRefreshToggle() {
	a.mu.Lock()
	a.settings.AutoRefreshDisabled = !a.settings.AutoRefreshDisabled
	winbridge.SaveSettings(a.settings)
	disabled := a.settings.AutoRefreshDisabled
	a.mu.Unlock()
	if disabled {
		a.mAutoRefr.Uncheck()
	} else {
		a.mAutoRefr.Check()
	}
}

func (a *App) doSetMode(mode winbridge.Mode) {
	a.mu.Lock()
	busy := a.manager != nil || a.connecting || a.disconnecting
	if !busy {
		a.settings.Mode = mode
		winbridge.SaveSettings(a.settings)
	}
	a.mu.Unlock()
	a.refreshModeChecks()
	if busy {
		go ShowInfo("Смена режима", "Сначала отключитесь, затем выберите режим.")
	}
}

func (a *App) settingsSnapshot() winbridge.AppSettings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings
}

func (a *App) refreshModeChecks() {
	if a.settingsSnapshot().Mode == winbridge.ModeSOCKS {
		a.mModeSOCKS.Check()
		a.mModeVPN.Uncheck()
	} else {
		a.mModeVPN.Check()
		a.mModeSOCKS.Uncheck()
	}
}

func (a *App) doAutoConnect() { a.connect(true) }

func (a *App) doConnect() { a.connect(false) }

func (a *App) connect(automatic bool) {
	a.mu.Lock()
	if a.manager != nil || a.connecting || a.disconnecting || a.exiting.Load() {
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
		if !automatic {
			go ShowError("Ошибка выбора конфига", err.Error())
		}
		return
	}
	if confPath == "" {
		return
	}

	cfg, err := winbridge.ParseEncryptedConfig(confPath)
	if err != nil {
		if !automatic {
			go ShowError("Ошибка конфига", err.Error())
		}
		return
	}

	mgr := winbridge.NewManager(cfg)
	settings := a.settingsSnapshot()
	mgr.SetMode(settings.Mode, settings.SocksPort)
	ctx, cancel := context.WithCancel(context.Background())

	a.mu.Lock()
	if a.exiting.Load() {
		a.mu.Unlock()
		cancel()
		return
	}
	a.manager = mgr
	a.cfg = cfg
	a.activeConfigHash = a.settings.LastConfigHash
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
		if !automatic && !errors.Is(err, context.Canceled) {
			go ShowError("Ошибка подключения", err.Error())
		}
		return
	}

	if !a.setConnected(mgr) {
		return
	}
	go a.watchStatus(ctx, mgr)
	mgr.StartWatchdog(ctx,
		func() { go a.doWatchdogReconnect() },
		func(reason string) { go a.doTurnFatal(mgr, reason) })
}

// doWatchdogReconnect вызывается watchdog'ом когда WG handshake умер.
// Отключает текущий туннель и переподключается с тем же конфигом.
func (a *App) doWatchdogReconnect() {
	a.mu.Lock()
	cfg := a.cfg
	mode := a.settings.Mode
	socksPort := a.settings.SocksPort
	if a.connecting || a.disconnecting || a.manager == nil || cfg == nil || a.exiting.Load() {
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

	if !a.setConnected(mgr) {
		return
	}
	go a.watchStatus(ctx, mgr)
	mgr.StartWatchdog(ctx,
		func() { go a.doWatchdogReconnect() },
		func(reason string) { go a.doTurnFatal(mgr, reason) })
}

// doTurnFatal вызывается, когда TURN-прокси сообщил, что все воркеры сдались:
// капча не решается, либо звонок умер уже после подключения. Реконнект здесь
// бессмысленен — он уедет в ту же стену, — поэтому просто отключаемся и
// показываем причину.
//
// mgr — тот Manager, чей watchdog вызвал этот колбэк (захвачен в замыкании на
// месте вызова StartWatchdog). Между стартом watchdog-горутины и её срабатыванием
// пользователь (или сам watchdog другим путём — doWatchdogReconnect) мог успеть
// создать новый Manager; в этом случае a.manager уже не mgr, и разрывать текущее
// (другое, возможно рабочее) соединение по устаревшему сигналу нельзя — no-op.
func (a *App) doTurnFatal(mgr *winbridge.Manager, reason string) {
	a.mu.Lock()
	current := a.manager
	a.mu.Unlock()
	if current != mgr {
		log.Printf("[Tray] TURN fatal from a stale manager, ignoring: %s", reason)
		return
	}

	log.Printf("[Tray] TURN fatal: %s", reason)
	go Notify("VPN", "Соединение остановлено: "+turnFatalMessage(reason), niifError)
	a.doDisconnect()
}

// turnFatalMessage переводит причину из turnFatalReason() (сырой err.Error()
// из pkg/proxy, часто на английском) в русский текст для баллуна — теми же
// формулировками, что Connect использует для тех же состояний
// (ReadyStatusAuthRequired/ReadyStatusCallUnavailable, winbridge/tunnel.go),
// чтобы пользователь не видел два разных объяснения одной и той же причины
// в зависимости от того, оборвалось соединение при подключении или посреди
// сессии.
func turnFatalMessage(reason string) string {
	switch {
	case strings.Contains(reason, "CALL_REQUIRES_AUTH"):
		return "VK авторизация устарела (CALL_REQUIRES_AUTH) — обновите конфиг через «Import token»"
	case strings.Contains(reason, "CALL_UNAVAILABLE"):
		return "VK-звонок завершён/удалён или ссылка недействительна (CALL_UNAVAILABLE) — получите новую ссылку и обновите конфиг"
	default:
		return "не удалось восстановить соединение — попробуйте переподключиться позже или обновите конфиг"
	}
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
	if a.disconnecting {
		a.mu.Unlock()
		return false
	}
	mgr, cancel := a.manager, a.cancel
	a.manager, a.cancel = nil, nil
	a.disconnecting = true
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.disconnecting = false; a.mu.Unlock() }()
	if cancel != nil {
		cancel()
	}
	if mgr != nil {
		// Retain final counters after disconnection; the next connect resets them.
		st := mgr.Stats()
		mgr.Disconnect()
		a.mu.Lock()
		if st.Connected {
			a.stats = st
		}
		a.stats.Connected = false
		a.mu.Unlock()
	}
	return cancel != nil || mgr != nil
}

func (a *App) doImport() {
	if !a.refreshing.CompareAndSwap(false, true) {
		return
	}
	defer a.refreshing.Store(false)
	token, err := InputDialog("WgKeyBot Импорт", "Введите токен WgKeyBot:")
	if err != nil {
		log.Printf("[Tray] input dialog error: %v", err)
		return
	}
	if token == "" {
		return
	}

	data, accessToken, err := winbridge.InitFromToken(token)
	if err != nil {
		var upg *winbridge.UpgradeRequiredError
		if errors.As(err, &upg) {
			go ShowError("Требуется обновление", upg.Error())
		} else {
			go ShowError("Ошибка импорта", err.Error())
		}
		return
	}

	if _, err := winbridge.SaveConfig(data); err != nil {
		go ShowError("Ошибка сохранения", err.Error())
		return
	}

	a.mu.Lock()
	a.settings.AccessToken = accessToken
	a.settings.LastConfigHash = winbridge.ConfigHash(data)
	a.settings.LastRefresh = time.Now()
	winbridge.SaveSettings(a.settings)
	a.mu.Unlock()
	a.loadConfigInfo()

	go Notify("Импорт", "Настройки подключения получены", niifInfo)
}

// doUpdate — пункт меню «Обновить конфиг».
func (a *App) doUpdate() { a.refreshConfig(true) }

// refreshConfig запрашивает конфиг у control plane по сохранённому
// access_token. Ручной вызов (manual) применяет его сразу — с переподключением,
// если туннель поднят, — и отчитывается пользователю. Фоновый только
// сохраняет: живой туннель он не трогает, новый конфиг вступит в силу при
// следующем подключении. В обоих случаях конфиг, совпавший по SHA-256 с
// последним сохранённым, не пересохраняется и не переподключает — раньше
// ручное обновление рвало туннель даже ради того же самого конфига.
func (a *App) refreshConfig(manual bool) {
	if !a.refreshing.CompareAndSwap(false, true) {
		return
	}
	defer a.refreshing.Store(false)
	settings := a.settingsSnapshot()
	if settings.AccessToken == "" {
		if manual {
			go ShowError("Обновление конфига",
				"Сессия не найдена.\nСначала выполните «Импорт токена...».")
		}
		return
	}
	data, err := winbridge.FetchConfig(settings.AccessToken)
	if err != nil {
		if !manual {
			log.Printf("[Tray] auto-refresh: fetch failed: %v", err)
			a.nextAutoRefresh.Store(time.Now().Add(autoRefreshRetry).Unix())
			return
		}
		if errors.Is(err, winbridge.ErrUnauthorized) {
			go ShowError("Обновление конфига", winbridge.ErrUnauthorized.Error())
		} else {
			var upg *winbridge.UpgradeRequiredError
			if errors.As(err, &upg) {
				go ShowError("Требуется обновление", upg.Error())
			} else {
				go ShowError("Ошибка обновления", err.Error())
			}
		}
		return
	}

	hash := winbridge.ConfigHash(data)
	if hash == settings.LastConfigHash {
		a.mu.Lock()
		a.settings.LastRefresh = time.Now()
		winbridge.SaveSettings(a.settings)
		a.mu.Unlock()
		if manual {
			go Notify("Обновление", "Конфиг актуален", niifInfo)
		} else {
			log.Printf("[Tray] auto-refresh: config unchanged")
		}
		return
	}

	if _, err := winbridge.SaveConfig(data); err != nil {
		if manual {
			go ShowError("Ошибка сохранения", err.Error())
		} else {
			log.Printf("[Tray] auto-refresh: save failed: %v", err)
		}
		return
	}
	a.mu.Lock()
	a.settings.LastConfigHash = hash
	a.settings.LastRefresh = time.Now()
	winbridge.SaveSettings(a.settings)
	a.mu.Unlock()
	a.loadConfigInfo()

	if !manual {
		log.Printf("[Tray] auto-refresh: new config saved, applies on next connect")
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

// maybeAutoRefresh запускает фоновое обновление конфига, когда с последнего
// прошло autoRefreshInterval. Только через поднятый туннель — есть рукопожатие:
// control plane снаружи туннеля может быть заблокирован, а без рукопожатия
// запрос ушёл бы в ещё не работающий туннель и отвалился бы по таймауту.
// Вызывается из цикла опроса статуса, то есть только пока туннель поднят.
func (a *App) maybeAutoRefresh(st winbridge.TunnelStats) {
	settings := a.settingsSnapshot()
	if settings.AutoRefreshDisabled || settings.AccessToken == "" || st.LastHandshake.IsZero() {
		return
	}
	now := time.Now()
	if now.Sub(settings.LastRefresh) < autoRefreshInterval || now.Unix() < a.nextAutoRefresh.Load() {
		return
	}
	// Ставится до запуска: пока запрос идёт, следующий тик не должен завести
	// второй, а после успеха отсчёт ведётся уже от LastRefresh.
	a.nextAutoRefresh.Store(now.Add(autoRefreshRetry).Unix())
	go a.refreshConfig(false)
}

// ── Status monitoring ──────────────────────────────────────────────────────────

// Each watcher belongs to one manager and exits on cancellation. The UI reads
// only the cached snapshot, so a slow UAPI/network operation cannot freeze it.
func (a *App) watchStatus(ctx context.Context, mgr *winbridge.Manager) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	networkTick := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if ctx.Err() != nil {
			return
		}
		st := mgr.Stats()
		a.mu.Lock()
		if a.manager != mgr || ctx.Err() != nil {
			a.mu.Unlock()
			return
		}
		a.stats = st
		connAt, settings := a.connectedAt, a.settings
		systray.SetTooltip(buildTooltip(time.Since(connAt), st, settings))
		a.mu.Unlock()
		a.maybeAutoRefresh(st)
		networkTick++
		if networkTick%5 != 0 {
			continue
		}
		if url := mgr.PendingCaptchaURL(); url != "" && !a.solvingCaptcha.Swap(true) {
			go func() {
				defer a.solvingCaptcha.Store(false)
				a.handleCaptcha(ctx, mgr, url)
			}()
		}
		mgr.CheckNetworkChange()
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
	a.mu.Lock()
	a.stats = winbridge.TunnelStats{}
	a.mu.Unlock()
	a.cancelBlink()
	systray.SetIcon(assets.IconConnecting())
	systray.SetTooltip("Подключение…")
	a.mConnect.Disable()
	a.mDisconnect.Enable()

	done := make(chan struct{})
	a.blinkMu.Lock()
	a.stopBlink = func() { close(done) }
	a.blinkMu.Unlock()
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
					systray.SetIcon(assets.IconConnectingDim())
				} else {
					systray.SetIcon(assets.IconConnecting())
				}
				on = !on
			}
		}
	}()
}

func (a *App) setConnected(mgr *winbridge.Manager) bool {
	a.mu.Lock()
	if a.manager != mgr || a.exiting.Load() {
		a.mu.Unlock()
		return false
	}
	a.connectedAt = time.Now()
	a.stats = winbridge.TunnelStats{Connected: true}
	settings := a.settings
	defer a.mu.Unlock()
	a.cancelBlink()
	systray.SetIcon(assets.IconConnected())
	if settings.Mode == winbridge.ModeSOCKS {
		addr := fmt.Sprintf("127.0.0.1:%d", settings.SocksPort)
		systray.SetTooltip("SOCKS прокси " + addr)
		go Notify("SOCKS прокси", "Запущен на "+addr, niifInfo)
	} else {
		systray.SetTooltip("Защита включена")
		go Notify("VPN", "Подключено", niifInfo)
	}
	a.mConnect.Disable()
	a.mDisconnect.Enable()
	return true
}

func (a *App) setDisconnected() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.manager != nil {
		return
	}
	a.cancelBlink()
	systray.SetIcon(assets.IconDisconnected())
	systray.SetTooltip("Отключено")
	a.mConnect.Enable()
	a.mDisconnect.Disable()
	go Notify("VPN", "Отключено", niifInfo)
}

func (a *App) cancelBlink() {
	a.blinkMu.Lock()
	defer a.blinkMu.Unlock()
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
