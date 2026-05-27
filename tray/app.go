//go:build windows

package tray

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/systray"
	"github.com/wgkeybot/windows/assets"
	"github.com/wgkeybot/windows/winbridge"
)

// Version отображается в пункте «О программе».
const Version = "1.0.0"

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
	mAutoConn   *systray.MenuItem
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
	a.mAutoConn = systray.AddMenuItem("Подключаться при запуске", "Автоматически поднимать VPN при старте")
	if a.settings.AutoConnect {
		a.mAutoConn.Check()
	}
	systray.AddSeparator()
	a.mAbout = systray.AddMenuItem("О программе", "")
	if a.debug {
		systray.AddSeparator()
		a.mLog = systray.AddMenuItem("Открыть лог", "Открыть wgkeybot.log в блокноте")
	}
	systray.AddSeparator()
	a.mQuit = systray.AddMenuItem("Выход", "Закрыть WgKeyBot")

	go a.eventLoop()

	if a.settings.AutoConnect && a.settings.LastConfig != "" {
		go a.doAutoConnect(a.settings.LastConfig)
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
		case <-a.mAutoConn.ClickedCh:
			a.doAutoConnectToggle()
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

func (a *App) doAutoConnect(configPath string) {
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

	cfg, err := winbridge.ParseEncryptedConfig(configPath)
	if err != nil {
		return
	}

	mgr := winbridge.NewManager(cfg)
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

	a.settings.LastConfig = configPath
	winbridge.SaveSettings(a.settings)

	a.setConnected(cfg.Name)
	go a.watchStatus()
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

	a.settings.LastConfig = confPath
	winbridge.SaveSettings(a.settings)

	a.setConnected(cfg.Name)
	go a.watchStatus()
}

func (a *App) doDisconnect() {
	a.mu.Lock()
	mgr := a.manager
	cancel := a.cancel
	a.manager = nil
	a.cancel = nil
	a.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if mgr != nil {
		go func() {
			mgr.Disconnect()
			a.setDisconnected()
		}()
	}
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

	if _, err := winbridge.SaveConfig(token, data); err != nil {
		go ShowError("Ошибка сохранения", err.Error())
		return
	}

	go Notify("Импорт", "Настройки подключения получены", niifInfo)
}

// ── Status monitoring ──────────────────────────────────────────────────────────

func (a *App) watchStatus() {
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
				a.handleCaptcha(mgr, url)
			}()
		}

		mgr.CheckNetworkChange()

		status := mgr.Status()
		tip := status + " | " + formatDuration(time.Since(connAt))
		systray.SetTooltip(tip)
	}
}

func (a *App) handleCaptcha(mgr *winbridge.Manager, url string) {
	log.Printf("[Tray] Captcha required during operation")
	token, err := winbridge.SolveCaptchaProxy(context.Background(), url, 5*time.Minute)
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
	systray.SetTooltip("Подключение...")
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

func (a *App) setConnected(name string) {
	a.cancelBlink()
	a.mu.Lock()
	a.connectedAt = time.Now()
	a.mu.Unlock()
	systray.SetIcon(assets.IconConnected())
	systray.SetTooltip("Подключено: " + name)
	a.mConnect.Disable()
	a.mDisconnect.Enable()
	go Notify("VPN", "Подключено", niifInfo)
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

func (a *App) resolveConfig() (string, error) {
	configs, err := winbridge.ListConfigs()
	if err != nil {
		return "", err
	}
	switch len(configs) {
	case 0:
		return "", fmt.Errorf(
			"Конфиги не найдены в %s.\n\nИспользуйте «Import token...» чтобы добавить конфиг.",
			winbridge.DefaultConfigDir(),
		)
	case 1:
		return configs[0], nil
	default:
		return SelectConfig(configs)
	}
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
