package winbridge

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/wgkeybot/windows/pkg/proxy"
)

// LogPath — путь к файлу логов (устанавливается через InitLogging).
var LogPath string

// InitLogging перенаправляет логи proxy-пакета и стандартного log в файл.
// Вызывать один раз при старте приложения.
func InitLogging() {
	dir := DefaultConfigDir()
	os.MkdirAll(dir, 0700)
	path := dir + `\wgkeybot.log`
	LogPath = path

	proxy.SetLogFilePath(path)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil {
		log.SetOutput(f)
	}
}

// Manager управляет жизненным циклом одного WireGuard/TURN-тоннеля на Windows.
type Manager struct {
	mu        sync.Mutex
	cfg       *TunnelConfig
	tunnel    *proxy.Tunnel
	routeMgr  *RouteManager
	socks     *SocksServer
	mode      Mode
	socksPort int
	physGW    string // physical gateway at connect time, for detecting network changes
	connected bool
}

// NewManager создаёт Manager для заданного конфига в режиме VPN.
func NewManager(cfg *TunnelConfig) *Manager {
	return &Manager{cfg: cfg, mode: ModeVPN, socksPort: DefaultSocksPort}
}

// SetMode задаёт режим работы (vpn / socks) и порт SOCKS5-сервера.
// Вызывать до Connect; на подключённом туннеле игнорируется.
func (m *Manager) SetMode(mode Mode, socksPort int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connected {
		return
	}
	if mode != ModeVPN && mode != ModeSOCKS {
		mode = ModeVPN
	}
	if socksPort < 1 || socksPort > 65535 {
		socksPort = DefaultSocksPort
	}
	m.mode = mode
	m.socksPort = socksPort
}

// Connect запускает тоннель: TURN-прокси → WireGuard → маршруты.
// ctx используется для отмены ожидания (captcha, timeout).
func (m *Manager) Connect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.connected {
		return fmt.Errorf("tunnel already connected")
	}

	// Clean up partial state on failure or cancellation — the caller may
	// cancel ctx and call Disconnect concurrently; this defer ensures
	// routeMgr and tunnel are freed even if Disconnect never reaches them.
	var connected bool
	defer func() {
		if connected {
			return
		}
		if m.socks != nil {
			m.socks.Close()
			m.socks = nil
		}
		if m.tunnel != nil {
			m.tunnel.Stop()
			m.tunnel = nil
		}
		if m.routeMgr != nil {
			m.routeMgr.Cleanup()
			m.routeMgr = nil
		}
	}()

	cfg := m.cfg

	// 1. В режиме VPN создаём RouteManager ДО поднятия WireGuard (чтобы TURN
	//    трафик шёл через физический интерфейс при добавлении маршрутов).
	//    В режиме SOCKS системная маршрутизация не трогается — RouteManager не нужен.
	var routeMgr *RouteManager
	if m.mode == ModeVPN {
		rm, err := NewRouteManager()
		if err != nil {
			return fmt.Errorf("route manager: %w", err)
		}
		routeMgr = rm
		m.routeMgr = rm
		if gw, _, err := DefaultGateway(); err == nil {
			m.physGW = gw
		}
	}

	// 2. Определяем DNS — сначала пробуем системный, иначе встроенный.
	sysDNS := GetSystemDNS()
	log.Printf("[Manager] System DNS: %v", sysDNS)

	// 3. Строим proxy.Config из TunnelConfig.
	proxyCfg := cfg.TURN
	proxyCfg.SystemDNS = sysDNS
	if proxyCfg.ListenAddr == "" {
		proxyCfg.ListenAddr = "127.0.0.1:0"
	}

	if proxyCfg.VKLink == "" {
		return fmt.Errorf(
			"конфиг %q не содержит настроек TURN.\n\n"+
				"Убедитесь, что конфиг получен через бота @wg_key_bot\n"+
				"и содержит строку #@wgt:VKLink = ...",
			cfg.Name,
		)
	}

	// 4. Создаём и запускаем TURN-прокси.
	t, err := proxy.NewTunnel(proxyCfg)
	if err != nil {
		return fmt.Errorf("new tunnel: %w", err)
	}
	m.tunnel = t

	t.StartBootstrap()

	// 5. Добавляем host-маршруты для TURN-серверов через физический шлюз.
	//    Делаем до WireGuard, чтобы при старте WireGuard они уже работали.
	//    Только в VPN-режиме — в SOCKS нет 0.0.0.0/0, петли не возникает.
	if routeMgr != nil && cfg.TURN.TurnIP != "" {
		routeMgr.AddTURNRoutes([]string{cfg.TURN.TurnIP})
	}

	// 6. Ждём готовности прокси.
	// pkg/proxy решает капчу поэтапно: HTTP auto → Manual (browser) → ManualVisible (dialog).
	// Каждый переход вызывает RequestCaptcha снова, поэтому WaitReady может вернуть
	// ReadyStatusCaptchaRequired несколько раз подряд — loop обрабатывает все раунды.
	log.Printf("[Manager] Waiting for TURN proxy ready...")
	for {
		status := t.WaitReady(90 * time.Second)
		if status == proxy.ReadyStatusOK {
			break
		}
		switch status {
		case proxy.ReadyStatusCaptchaRequired:
			captchaURL := t.PendingCaptchaURL()
			log.Printf("[Manager] Captcha required: %s", captchaURL)
			token, err := SolveCaptchaProxy(ctx, captchaURL)
			if err != nil {
				return fmt.Errorf("captcha: %w", err)
			}
			t.SolveCaptcha(token)
			// Continue loop: pkg/proxy may request another captcha (next solve mode).
		case proxy.ReadyStatusAuthRequired:
			return fmt.Errorf("VK авторизация устарела (CALL_REQUIRES_AUTH) — обновите конфиг через «Import token»")
		default:
			return fmt.Errorf("TURN proxy failed (status %d)", status)
		}
	}

	// 7. Получаем реальный ListenAddr прокси (может быть 127.0.0.1:PORT).
	listenAddr := t.ListenAddr()
	log.Printf("[Manager] TURN proxy listening at %s", listenAddr)

	// 8. Строим UAPI-конфиг для WireGuard.
	uapiCfg := cfg.BuildWGUAPIConfig(listenAddr)

	wgCfg := proxy.WireGuardConfig{
		InterfaceName: sanitizeIfaceName(cfg.Name),
		MTU:           cfg.MTU,
		UAPIConfig:    uapiCfg,
		Address:       strings.Join(cfg.Address, ","),
		DNS:           cfg.DNS,
	}

	// 9. Поднимаем WireGuard. Развилка по режиму:
	//    SOCKS — userspace netstack + локальный SOCKS5; VPN — wintun + маршруты.
	if m.mode == ModeSOCKS {
		log.Printf("[Manager] Attaching WireGuard (netstack/SOCKS mode)...")
		netDev, err := t.AttachWireGuardNetstack(wgCfg)
		if err != nil {
			return fmt.Errorf("attach WireGuard (netstack): %w", err)
		}

		socksAddr := fmt.Sprintf("127.0.0.1:%d", m.socksPort)
		srv, err := NewSocksServer(socksAddr, netDev.DialContext)
		if err != nil {
			return fmt.Errorf("start SOCKS server: %w", err)
		}
		m.socks = srv
		go srv.Serve()
		log.Printf("[Manager] SOCKS5 proxy listening at %s", srv.Addr())
	} else {
		// 9. Создаём wintun-интерфейс и поднимаем WireGuard.
		log.Printf("[Manager] Attaching WireGuard interface %q...", wgCfg.InterfaceName)
		if err := t.AttachWireGuard(wgCfg); err != nil {
			return fmt.Errorf("attach WireGuard: %w", err)
		}

		// 10. Назначаем IP и DNS через netsh.
		if err := SetupInterface(wgCfg.InterfaceName, cfg.Address, cfg.DNS); err != nil {
			return fmt.Errorf("setup interface: %w", err)
		}

		// 11. Добавляем bypass-маршруты для динамических TURN-серверов.
		//     Делаем ДО VPN-маршрутов — иначе подсеть 0.0.0.0/0 или широкий CIDR
		//     накроет TURN IP и новые стримы уйдут в петлю через VPN-интерфейс.
		if turnAddrs := m.tunnel.ActiveTURNAddrs(); len(turnAddrs) > 0 {
			var turnIPs []string
			for _, addr := range turnAddrs {
				host, _, err := net.SplitHostPort(addr)
				if err == nil && net.ParseIP(host) != nil {
					turnIPs = append(turnIPs, host)
				}
			}
			if len(turnIPs) > 0 {
				log.Printf("[Manager] Adding TURN bypass routes for: %v", turnIPs)
				routeMgr.AddTURNRoutes(turnIPs)
			}
		}

		// 12. Добавляем VPN маршруты (AllowedIPs).
		if err := AddVPNRoutes(wgCfg.InterfaceName, cfg.AllowedIPs); err != nil {
			log.Printf("[Manager] Warning: add VPN routes: %v", err)
		}
	}

	m.connected = true
	connected = true // disarm cleanup defer
	log.Printf("[Manager] Tunnel %q connected", cfg.Name)
	return nil
}

// Disconnect корректно останавливает тоннель и очищает маршруты.
func (m *Manager) Disconnect() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.connected {
		return
	}

	cfg := m.cfg

	// Останавливаем SOCKS5-сервер (если был в SOCKS-режиме).
	if m.socks != nil {
		m.socks.Close()
		m.socks = nil
	}

	// Удаляем VPN маршруты (только в VPN-режиме они добавлялись).
	if m.mode == ModeVPN && cfg != nil {
		RemoveVPNRoutes(sanitizeIfaceName(cfg.Name), cfg.AllowedIPs)
	}

	// Останавливаем тоннель (TURN + WireGuard)
	if m.tunnel != nil {
		m.tunnel.Stop()
		m.tunnel = nil
	}

	// Удаляем TURN host-маршруты
	if m.routeMgr != nil {
		m.routeMgr.Cleanup()
		m.routeMgr = nil
	}

	m.connected = false
	log.Printf("[Manager] Tunnel %q disconnected", cfg.Name)
}

// TunnelStats — снимок состояния туннеля для отображения пользователю.
type TunnelStats struct {
	Connected     bool
	RxBytes       uint64
	TxBytes       uint64
	LastHandshake time.Time // нулевое, если рукопожатия ещё не было
}

// Stats возвращает текущую статистику туннеля.
func (m *Manager) Stats() TunnelStats {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.connected || m.tunnel == nil {
		return TunnelStats{}
	}

	uapi, err := m.tunnel.IpcGet()
	if err != nil {
		return TunnelStats{Connected: true}
	}
	return parseWGStats(uapi)
}

// IsConnected возвращает true если тоннель поднят.
func (m *Manager) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected
}

// PendingCaptchaURL returns the pending captcha URL if a WorkerGroup is
// blocked waiting for captcha input, or empty string otherwise.
func (m *Manager) PendingCaptchaURL() string {
	m.mu.Lock()
	t := m.tunnel
	m.mu.Unlock()
	if t == nil {
		return ""
	}
	return t.PendingCaptchaURL()
}

// SolveCaptcha delivers a captcha answer to a blocked WorkerGroup.
// Safe to call when there is no pending captcha (no-op).
func (m *Manager) SolveCaptcha(answer string) {
	m.mu.Lock()
	t := m.tunnel
	m.mu.Unlock()
	if t != nil {
		t.SolveCaptcha(answer)
	}
}

// CheckNetworkChange polls the current default gateway and, if it differs
// from the one recorded during Connect, notifies the tunnel so it can reset
// DNS caches and reconnect TURN streams.
func (m *Manager) CheckNetworkChange() bool {
	m.mu.Lock()
	t := m.tunnel
	prevGW := m.physGW
	m.mu.Unlock()

	if t == nil || prevGW == "" {
		return false
	}

	gw, _, err := DefaultGateway()
	if err != nil || gw == "" || gw == prevGW {
		return false
	}

	log.Printf("[Manager] Gateway changed: %s -> %s", prevGW, gw)
	m.mu.Lock()
	m.physGW = gw
	m.mu.Unlock()
	t.OnNetworkChange()
	return true
}

// OnNetworkChange вызывается при смене физической сети.
// Сбрасывает DNS-кеш и переподключает TURN-стримы.
func (m *Manager) OnNetworkChange() {
	m.mu.Lock()
	t := m.tunnel
	m.mu.Unlock()

	if t != nil {
		log.Printf("[Manager] Network change detected — notifying TURN proxy")
		t.OnNetworkChange()
	}
}

// sanitizeIfaceName возвращает допустимое имя Windows-интерфейса (макс 64 символа).
func sanitizeIfaceName(name string) string {
	if name == "" {
		return "WgKeyBot"
	}
	// Wintun: имя не должно превышать MAX_ADAPTER_NAME_LENGTH (128 символов),
	// но netsh ограничивает до 64. Обрезаем до безопасного предела.
	if len(name) > 32 {
		name = name[:32]
	}
	return name
}

// StartWatchdog запускает фоновую горутину, которая следит за состоянием WG
// handshake. Если handshake устарел (>3 мин) при растущем TX — соединение
// считается мёртвым, и вызывается onDead. Горутина завершается при отмене ctx
// или если туннель уже отключён.
func (m *Manager) StartWatchdog(ctx context.Context, onDead func()) {
	const (
		pollInterval = 30 * time.Second
		staleAfter   = 3 * time.Minute
		neverAfter   = 150 * time.Second
		deadChecksMax = 2
	)
	go func() {
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()
		upSince := time.Now()
		var prevTx uint64
		prevTxSet := false
		deadChecks := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			stats := m.Stats()
			if !stats.Connected {
				return
			}
			now := time.Now()
			isDead := false
			if stats.LastHandshake.IsZero() {
				isDead = now.Sub(upSince) > neverAfter
			} else if now.Sub(stats.LastHandshake) > staleAfter {
				isDead = prevTxSet && stats.TxBytes > prevTx
			}
			prevTx = stats.TxBytes
			prevTxSet = true
			if !isDead {
				deadChecks = 0
				continue
			}
			deadChecks++
			if deadChecks >= deadChecksMax {
				log.Printf("[Manager] Watchdog: WG handshake stale — triggering reconnect")
				onDead()
				return
			}
		}
	}()
}

// parseWGStats извлекает счётчики трафика и время рукопожатия из UAPI-ответа.
func parseWGStats(uapi string) TunnelStats {
	st := TunnelStats{Connected: true}
	var lastHandshake int64
	for _, line := range strings.Split(uapi, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "rx_bytes":
			fmt.Sscanf(v, "%d", &st.RxBytes)
		case "tx_bytes":
			fmt.Sscanf(v, "%d", &st.TxBytes)
		case "last_handshake_time_sec":
			fmt.Sscanf(v, "%d", &lastHandshake)
		}
	}
	if lastHandshake > 0 {
		st.LastHandshake = time.Unix(lastHandshake, 0)
	}
	return st
}
