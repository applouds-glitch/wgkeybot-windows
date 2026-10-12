package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// ReadyStatus — результат WaitReady.
type ReadyStatus int

const (
	ReadyStatusError           ReadyStatus = -1
	ReadyStatusOK              ReadyStatus = 0
	ReadyStatusCaptchaRequired ReadyStatus = 1
	ReadyStatusAuthRequired    ReadyStatus = 2
	// ReadyStatusCallUnavailable — VK-звонок завершён/удалён или ссылка
	// недействительна. Terminal: ни captcha, ни ретраи не помогут — нужна
	// новая ссылка (новый конфиг).
	ReadyStatusCallUnavailable ReadyStatus = 3
	// ReadyStatusTurnFatal — все воркеры сессии сдались: капча не решается
	// столько раз подряд, что дальше пробовать бессмысленно, либо звонок умер
	// уже после старта. Terminal: watchdog не должен переподключаться.
	ReadyStatusTurnFatal ReadyStatus = 4
)

// Config — параметры TURN-прокси + WireGuard для Windows-клиента.
// Соответствует @wgt:-секции в .conf файле.
type Config struct {
	// VK / TURN
	VKLink         string `json:"vk_link"`
	UseUDP         bool   `json:"use_udp"`
	StreamsTotal   int    `json:"streams_total"`
	StreamsPerCred int    `json:"streams_per_cred"`
	WatchdogSecs   int    `json:"watchdog_secs"`

	// Peer endpoint — всегда 127.0.0.1:<port> (WireGuard → TURN-прокси → TURN-сервер)
	PeerAddr   string `json:"peer_addr"`
	ListenAddr string `json:"listen_addr"`

	// Опциональный override TURN-сервера
	TurnIP   string `json:"turn_ip"`
	TurnPort int    `json:"turn_port"`
	PeerType string `json:"peer_type"`

	// Обфускация WRAP
	WrapKey string `json:"wrap_key,omitempty"`

	// DNS и fallback
	SystemDNS []string `json:"system_dns,omitempty"`
}

// WireGuardConfig — параметры для wgTurnOn / IpcSet.
type WireGuardConfig struct {
	// Имя wintun-интерфейса (например "WgKeyBot")
	InterfaceName string
	// MTU туннеля
	MTU int
	// WireGuard UAPI конфиг (приватный ключ, пиры и т.д.)
	UAPIConfig string
	// IP-адрес интерфейса с маской, напр. "10.10.11.1/32"
	Address string
	// DNS-серверы для туннеля, напр. ["8.8.8.8", "8.8.4.4"]
	DNS []string
}

// Tunnel — единичный VPN-тоннель (TURN-прокси + WireGuard device).
//
// Жизненный цикл:
//
//	t, _ := NewTunnel(cfg)
//	t.StartBootstrap()
//	switch t.WaitReady(120 * time.Second) {
//	case ReadyStatusOK:
//	    t.AttachWireGuard(wgCfg)
//	case ReadyStatusCaptchaRequired:
//	    url := t.PendingCaptchaURL()
//	    // показать браузер / WebView2
//	}
//	defer t.Stop()
type Tunnel struct {
	cfg Config

	mu sync.RWMutex
	// boot — текущее поколение TURN-прокси; новое создаёт StartBootstrap и
	// RestartTransport. listenAddr — фактический адрес слушателя, как только
	// прокси его занял (порт :0 разрешается ОС).
	boot       *bootState
	listenAddr string

	// lifeMu упорядочивает старт, перезапуск и остановку прокси; stopped —
	// после Stop поколений больше не бывает.
	lifeMu  sync.Mutex
	stopped bool

	device      *device.Device
	tunDev      tun.Device
	wgKeepalive *wireGuardKeepaliveSender
	stopOnce    sync.Once
}

// NewTunnel создаёт Tunnel из Config. Не делает сетевых вызовов.
func NewTunnel(cfg Config) (*Tunnel, error) {
	if cfg.VKLink == "" {
		return nil, errors.New("vk_link is empty")
	}
	if cfg.StreamsTotal == 0 {
		cfg.StreamsTotal = 8
	}
	if cfg.StreamsPerCred == 0 {
		cfg.StreamsPerCred = 4
	}
	if cfg.WatchdogSecs == 0 {
		cfg.WatchdogSecs = 30
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	if cfg.PeerType == "" {
		cfg.PeerType = "proxy_v2"
	}
	return &Tunnel{cfg: cfg}, nil
}

// bootState — одно поколение TURN-прокси: его контекст, канал готовности
// (закрывается, когда StartProxy вернулся) и код возврата (пишется до
// закрытия канала).
type bootState struct {
	ctx    context.Context
	cancel context.CancelFunc
	ready  chan struct{}
	result int32
}

// NewTunnelJSON создаёт Tunnel из JSON-строки.
func NewTunnelJSON(configJSON string) (*Tunnel, error) {
	var cfg Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("parse Config: %w", err)
	}
	return NewTunnel(cfg)
}

// StartBootstrap запускает TURN-прокси в фоне. Не блокирует.
// Важно: вызывается до того, как WireGuard-тоннель поднят, чтобы
// TURN-сокеты использовали физический интерфейс.
func (t *Tunnel) StartBootstrap() {
	if len(t.cfg.SystemDNS) > 0 {
		InitSystemDns(t.cfg.SystemDNS)
	}
	t.lifeMu.Lock()
	defer t.lifeMu.Unlock()
	if t.stopped {
		return
	}
	t.startGeneration(false)
}

// startGeneration запускает новое поколение прокси (под lifeMu). keepDNS —
// см. StartProxyParams.KeepDNSCache. Слушатель занимает адрес, который уже
// опубликовало предыдущее поколение, — тот же порт, что и у Endpoint WireGuard.
func (t *Tunnel) startGeneration(keepDNS bool) *bootState {
	ctx, cancel := context.WithCancel(context.Background())
	b := &bootState{ctx: ctx, cancel: cancel, ready: make(chan struct{})}
	t.mu.Lock()
	t.boot = b
	listenAddr := t.listenAddr
	t.mu.Unlock()
	if listenAddr == "" {
		listenAddr = t.cfg.ListenAddr
	}

	go func() {
		b.result = StartProxy(StartProxyParams{
			PeerAddr:        t.cfg.PeerAddr,
			VKLink:          t.cfg.VKLink,
			StreamNum:       t.cfg.StreamsTotal,
			UseUDP:          t.cfg.UseUDP,
			ListenAddr:      listenAddr,
			TurnIP:          t.cfg.TurnIP,
			TurnPort:        t.cfg.TurnPort,
			PeerType:        t.cfg.PeerType,
			StreamsPerCred:  t.cfg.StreamsPerCred,
			WatchdogTimeout: t.cfg.WatchdogSecs,
			WrapKey:         t.cfg.WrapKey,
			SystemDNS:       t.cfg.SystemDNS,
			Parent:          ctx,
			OnListen:        t.publishListenAddr,
			KeepDNSCache:    keepDNS,
		})
		close(b.ready)
	}()
	return b
}

func (t *Tunnel) publishListenAddr(addr string) {
	t.mu.Lock()
	t.listenAddr = addr
	t.mu.Unlock()
}

// RestartTransport перезапускает TURN-прокси под живым WireGuard: старое
// поколение останавливается (его аллокации освобождаются), при
// dropCredentials кеш кредов сбрасывается — следующий старт берёт у VK новую
// идентичность, — и стартует новое поколение на том же порту. Device, wintun
// и netstack не трогаются: WireGuard так и шлёт на 127.0.0.1:<порт>. Дальше —
// WaitStartedContext.
//
// Не Stop + StartBootstrap: Stop закрывает device и снимает WireGuard-keepalive.
func (t *Tunnel) RestartTransport(dropCredentials bool) error {
	t.lifeMu.Lock()
	defer t.lifeMu.Unlock()
	if t.stopped {
		return errors.New("tunnel is stopped")
	}
	t.mu.RLock()
	prev := t.boot
	t.mu.RUnlock()
	if prev != nil {
		prev.cancel()
	}
	StopProxy()
	if dropCredentials {
		// After the old transport is gone: its departing workers must not fetch.
		invalidateAllCaches()
		turnLog("[PROXY] Credential caches dropped for the rebuild — the next start fetches a new VK identity")
	}
	t.startGeneration(true)
	return nil
}

// WaitReady блокирует до готовности первого TURN-стрима, до запроса captcha или таймаута.
func (t *Tunnel) WaitReady(timeout time.Duration) ReadyStatus {
	return t.WaitReadyContext(context.Background(), timeout)
}

// WaitReadyContext — WaitReady, который прерывается отменой ctx и тогда
// возвращает ReadyStatusError: вызывающий отличает её по ctx.Err(). Без этого
// «Отключить» во время подключения ждало весь таймаут — Connect держит
// Manager.mu, и teardown стоял на нём до 90 с.
func (t *Tunnel) WaitReadyContext(ctx context.Context, timeout time.Duration) ReadyStatus {
	t.mu.RLock()
	b := t.boot
	t.mu.RUnlock()
	if b == nil {
		return ReadyStatusError
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-b.ready:
		// StartProxy returned — check outcome below.
	case <-CaptchaNotifyChan():
		// RequestCaptcha was called while prefetch was still running.
		return ReadyStatusCaptchaRequired
	case <-timer.C:
		return ReadyStatusError
	case <-ctx.Done():
		return ReadyStatusError
	}
	if reason := turnFatalReason(); reason != "" {
		return ReadyStatusTurnFatal
	}
	if PendingCaptchaURL() != "" {
		return ReadyStatusCaptchaRequired
	}
	return b.status()
}

// WaitStartedContext ждёт, пока текущее поколение прокси (после
// RestartTransport) поднимет первый поток или сдастся. Капчу по дороге не
// возвращает: под живым туннелем её решает опрос хоста (tray.watchStatus →
// PendingCaptchaURL), а ожидание просто продолжается. started=false — ни того,
// ни другого до timeout или отмены ctx.
func (t *Tunnel) WaitStartedContext(ctx context.Context, timeout time.Duration) (status ReadyStatus, started bool) {
	t.mu.RLock()
	b := t.boot
	t.mu.RUnlock()
	if b == nil {
		return ReadyStatusError, true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-b.ready:
	case <-timer.C:
		return ReadyStatusError, false
	case <-ctx.Done():
		return ReadyStatusError, false
	}
	if reason := turnFatalReason(); reason != "" {
		return ReadyStatusTurnFatal, true
	}
	return b.status(), true
}

// status переводит код возврата StartProxy в ReadyStatus. Читается только
// после закрытия ready: результат записан раньше.
func (b *bootState) status() ReadyStatus {
	switch b.result {
	case 0:
		return ReadyStatusOK
	case -2:
		return ReadyStatusAuthRequired
	case -4:
		return ReadyStatusCallUnavailable
	default:
		return ReadyStatusError
	}
}

// AttachWireGuard создаёт wintun-интерфейс и запускает wireguard-go.
// Вызывается после WaitReady вернул ReadyStatusOK.
// После успешного возврата winbridge должен добавить IP/маршруты через netsh.
func (t *Tunnel) AttachWireGuard(wgCfg WireGuardConfig) error {
	name := wgCfg.InterfaceName
	if name == "" {
		name = "WgKeyBot"
	}
	mtu := wgCfg.MTU
	if mtu == 0 {
		mtu = 1280
	}
	SetWrapMTU(mtu)

	tunDev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return fmt.Errorf("create wintun %q: %w", name, err)
	}

	if err := t.startDevice(tunDev, wgCfg.UAPIConfig); err != nil {
		return err
	}

	turnLog("[WG] Interface %q up, MTU=%d", name, mtu)
	return nil
}

// AttachWireGuardNetstack создаёт WireGuard поверх userspace-стека gVisor
// (без wintun-интерфейса и системной маршрутизации) и возвращает *netstack.Net,
// чей DialContext проксирует TCP/UDP через туннель. Используется в SOCKS-режиме.
func (t *Tunnel) AttachWireGuardNetstack(wgCfg WireGuardConfig) (*netstack.Net, error) {
	mtu := wgCfg.MTU
	if mtu == 0 {
		mtu = 1280
	}
	SetWrapMTU(mtu)

	localAddrs, err := parseNetipAddrs(wgCfg.Address)
	if err != nil {
		return nil, fmt.Errorf("parse interface address %q: %w", wgCfg.Address, err)
	}
	if len(localAddrs) == 0 {
		return nil, errors.New("no interface address for netstack tunnel")
	}
	dnsAddrs, _ := parseNetipAddrs(strings.Join(wgCfg.DNS, ","))

	tunDev, netDev, err := netstack.CreateNetTUN(localAddrs, dnsAddrs, mtu)
	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}

	if err := t.startDevice(tunDev, wgCfg.UAPIConfig); err != nil {
		return nil, err
	}

	turnLog("[WG] Netstack tunnel up, MTU=%d, addrs=%v", mtu, localAddrs)
	return netDev, nil
}

// startDevice строит wireguard-go device поверх заданного tun.Device,
// применяет UAPI-конфиг, поднимает интерфейс и сохраняет ссылки в Tunnel.
// При ошибке корректно закрывает device/tun.
func (t *Tunnel) startDevice(tunDev tun.Device, uapiConfig string) error {
	// Through the thinner (wg_log_filter.go): keepalives are counted, not
	// written one by one, and the per-core worker lines are dropped.
	thinned := newWGLogThinner(
		func(msg string) { turnLog("[WG] %s", msg) },
		func(msg string) { turnLog("[WG-ERR] %s", msg) },
	)
	logger := &device.Logger{Verbosef: thinned.Verbosef, Errorf: thinned.Errorf}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(uapiConfig); err != nil {
		dev.Close()
		return fmt.Errorf("IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("device.Up: %w", err)
	}

	// WireGuard's own keepalive rides the TURN keepalive grid (see
	// wireguard_keepalive.go) so both layers share one wake, and so the first
	// grid tick kicks the initial handshake instead of waiting for traffic.
	sender := installWireGuardKeepaliveSender(newWireGuardKeepaliveSendFunc(dev, uapiConfig))

	t.mu.Lock()
	t.device = dev
	t.tunDev = tunDev
	t.wgKeepalive = sender
	t.mu.Unlock()
	return nil
}

// parseNetipAddrs разбирает CSV-список адресов (с маской или без) в []netip.Addr.
// Пустые элементы пропускаются; маска (/32, /24, …) отбрасывается.
func parseNetipAddrs(csv string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, '/'); i >= 0 {
			part = part[:i]
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	return out, nil
}

// Stop корректно останавливает тоннель. Прокси закрывается до device,
// чтобы избежать дедлока между device.Close() и proxy-горутинами.
func (t *Tunnel) Stop() {
	t.stopOnce.Do(func() {
		t.lifeMu.Lock()
		t.stopped = true
		t.mu.Lock()
		b := t.boot
		dev := t.device
		sender := t.wgKeepalive
		t.device = nil
		t.wgKeepalive = nil
		t.mu.Unlock()
		t.lifeMu.Unlock()

		if b != nil {
			b.cancel()
		}
		StopProxy()
		// Blocks until an already-started send returns, so the device is never
		// closed underneath one.
		clearWireGuardKeepaliveSender(sender)
		if dev != nil {
			dev.Close()
		}
	})
}

// ListenAddr возвращает адрес, на котором слушает TURN-прокси (нужен winbridge
// для настройки Endpoint в WireGuard-конфиге): фактический, как только прокси
// занял порт (в том числе выбранный ОС для «:0»), до того — из конфига.
func (t *Tunnel) ListenAddr() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.listenAddr != "" {
		return t.listenAddr
	}
	return t.cfg.ListenAddr
}

// PendingCaptchaURL — URL slider-captcha если PoW не сработал. Иначе "".
func (t *Tunnel) PendingCaptchaURL() string { return PendingCaptchaURL() }

// TurnFatalReason возвращает причину, по которой все воркеры сессии сдались,
// или "" пока у туннеля есть транспорт. Опрашивается winbridge в двух точках:
// в цикле WaitReady на подключении и в тике watchdog'а уже после него.
func (t *Tunnel) TurnFatalReason() string { return turnFatalReason() }

// SolveCaptcha — передаёт ответ captcha ожидающей Go-горутине.
func (t *Tunnel) SolveCaptcha(answer string) { PublishCaptchaAnswer(answer) }

// OnNetworkChange сбрасывает DNS-кеш и пересоздаёт HTTP-соединения.
// Вызывается когда Windows обнаруживает смену физической сети.
func (t *Tunnel) OnNetworkChange() { NotifyNetworkChange() }

// IpcGet возвращает текущую статистику WireGuard в UAPI-формате.
func (t *Tunnel) IpcGet() (string, error) {
	t.mu.RLock()
	dev := t.device
	t.mu.RUnlock()
	if dev == nil {
		return "", errors.New("WireGuard device not attached")
	}
	return dev.IpcGet()
}

// ActiveTURNAddrs возвращает все уникальные адреса TURN-серверов из кеша учётных данных.
// Вызывается после WaitReady для получения динамически резолвленных IP-адресов,
// которым нужны bypass-маршруты до установки VPN-маршрутов.
func (t *Tunnel) ActiveTURNAddrs() []string { return ActiveTURNAddrs() }

// AuthBypassIPs возвращает IP control-plane хостов (VK/OK auth): и тех, что
// зарезолвились при bootstrap, и фиксированного списка authHosts, который
// резолвится здесь же (см. ResolveAuthHosts — при кешированных кредах bootstrap
// в VK не ходит и сам ничего не резолвит). winbridge ставит для них
// bypass-маршруты мимо VPN — иначе ре-фетч credentials после поднятия туннеля
// уходит в сам туннель и виснет.
func (t *Tunnel) AuthBypassIPs(ctx context.Context) []string {
	ResolveAuthHosts(ctx)
	return ResolvedHostIPs()
}

// ActiveTURNServer возвращает настроенный IP TURN-сервера (если задан явно).
func (t *Tunnel) ActiveTURNServer() string {
	if t.cfg.TurnIP != "" {
		if ip := net.ParseIP(t.cfg.TurnIP); ip != nil {
			return t.cfg.TurnIP
		}
	}
	return ""
}
