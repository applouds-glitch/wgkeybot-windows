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

	mu        sync.RWMutex
	readyCh   chan struct{}
	readyOnce sync.Once

	bootCtx    context.Context
	bootCancel context.CancelFunc
	bootResult int32

	device   *device.Device
	tunDev   tun.Device
	stopOnce sync.Once
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
	return &Tunnel{
		cfg:     cfg,
		readyCh: make(chan struct{}),
	}, nil
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
	t.mu.Lock()
	t.bootCtx, t.bootCancel = context.WithCancel(context.Background())
	t.mu.Unlock()

	if len(t.cfg.SystemDNS) > 0 {
		InitSystemDns(t.cfg.SystemDNS)
	}

	go func() {
		rc := StartProxy(StartProxyParams{
			PeerAddr:        t.cfg.PeerAddr,
			VKLink:          t.cfg.VKLink,
			StreamNum:       t.cfg.StreamsTotal,
			UseUDP:          t.cfg.UseUDP,
			ListenAddr:      t.cfg.ListenAddr,
			TurnIP:          t.cfg.TurnIP,
			TurnPort:        t.cfg.TurnPort,
			PeerType:        t.cfg.PeerType,
			StreamsPerCred:  t.cfg.StreamsPerCred,
			WatchdogTimeout: t.cfg.WatchdogSecs,
			WrapKey:         t.cfg.WrapKey,
			SystemDNS:       t.cfg.SystemDNS,
		})
		t.mu.Lock()
		t.bootResult = rc
		t.mu.Unlock()
		t.readyOnce.Do(func() { close(t.readyCh) })
	}()
}

// WaitReady блокирует до готовности первого TURN-стрима, до запроса captcha или таймаута.
func (t *Tunnel) WaitReady(timeout time.Duration) ReadyStatus {
	select {
	case <-t.readyCh:
		// StartProxy returned — check outcome below.
	case <-CaptchaNotifyChan():
		// RequestCaptcha was called while prefetch was still running.
		return ReadyStatusCaptchaRequired
	case <-time.After(timeout):
		return ReadyStatusError
	}
	if PendingCaptchaURL() != "" {
		return ReadyStatusCaptchaRequired
	}
	t.mu.RLock()
	rc := t.bootResult
	t.mu.RUnlock()
	if rc == -2 {
		return ReadyStatusAuthRequired
	}
	if rc != 0 {
		return ReadyStatusError
	}
	return ReadyStatusOK
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
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) { turnLog("[WG] "+format, args...) },
		Errorf:   func(format string, args ...any) { turnLog("[WG-ERR] "+format, args...) },
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(uapiConfig); err != nil {
		dev.Close()
		return fmt.Errorf("IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("device.Up: %w", err)
	}

	t.mu.Lock()
	t.device = dev
	t.tunDev = tunDev
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
		t.mu.Lock()
		cancel := t.bootCancel
		dev := t.device
		t.device = nil
		t.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		StopProxy()
		if dev != nil {
			dev.Close()
		}
	})
}

// ListenAddr возвращает адрес, на котором слушает TURN-прокси
// (нужен winbridge для настройки Endpoint в WireGuard-конфиге).
func (t *Tunnel) ListenAddr() string { return t.cfg.ListenAddr }

// PendingCaptchaURL — URL slider-captcha если PoW не сработал. Иначе "".
func (t *Tunnel) PendingCaptchaURL() string { return PendingCaptchaURL() }

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

// AuthBypassIPs возвращает IP control-plane хостов (VK/OK auth), зарезолвленных
// при bootstrap. winbridge ставит для них bypass-маршруты мимо VPN — иначе
// ре-фетч credentials после поднятия туннеля уходит в сам туннель и виснет.
func (t *Tunnel) AuthBypassIPs() []string { return ResolvedHostIPs() }

// ActiveTURNServer возвращает настроенный IP TURN-сервера (если задан явно).
func (t *Tunnel) ActiveTURNServer() string {
	if t.cfg.TurnIP != "" {
		if ip := net.ParseIP(t.cfg.TurnIP); ip != nil {
			return t.cfg.TurnIP
		}
	}
	return ""
}
