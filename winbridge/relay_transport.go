package winbridge

import (
	"context"
	"log"
	"time"
)

// RelayTransport — как туннель ходит до TURN-релеев (pkg/proxy/relay_transport.go).
// UDP — везде, где он работает: без head-of-line блокировки под WireGuard. TCP —
// для сетей, где по UDP подключение не поднимается: известная — мобильная сеть
// Ростелекома за белым списком, где ответы на Allocate по UDP приходят, а данные
// через релей — нет. На Windows это ноутбук на раздаче с телефона с такой
// SIM-картой. Оператора Windows не видит, поэтому «авто» по нему, как в
// Android, нет — выбор за пользователем (как в iOS).
type RelayTransport string

const (
	// RelayTransportAsConfigured — как в конфиге (#@wgt:UseUDP; у бота — UDP).
	RelayTransportAsConfigured RelayTransport = ""
	RelayTransportUDP          RelayTransport = "udp"
	RelayTransportTCP          RelayTransport = "tcp"
)

// valid — известное значение; неизвестное читается как «как в конфиге».
func (t RelayTransport) valid() bool {
	return t == RelayTransportAsConfigured || t == RelayTransportUDP || t == RelayTransportTCP
}

// ApplyRelayTransport накладывает выбор пользователя на копию конфига, как
// ApplyExpert: сохранённый конфиг и его хеш не трогаются, а watchdog
// переподключается с той же копией.
func ApplyRelayTransport(cfg *TunnelConfig, t RelayTransport) *TunnelConfig {
	if cfg == nil || (t != RelayTransportUDP && t != RelayTransportTCP) {
		return cfg
	}
	useUDP := t == RelayTransportUDP
	if cfg.TURN.UseUDP == useUDP {
		return cfg
	}
	c := *cfg
	c.TURN.UseUDP = useUDP
	log.Printf("[Config] Transport to the relays: %s (chosen in the tray)", relayTransportName(!useUDP))
	return &c
}

// RelaysOverTCP — ходит ли туннель по cfg до релеев по TCP.
func RelaysOverTCP(cfg *TunnelConfig) bool { return cfg != nil && !cfg.TURN.UseUDP }

func relayTransportName(overTCP bool) string {
	if overTCP {
		return "TCP"
	}
	return "UDP"
}

// SetRelayTransport меняет транспорт до релеев поднятого туннеля: TURN-транспорт
// перезапускается под живым WireGuard с теми же кредами
// (proxy.Tunnel.SetRelayOverTCP), WireGuard, wintun и маршруты не трогаются.
// Ждёт, пока новый транспорт поднимет первый поток, как перезапуск сторожа;
// капчу по дороге решает опрос tray. changed — был ли перезапуск: без перемены
// транспорта его нет.
func (m *Manager) SetRelayTransport(ctx context.Context, overTCP bool) (changed bool, err error) {
	m.mu.Lock()
	t := m.tunnel
	connected := m.connected
	m.mu.Unlock()
	if !connected || t == nil {
		return false, errNotConnected
	}
	changed, err = t.SetRelayOverTCP(overTCP)
	if err != nil || !changed {
		return changed, err
	}
	m.noteRelaySwitched()
	log.Printf("[Manager] Transport to the relays is now %s — the TURN transport restarted under the live WireGuard", relayTransportName(overTCP))
	err = m.awaitTransport(ctx, t)
	m.noteRelaySwitched()
	return true, err
}

// noteRelaySwitched отмечает для сторожа переключение транспорта
// (Manager.relaySwitchedAt).
func (m *Manager) noteRelaySwitched() {
	now := time.Now()
	m.relaySwitchedAt.Store(&now)
}
