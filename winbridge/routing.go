package winbridge

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// RouteManager управляет маршрутами Windows на время жизни тоннеля.
// Принцип: перед поднятием WireGuard-интерфейса запоминаем физический
// шлюз по умолчанию и добавляем явные host-маршруты для TURN-серверов
// через этот шлюз. После остановки тоннеля — удаляем их.
//
// Маршруты ставятся не только пачкой до AllowedIPs, но и по требованию:
// прокси перед каждым дозвоном (TURN, VK, DNS, капча) зовёт EnsureBypassRoute
// (proxy.BypassRouter), так что адрес, узнанный уже под поднятым VPN — релей
// новых кредов, следующая A-запись VK, хост виджета капчи — тоже уходит в
// физический интерфейс, а не в туннель. Смена шлюза (Refresh) переносит все
// поставленные маршруты на новый.
//
// Вся работа идёт через IP Helper API (winipcfg), без запуска netsh/route —
// спавн внешних процессов из админ-процесса повышает heuristic-score антивируса.
type RouteManager struct {
	mu       sync.Mutex
	physLUID winipcfg.LUID // LUID физического интерфейса с дефолтным маршрутом
	physGW   netip.Addr    // IP шлюза физической сети
	owned    map[netip.Addr]struct{}
	order    []netip.Addr // owned в порядке добавления (для журнала и отката)
}

// NewRouteManager создаёт RouteManager, определяя текущий дефолтный шлюз.
func NewRouteManager() (*RouteManager, error) {
	gw, luid, ifIndex, err := defaultRoute()
	if err != nil {
		return nil, fmt.Errorf("cannot find default gateway: %w", err)
	}
	log.Printf("[ROUTE] Physical gateway: %s via ifindex %d", gw, ifIndex)
	return &RouteManager{physLUID: luid, physGW: gw, owned: map[netip.Addr]struct{}{}}, nil
}

// EnsureBypassRoute ставит host-маршрут до ip через физический шлюз, если его
// ещё нет. Реализует proxy.BypassRouter: прокси зовёт это перед каждым
// дозвоном, ошибка означает «не дозваниваться» — иначе пакет уйдёт в туннель.
//
// Приватные, link-local и прочие неглобальные адреса не трогаются: DNS-сервер
// в локальной сети и так on-link, а /32 через шлюз увёл бы трафик к нему
// кружным путём. Адрес другого семейства, чем шлюз, тоже оставляется как есть —
// маршрутизировать его не через что.
func (r *RouteManager) EnsureBypassRoute(ipStr string) error {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return fmt.Errorf("bypass route: %q is not an IP", ipStr)
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.owned[ip]; ok {
		return nil
	}
	if ip.Is4() != r.physGW.Is4() {
		log.Printf("[ROUTE] Skipping %s: address family differs from gateway %s", ip, r.physGW)
		return nil
	}
	if err := r.addLocked(ip); err != nil {
		return err
	}
	r.owned[ip] = struct{}{}
	r.order = append(r.order, ip)
	return nil
}

// addLocked ставит /32 (или /128) до ip через текущий шлюз. Уже существующий
// маршрут — например, оставшийся от аварийно завершённого процесса — считается
// нашим: он ведёт туда же, а Cleanup его снимет.
func (r *RouteManager) addLocked(ip netip.Addr) error {
	dst := netip.PrefixFrom(ip, ip.BitLen())
	err := r.physLUID.AddRoute(dst, r.physGW, 0)
	switch {
	case err == nil:
		log.Printf("[ROUTE] Added bypass route: %s via %s", dst, r.physGW)
	case errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS):
		log.Printf("[ROUTE] Bypass route %s via %s already present — adopted", dst, r.physGW)
	default:
		return fmt.Errorf("add route %s via %s: %w", dst, r.physGW, err)
	}
	return nil
}

// AddTURNRoutes добавляет host-маршруты для списка адресов через физический
// шлюз (пачка до поднятия WireGuard-интерфейса). Отказ по одному адресу не
// останавливает остальные — он попадёт в журнал, а прокси спросит маршрут ещё
// раз перед дозвоном.
func (r *RouteManager) AddTURNRoutes(turnServerIPs []string) {
	for _, ipStr := range turnServerIPs {
		if err := r.EnsureBypassRoute(ipStr); err != nil {
			log.Printf("[ROUTE] Warning: %v", err)
		}
	}
}

// Refresh перечитывает дефолтный маршрут и, если шлюз или интерфейс сменились,
// переносит все поставленные host-маршруты на новые: маршрут через исчезнувший
// шлюз неактивен, и трафик к релеям падал бы в 0.0.0.0/0 туннеля. Возвращает
// true, если перенос был.
func (r *RouteManager) Refresh() bool {
	gw, luid, ifIndex, err := defaultRoute()
	if err != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if gw == r.physGW && luid == r.physLUID {
		return false
	}
	log.Printf("[ROUTE] Physical gateway changed: %s -> %s (ifindex %d), re-homing %d bypass route(s)", r.physGW, gw, ifIndex, len(r.order))
	for _, ip := range r.order {
		dst := netip.PrefixFrom(ip, ip.BitLen())
		if err := r.physLUID.DeleteRoute(dst, r.physGW); err != nil {
			log.Printf("[ROUTE] Warning: cannot remove route for %s via old gateway: %v", ip, err)
		}
	}
	r.physGW, r.physLUID = gw, luid
	for _, ip := range r.order {
		if ip.Is4() != r.physGW.Is4() {
			continue
		}
		if err := r.addLocked(ip); err != nil {
			log.Printf("[ROUTE] Warning: %v", err)
		}
	}
	return true
}

// Cleanup удаляет добавленные host-маршруты.
func (r *RouteManager) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ip := range r.order {
		dst := netip.PrefixFrom(ip, ip.BitLen())
		if err := r.physLUID.DeleteRoute(dst, r.physGW); err != nil {
			log.Printf("[ROUTE] Warning: cannot remove route for %s: %v", ip, err)
		} else {
			log.Printf("[ROUTE] Removed bypass route: %s", dst)
		}
	}
	r.order = nil
	r.owned = map[netip.Addr]struct{}{}
}

// SetupInterface назначает IP-адреса и DNS wintun-интерфейсу через IP Helper API.
func SetupInterface(luid winipcfg.LUID, addresses []string, dnsServers []string) error {
	if len(addresses) == 0 {
		return fmt.Errorf("no addresses to configure")
	}

	prefixes := make([]netip.Prefix, 0, len(addresses))
	for _, a := range addresses {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return fmt.Errorf("invalid address %q: %w", a, err)
		}
		prefixes = append(prefixes, p)
	}
	if err := luid.SetIPAddresses(prefixes); err != nil {
		return fmt.Errorf("set ip addresses: %w", err)
	}

	// DNS назначается отдельно по семействам (IPv4 / IPv6).
	if len(dnsServers) > 0 {
		var v4, v6 []netip.Addr
		for _, d := range dnsServers {
			a, err := netip.ParseAddr(d)
			if err != nil {
				log.Printf("[ROUTE] Skipping invalid DNS %q: %v", d, err)
				continue
			}
			if a.Is4() {
				v4 = append(v4, a)
			} else {
				v6 = append(v6, a)
			}
		}
		if len(v4) > 0 {
			if err := luid.SetDNS(windows.AF_INET, v4, nil); err != nil {
				log.Printf("[ROUTE] Warning: set IPv4 DNS: %v", err)
			}
		}
		if len(v6) > 0 {
			if err := luid.SetDNS(windows.AF_INET6, v6, nil); err != nil {
				log.Printf("[ROUTE] Warning: set IPv6 DNS: %v", err)
			}
		}
	}

	log.Printf("[ROUTE] Interface configured: addr=%v dns=%v", addresses, dnsServers)
	return nil
}

// AddVPNRoutes добавляет маршруты AllowedIPs через wintun-интерфейс (on-link).
func AddVPNRoutes(luid winipcfg.LUID, allowedIPs []string) error {
	for _, cidr := range allowedIPs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			log.Printf("[ROUTE] Skipping invalid AllowedIP %q: %v", cidr, err)
			continue
		}
		dst := p.Masked() // destination маршрута — адрес сети
		if err := luid.AddRoute(dst, onLinkNextHop(dst), 0); err != nil {
			log.Printf("[ROUTE] Warning: add route %s: %v", cidr, err)
		} else {
			log.Printf("[ROUTE] Added VPN route: %s", dst)
		}
	}
	return nil
}

// RemoveVPNRoutes удаляет маршруты AllowedIPs. При удалении самого wintun-адаптера
// маршруты исчезают автоматически — этот вызов лишь подстраховка/явная очистка.
func RemoveVPNRoutes(luid winipcfg.LUID, allowedIPs []string) {
	for _, cidr := range allowedIPs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		dst := p.Masked()
		luid.DeleteRoute(dst, onLinkNextHop(dst))
	}
}

// DefaultGateway возвращает IP дефолтного шлюза и индекс интерфейса (строкой).
// Сохранена сигнатура (gateway, iface, err) для совместимости с вызывающим кодом.
func DefaultGateway() (string, string, error) {
	gw, _, ifIndex, err := defaultRoute()
	if err != nil {
		return "", "", err
	}
	return gw.String(), strconv.FormatUint(uint64(ifIndex), 10), nil
}

// defaultRoute находит лучший (минимальная метрика) дефолтный маршрут IPv4 с
// настоящим next-hop'ом, игнорируя on-link маршруты (в т.ч. 0.0.0.0/0 нашего
// собственного wintun-интерфейса, у которого next-hop неопределён).
func defaultRoute() (gw netip.Addr, luid winipcfg.LUID, ifIndex uint32, err error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return netip.Addr{}, 0, 0, fmt.Errorf("get ip forward table: %w", err)
	}
	best := -1
	var bestMetric uint32
	for i := range rows {
		p := rows[i].DestinationPrefix.Prefix()
		if !p.IsValid() || p.Bits() != 0 {
			continue // не дефолтный маршрут
		}
		nh := rows[i].NextHop.Addr()
		if !nh.IsValid() || nh.IsUnspecified() {
			continue // on-link (например, наш wintun) — пропускаем
		}
		if best == -1 || rows[i].Metric < bestMetric {
			best = i
			bestMetric = rows[i].Metric
		}
	}
	if best == -1 {
		return netip.Addr{}, 0, 0, fmt.Errorf("default gateway not found in route table")
	}
	return rows[best].NextHop.Addr(), rows[best].InterfaceLUID, rows[best].InterfaceIndex, nil
}

// onLinkNextHop возвращает неопределённый адрес нужного семейства — признак
// on-link маршрута (трафик уходит прямо в интерфейс, без шлюза).
func onLinkNextHop(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}
