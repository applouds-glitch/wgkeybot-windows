package winbridge

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"syscall"
)

// RouteManager управляет маршрутами Windows на время жизни тоннеля.
// Принцип: перед поднятием WireGuard-интерфейса запоминаем физический
// шлюз по умолчанию и добавляем явные host-маршруты для TURN-серверов
// через этот шлюз. После остановки тоннеля — удаляем их.
type RouteManager struct {
	physicalGW string // IP шлюза физической сети
	turnRoutes []string
}

// NewRouteManager создаёт RouteManager, определяя текущий дефолтный шлюз.
func NewRouteManager() (*RouteManager, error) {
	gw, iface, err := DefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("cannot find default gateway: %w", err)
	}
	log.Printf("[ROUTE] Physical gateway: %s via %s", gw, iface)
	return &RouteManager{physicalGW: gw}, nil
}

// AddTURNRoutes добавляет явные host-маршруты для TURN-серверов через
// физический шлюз. Вызывается ПЕРЕД поднятием WireGuard-интерфейса.
func (r *RouteManager) AddTURNRoutes(turnServerIPs []string) {
	for _, ip := range turnServerIPs {
		if net.ParseIP(ip) == nil {
			log.Printf("[ROUTE] Skipping non-IP: %s", ip)
			continue
		}
		if err := r.addRoute(ip+"/32", r.physicalGW); err != nil {
			log.Printf("[ROUTE] Warning: cannot add route for %s: %v", ip, err)
			continue
		}
		r.turnRoutes = append(r.turnRoutes, ip)
		log.Printf("[ROUTE] Added TURN route: %s/32 via %s", ip, r.physicalGW)
	}
}

// SetupInterface назначает IP-адрес и DNS wintun-интерфейсу через netsh.
func SetupInterface(ifaceName string, addresses []string, dnsServers []string) error {
	if len(addresses) == 0 {
		return fmt.Errorf("no addresses to configure")
	}

	// Назначаем первый адрес
	addr := addresses[0]
	ip, ipNet, err := net.ParseCIDR(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}
	mask := ipNetMask(ipNet.Mask)

	// Назначаем IP интерфейсу
	out, err := netsh("interface", "ip", "set", "address",
		fmt.Sprintf("name=%q", ifaceName), "static", ip.String(), mask, "none")
	if err != nil {
		return fmt.Errorf("set address: %w (output: %s)", err, out)
	}

	// Дополнительные адреса
	for _, a := range addresses[1:] {
		ip2, _, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		netsh("interface", "ip", "add", "address",
			fmt.Sprintf("name=%q", ifaceName), ip2.String())
	}

	// DNS
	if len(dnsServers) > 0 {
		netsh("interface", "ip", "set", "dnsservers",
			fmt.Sprintf("name=%q", ifaceName), "static", dnsServers[0], "primary")
		for _, dns := range dnsServers[1:] {
			netsh("interface", "ip", "add", "dnsservers",
				fmt.Sprintf("name=%q", ifaceName), dns)
		}
	}

	log.Printf("[ROUTE] Interface %q configured: addr=%s dns=%v", ifaceName, addresses[0], dnsServers)
	return nil
}

// AddVPNRoutes добавляет маршруты AllowedIPs через wintun-интерфейс.
func AddVPNRoutes(ifaceName string, allowedIPs []string) error {
	for _, cidr := range allowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[ROUTE] Skipping invalid AllowedIP %q: %v", cidr, err)
			continue
		}
		// netsh interface ip add route <prefix> <interface_name> — interface name is positional
		out, err := netsh("interface", "ip", "add", "route",
			ipNet.String(), ifaceName)
		if err != nil {
			log.Printf("[ROUTE] Warning: add route %s via %s: %v (%s)", cidr, ifaceName, err, out)
		} else {
			log.Printf("[ROUTE] Added VPN route: %s via %s", cidr, ifaceName)
		}
	}
	return nil
}

// RemoveVPNRoutes удаляет маршруты AllowedIPs.
func RemoveVPNRoutes(ifaceName string, allowedIPs []string) {
	for _, cidr := range allowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		netsh("interface", "ip", "delete", "route",
			ipNet.String(), ifaceName)
	}
}

// Cleanup удаляет добавленные TURN host-маршруты.
func (r *RouteManager) Cleanup() {
	for _, ip := range r.turnRoutes {
		if err := r.deleteRoute(ip + "/32"); err != nil {
			log.Printf("[ROUTE] Warning: cannot remove route for %s: %v", ip, err)
		} else {
			log.Printf("[ROUTE] Removed TURN route: %s/32", ip)
		}
	}
	r.turnRoutes = nil
}

// addRoute добавляет маршрут через netsh / route add.
func (r *RouteManager) addRoute(cidr, gateway string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	// route ADD <network> MASK <mask> <gateway>
	out, err := runCmd("route", "ADD",
		ipNet.IP.String(), "MASK", ipNetMask(ipNet.Mask), gateway)
	if err != nil {
		return fmt.Errorf("%w (output: %s)", err, out)
	}
	return nil
}

func (r *RouteManager) deleteRoute(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	_, err = runCmd("route", "DELETE", ipNet.IP.String())
	return err
}

// DefaultGateway возвращает IP дефолтного шлюза и IP интерфейса.
// Использует `route print 0.0.0.0` и парсит вывод.
func DefaultGateway() (string, string, error) { return defaultGateway() }

func defaultGateway() (string, string, error) {
	out, err := runCmd("route", "print", "0.0.0.0")
	if err != nil {
		return "", "", err
	}
	// Ищем строку вида: "0.0.0.0  0.0.0.0  <gateway>  <interface>  <metric>"
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gw := fields[2]
			if net.ParseIP(gw) != nil && gw != "0.0.0.0" {
				return gw, fields[3], nil
			}
		}
	}
	return "", "", fmt.Errorf("default gateway not found in route table")
}

// netsh запускает netsh с аргументами и возвращает вывод.
func netsh(args ...string) (string, error) {
	return runCmd("netsh", args...)
}

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ipNetMask конвертирует net.IPMask в строку вида "255.255.255.0".
func ipNetMask(mask net.IPMask) string {
	if len(mask) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	}
	return "255.255.255.0"
}
