//go:build windows

package proxy

import "golang.zx2c4.com/wireguard/tun"

// InterfaceLUID возвращает LUID нижележащего wintun-адаптера, либо 0, если
// тоннель поднят не через wintun (например, netstack/SOCKS-режим).
// LUID используется winbridge для настройки IP/DNS/маршрутов через IP Helper API.
func (t *Tunnel) InterfaceLUID() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if nt, ok := t.tunDev.(*tun.NativeTun); ok {
		return nt.LUID()
	}
	return 0
}
