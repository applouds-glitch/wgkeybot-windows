package proxy

import (
	"context"
	"net"
	"syscall"
	"time"
)

// protectControl — no-op on Windows.
//
// On Android this called VpnService.protect() to route TURN sockets through
// the physical interface, bypassing the VPN tunnel. On Windows we achieve the
// same result differently:
//   - TURN proxy starts before the WireGuard tunnel is brought up, so initial
//     TURN connections use the physical interface naturally.
//   - After the VPN is established, winbridge.AddTURNRoutes() adds explicit
//     host routes for all active TURN server IPs via the physical gateway,
//     so reconnections also bypass the VPN.
//
// This function is kept to satisfy calls from turn-client.go, dns.go, and
// stream_run_with_creds.go that pass it as a syscall.RawConn control hook.
func protectControl(_ string, _ string, _ syscall.RawConn) error {
	return nil
}

// protectAndDial creates a TCP or UDP connection. On Windows the dialer is
// unmodified — see protectControl comment above.
func protectAndDial(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, addr)
}
