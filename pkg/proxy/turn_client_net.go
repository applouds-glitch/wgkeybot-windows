/* SPDX-License-Identifier: Apache-2.0 */

package proxy

import (
	"net"

	"github.com/pion/transport/v4/stdnet"
	"github.com/pion/turn/v5"
)

// newTURNClient uses the caller's already connected socket. Pion's default
// stdnet.NewNet enumerates every interface and its addresses on each new
// client — on Android through netlink, which can fail outright with "route
// ip+net: netlinkrib: permission denied" before any Allocate is sent. Our UDP
// relay allocation (over UDP or TCP) only needs address resolution from Net,
// not interface discovery. The zero value provides that without querying
// interfaces or opening another socket.
//
// Windows: the enumeration does not fail, but it is not free either — a
// GetAdaptersAddresses walk over every adapter (wintun, Hyper-V, VPN clients,
// …) on every dial, for every stream, and every reconnect, for a list nothing
// here reads. Address resolution is unchanged: both Nets hand it to
// net.ResolveUDPAddr. Pion's AllocateTCP would dial connections of its own
// through Net, around ensureBypass; we only ever call Allocate.
func newTURNClient(config *turn.ClientConfig) (*turn.Client, error) {
	config.Net = &stdnet.Net{}
	return turn.NewClient(config)
}

// The production TURN socket is connected before Pion receives it.
type connectedUDPConn struct{ *net.UDPConn }

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
