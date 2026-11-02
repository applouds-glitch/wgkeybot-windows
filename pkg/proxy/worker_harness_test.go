/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */
package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// The workers' test bench, from Android's relay_head_start_test.go and
// network_switch_test.go: real TURN servers on loopback, real workers dialing
// them, a peer that echoes the relay proof.

// sourceCounter counts the client sockets that have reached a relay socket
// (one per dial).
type sourceCounter struct {
	net.PacketConn
	mu   sync.Mutex
	seen map[string]bool
}

func (c *sourceCounter) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.mu.Lock()
		c.seen[addr.String()] = true
		c.mu.Unlock()
	}
	return n, addr, err
}

func (c *sourceCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

// delayedAllocateReplies holds back the server's Allocate answers (the
// challenge and the authenticated reply alike) by delay, without blocking the
// server's read loop or changing pion's retransmissions.
type delayedAllocateReplies struct {
	net.PacketConn
	delay time.Duration
}

func (c *delayedAllocateReplies) WriteTo(b []byte, addr net.Addr) (int, error) {
	m := &stun.Message{Raw: append([]byte(nil), b...)}
	if m.Decode() == nil && m.Type.Method == stun.MethodAllocate && c.delay > 0 {
		payload := append([]byte(nil), b...)
		time.AfterFunc(c.delay, func() { c.PacketConn.WriteTo(payload, addr) })
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, addr)
}

// testRelay is a TURN server for the worker tests; seen counts the client
// sockets that have reached it (one per dial).
type testRelay struct {
	addr   string
	server *turn.Server
	seen   *sourceCounter
}

func startTestRelay(t *testing.T, pc net.PacketConn, replyDelay time.Duration) *testRelay {
	t.Helper()
	seen := &sourceCounter{PacketConn: pc, seen: map[string]bool{}}
	var conn net.PacketConn = seen
	if replyDelay > 0 {
		conn = &delayedAllocateReplies{PacketConn: seen, delay: replyDelay}
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "worker-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "worker-test", "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            conn,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return &testRelay{addr: pc.LocalAddr().String(), server: server, seen: seen}
}

// twoRelaySockets returns two listening sockets in the order stream 0 would
// dial their addresses (assignRelays sorts the list), so a test can decide
// what stands first.
func twoRelaySockets(t *testing.T) (first, second net.PacketConn) {
	t.Helper()
	a, b := listenFakeRelay(t), listenFakeRelay(t)
	if assignRelays([]string{a.LocalAddr().String(), b.LocalAddr().String()}, 0, time.Now())[0] == a.LocalAddr().String() {
		return a, b
	}
	return b, a
}

type raceHarness struct {
	streams []*stream
	cancel  context.CancelFunc
	done    *sync.WaitGroup
}

// runWorkersAgainst runs n workers over addrs, with a peer that echoes the
// relay proof, until the test ends.
func runWorkersAgainst(t *testing.T, group int, n int, addrs []string) *raceHarness {
	t.Helper()
	answer := make(chan struct{})
	close(answer)
	return runWorkersAgainstPeer(t, group, n, addrs, fakeRelay(t, answer))
}

// runWorkersAgainstPeer is runWorkersAgainst with a peer of the test's own.
func runWorkersAgainstPeer(t *testing.T, group int, n int, addrs []string, peer *net.UDPAddr) *raceHarness {
	t.Helper()
	return runWorkersOfType(t, group, n, addrs, peer, "wireguard")
}

// runWorkersOfType is runWorkersAgainstPeer over the transport of the test's
// choice; the peer has to speak it.
func runWorkersOfType(t *testing.T, group int, n int, addrs []string, peer *net.UDPAddr, peerType string) *raceHarness {
	t.Helper()
	resetAllocationBook(t)
	resetNetworkAvailabilityForTest()
	t.Cleanup(resetNetworkAvailabilityForTest)
	resetServerHealth()
	t.Cleanup(resetServerHealth)

	prev := globalGetCreds
	globalGetCreds = func(context.Context, string, int) (string, string, []string, error) {
		return t.Name(), "pass", addrs, nil
	}
	t.Cleanup(func() { globalGetCreds = prev })

	ctx, cancel := context.WithCancel(context.Background())
	h := &raceHarness{cancel: cancel, done: &sync.WaitGroup{}}
	for i := 0; i < n; i++ {
		s, _ := newNoDTLSTestStream(t)
		s.id = i
		h.streams = append(h.streams, s)
		h.done.Add(1)
		go func() {
			defer h.done.Done()
			runWorker(ctx, WorkerGroupConfig{GroupID: group, Link: "test", UseUDP: benchUseUDP(), PeerType: peerType, PeerAddr: peer}, s, 0)
		}()
	}
	t.Cleanup(func() {
		cancel()
		h.done.Wait()
	})
	return h
}

func (h *raceHarness) ready() int {
	n := 0
	for _, s := range h.streams {
		if s.ready.Load() {
			n++
		}
	}
	return n
}

// The bench itself: a worker over a live relay comes up.
func TestTheWorkerBenchBringsAStreamUp(t *testing.T) {
	relay := startTestRelay(t, listenFakeRelay(t), 0)
	h := runWorkersAgainst(t, 160, 1, []string{relay.addr})
	waitFor(t, "the stream up", 8*time.Second, func() bool { return h.ready() == 1 })
}
