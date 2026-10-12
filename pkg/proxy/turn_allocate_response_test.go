/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// Use real framed TCP: an unrelated response must not overwrite the actual
// initial Allocate refusal. Both replies deliberately omit challenge attrs.
func TestInitialAllocateErrorMatchesTransactionOverTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	defer resetServerHealth()
	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		pc := turn.NewSTUNConn(conn)
		buf := make([]byte, 2048)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		request := &stun.Message{Raw: buf[:n]}
		if err = request.Decode(); err != nil {
			done <- err
			return
		}
		wrongID := request.TransactionID
		wrongID[0] ^= 0xff
		for _, spec := range []struct {
			id   [stun.TransactionIDSize]byte
			code stun.ErrorCode
		}{
			{wrongID, stun.CodeAllocQuotaReached}, {request.TransactionID, stun.CodeAllocMismatch},
		} {
			response := stun.MustBuild(stun.NewTransactionIDSetter(spec.id), stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse), stun.ErrorCodeAttribute{Code: spec.code}, stun.Fingerprint)
			if _, err = pc.WriteTo(response.Raw, conn.RemoteAddr()); err != nil {
				done <- err
				return
			}
		}
		// Keep the server socket open until the client has handled its response.
		pc.ReadFrom(buf)
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, _, _, _, err = dialAndAllocate(ctx, &stream{}, t.Name(), "pass", l.Addr().String(), WorkerGroupConfig{})
	if code, ok := turnErrorCode(err); !ok || code != stun.CodeAllocMismatch {
		t.Fatalf("unrelated transaction replaced actual 437: %v", err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAllocateResponseDoesNotReplaceTransportErrors(t *testing.T) {
	c := &allocateResponseConn{refusal: turnErr(stun.CodeAllocMismatch).(*stun.TurnError)}
	for _, original := range []error{nil, context.Canceled, net.ErrClosed, errors.New("all retransmissions failed"), turnErr(stun.CodeForbidden)} {
		if got := c.allocationError(original); got != original {
			t.Fatalf("replaced %v with %v", original, got)
		}
	}
}

// Live relays can send unrelated UDP datagrams before the Allocate response.
// The server has already reserved an allocation at this point: losing the
// response leaves it occupied even though the client reports a timeout.
type noisyAllocateReplies struct {
	net.PacketConn
	injected atomic.Int32
}

func (c *noisyAllocateReplies) WriteTo(b []byte, addr net.Addr) (int, error) {
	m := &stun.Message{Raw: append([]byte(nil), b...)}
	if m.Decode() == nil && m.Type == stun.NewType(stun.MethodAllocate, stun.ClassSuccessResponse) {
		noise := make([]byte, 1200)
		// Same non-STUN/non-ChannelData header shape observed in the field.
		copy(noise, []byte{0xc3, 0, 0, 0, 1, 8})
		if _, err := c.PacketConn.WriteTo(noise, addr); err != nil {
			return 0, err
		}
		c.injected.Add(1)
	}
	return c.PacketConn.WriteTo(b, addr)
}

func TestDialAndAllocateIgnoresUnrelatedDatagrams(t *testing.T) {
	pc := listenFakeRelay(t)
	noisy := &noisyAllocateReplies{PacketConn: pc}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "noisy-allocate-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "noisy-allocate-test", "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: noisy,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer resetServerHealth()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, raw, relay, _, perm, err := dialAndAllocate(ctx, &stream{}, "noisy-user", "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true})
	if err != nil {
		t.Fatalf("Allocate lost after unrelated datagram: %v (server allocations: %d, injected: %d)", err, server.AllocationCount(), noisy.injected.Load())
	}
	defer raw.Close()
	defer client.Close()
	defer relay.Close()
	if noisy.injected.Load() == 0 {
		t.Fatal("server did not inject the unrelated datagram")
	}
	if err := perm.readerStoppedBy(); err != nil {
		t.Fatalf("unrelated datagram stopped pion's reader: %v", err)
	}
	if got := server.AllocationCount(); got != 1 {
		t.Fatalf("active allocations=%d, want 1", got)
	}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for server.AllocationCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("Refresh(lifetime=0) did not release the allocation after noise")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
