/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"testing"
	"time"
)

func tunnelWithBoot() (*Tunnel, *bootState) {
	b := &bootState{ready: make(chan struct{})}
	b.ctx, b.cancel = context.WithCancel(context.Background())
	return &Tunnel{boot: b}, b
}

// "Отключить" во время подключения отменяет ctx; ожидание готовности должно
// закончиться сразу, а не через весь таймаут.
func TestWaitReadyContextEndsOnCancel(t *testing.T) {
	tun, _ := tunnelWithBoot()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan ReadyStatus, 1)
	go func() { done <- tun.WaitReadyContext(ctx, time.Minute) }()

	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case status := <-done:
		if status == ReadyStatusOK {
			t.Fatal("a cancelled wait reported the proxy ready")
		}
	case <-time.After(time.Second):
		t.Fatal("the wait outlived its context")
	}
}

// The rebuild's wait tells "still starting" apart from "started and failed":
// the former keeps waiting (a captcha may be on screen), the latter is the
// verdict the watchdog acts on.
func TestWaitStartedContextReportsWhetherTheStartEnded(t *testing.T) {
	tun, b := tunnelWithBoot()
	if status, started := tun.WaitStartedContext(context.Background(), 20*time.Millisecond); started || status != ReadyStatusError {
		t.Fatalf("a start still running read as started=%v status=%v", started, status)
	}
	b.result = -4
	close(b.ready)
	if status, started := tun.WaitStartedContext(context.Background(), time.Second); !started || status != ReadyStatusCallUnavailable {
		t.Fatalf("a start that ended with -4 read as started=%v status=%v", started, status)
	}
}

// WireGuard's endpoint is the port the proxy actually bound: a config without
// LocalPort asks for :0, and the address published by the listener is what the
// next generation binds again.
func TestListenAddrIsTheAddressTheProxyPublished(t *testing.T) {
	tun := &Tunnel{cfg: Config{ListenAddr: "127.0.0.1:0"}}
	if got := tun.ListenAddr(); got != "127.0.0.1:0" {
		t.Fatalf("before the bind: %q", got)
	}
	tun.publishListenAddr("127.0.0.1:41234")
	if got := tun.ListenAddr(); got != "127.0.0.1:41234" {
		t.Fatalf("after the bind: %q", got)
	}
}

// A stopped tunnel starts no more generations: the device is gone.
func TestRestartTransportRefusesAfterStop(t *testing.T) {
	tun, _ := tunnelWithBoot()
	tun.Stop()
	if err := tun.RestartTransport(false); err == nil {
		t.Fatal("a rebuild after Stop started a proxy for a closed device")
	}
}

// Wake — это сигнал хоста для всех циклов keepalive: эпоха сдвигается, а канал,
// на котором цикл ждёт, закрывается.
func TestWakeReachesTheKeepaliveLoops(t *testing.T) {
	tun, err := NewTunnel(Config{VKLink: "test"})
	if err != nil {
		t.Fatal(err)
	}
	epoch, ch := hostWakeEpoch(), hostWakeChannel()
	tun.Wake("gateway back")
	if hostWakeEpoch() == epoch {
		t.Fatal("the wake epoch did not move")
	}
	select {
	case <-ch:
	default:
		t.Fatal("a loop parked on the wake channel was not woken")
	}
}

// A captcha notification left in the channel by a captcha nobody waited for
// here — asked for mid-session, solved by the tray's poll — is no captcha of
// this start: the wait goes on to the start's own outcome instead of handing
// Connect a captcha with no URL.
func TestWaitReadyIgnoresAStaleCaptchaNotification(t *testing.T) {
	if PendingCaptchaURL() != "" {
		t.Skip("a captcha is pending from another test")
	}
	for i := 0; i < 20; i++ {
		tun, b := tunnelWithBoot()
		select {
		case captchaNotifyCh <- struct{}{}:
		default:
		}
		close(b.ready) // result 0: the start came up
		if got := tun.WaitReady(time.Second); got != ReadyStatusOK {
			t.Fatalf("round %d: a stale notification read as %v, want ReadyStatusOK", i, got)
		}
	}
	// A start still running: the stale notification does not end the wait.
	tun, b := tunnelWithBoot()
	select {
	case captchaNotifyCh <- struct{}{}:
	default:
	}
	done := make(chan ReadyStatus, 1)
	go func() { done <- tun.WaitReady(5 * time.Second) }()
	select {
	case got := <-done:
		t.Fatalf("a stale notification ended the wait: %v", got)
	case <-time.After(100 * time.Millisecond):
	}
	close(b.ready)
	if got := <-done; got != ReadyStatusOK {
		t.Fatalf("the start's own outcome: %v, want ReadyStatusOK", got)
	}
}

// The tray's choice of transport restarts the transport only when it changes,
// and never on a tunnel that has stopped.
func TestSetRelayOverTCPRestartsOnlyOnAChange(t *testing.T) {
	stopped := &Tunnel{cfg: Config{UseUDP: true}, stopped: true}
	if _, err := stopped.SetRelayOverTCP(true); err == nil {
		t.Fatal("a stopped tunnel took a new transport")
	}
	same := &Tunnel{cfg: Config{UseUDP: true}}
	if changed, err := same.SetRelayOverTCP(false); changed || err != nil {
		t.Fatalf("UDP over UDP: changed=%v err=%v, want no restart", changed, err)
	}
	if !same.cfg.UseUDP {
		t.Fatal("the transport changed although the choice had not")
	}
}
