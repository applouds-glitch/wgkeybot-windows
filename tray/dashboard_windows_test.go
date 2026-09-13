//go:build windows

package tray

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wgkeybot/windows/winbridge"
)

func TestDashboardConfigAndTraffic(t *testing.T) {
	cfg := &winbridge.TunnelConfig{Endpoint: "vpn.example:51820", Address: []string{"10.0.0.2/32"},
		DNS: []string{"1.1.1.1"}, MTU: 1280, AllowedIPs: []string{"0.0.0.0/0"},
		PrivateKey: "PRIVATE-SECRET", PresharedKey: "PRESHARED-SECRET"}
	a := &App{savedConfig: cfg, settings: winbridge.AppSettings{Mode: winbridge.ModeSOCKS,
		SocksPort: 2080, AccessToken: "TOKEN-SECRET"}}
	s := a.dashboardSnapshot()
	if !s.canConnect || s.canDisconnect || !strings.Contains(s.hint, "127.0.0.1:2080") {
		t.Fatalf("unexpected disconnected controls: %+v", s)
	}
	for _, want := range []string{"vpn.example:51820", "10.0.0.2/32", "1.1.1.1", "1280", "0.0.0.0/0"} {
		if !strings.Contains(s.config, want) {
			t.Errorf("config missing %q", want)
		}
	}
	for _, secret := range []string{cfg.PrivateKey, cfg.PresharedKey, a.settings.AccessToken} {
		if strings.Contains(s.config+s.configNote+s.hint, secret) {
			t.Error("secret exposed in dashboard text")
		}
	}
	a.manager = winbridge.NewManager(cfg)
	a.cfg = cfg
	a.cancel = func() {}
	a.activeConfigHash, a.settings.LastConfigHash = "old", "new"
	a.stats = winbridge.TunnelStats{Connected: true, RxBytes: 2 << 20, TxBytes: 1 << 20, LastHandshake: time.Now()}
	a.connectedAt = time.Now().Add(-2 * time.Minute)
	s = a.dashboardSnapshot()
	if s.canConnect || !s.canDisconnect || s.status != "Подключено" || s.total != "3.0 МБ" {
		t.Fatalf("unexpected connected state: %+v", s)
	}
	if !strings.Contains(s.configNote, "обновление") {
		t.Error("pending config update not indicated")
	}
	a.stats.LastHandshake = time.Time{}
	if got := a.dashboardSnapshot().status; got != "Ожидание ответа WireGuard…" {
		t.Fatal(got)
	}
	a.stats.LastHandshake = time.Now().Add(-4 * time.Minute)
	if got := a.dashboardSnapshot().status; got != "Восстановление связи…" {
		t.Fatal(got)
	}
	a.manager, a.cancel = nil, nil
	s = a.dashboardSnapshot()
	if s.status != "Отключено" || s.total != "3.0 МБ" || !strings.Contains(s.session, "последнего") {
		t.Fatalf("final counters not retained: %+v", s)
	}
}

func TestDashboardBusyAndMissingConfig(t *testing.T) {
	a := &App{configError: "Импортируйте токен"}
	if s := a.dashboardSnapshot(); s.canConnect || s.config != a.configError {
		t.Fatal(s)
	}
	a.savedConfig = &winbridge.TunnelConfig{}
	a.connecting = true
	if s := a.dashboardSnapshot(); !s.busy || s.canConnect || s.status != "Подключение…" {
		t.Fatal(s)
	}
	a.connecting = false
	a.disconnecting = true
	if s := a.dashboardSnapshot(); !s.busy || s.canConnect || s.status != "Отключение…" {
		t.Fatal(s)
	}
	a.disconnecting = false
	a.refreshing.Store(true)
	if s := a.dashboardSnapshot(); s.canConnect || !s.refreshing {
		t.Fatal(s)
	}
}

func TestCancelledStatusWatcherReturnsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { (&App{}).watchStatus(ctx, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled watcher is still polling")
	}
}
