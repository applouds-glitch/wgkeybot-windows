//go:build windows

package tray

import (
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/wgkeybot/windows/pkg/expert"
	"github.com/wgkeybot/windows/pkg/proxy"
	"github.com/wgkeybot/windows/winbridge"
)

// Поле ссылок многострочное: читается то, что видит пользователь, а запись идёт
// мимо кеша setText — пользователь мог изменить текст после прошлой записи.
func TestExpertEditTextRoundTrip(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	w, err := newNativeWindow("WgKeyBot expert test", 472, 152, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.dispose()
	edit := w.add("EDIT", "", 0x00800000|0x0004|0x1000, 0, 20, 20, 420, 80, 0)
	const links = "first_link_1\r\nhttps://vk.ru/call/join/second_link_2"
	setEditText(edit, links)
	if got := editText(edit); got != links {
		t.Fatalf("read %q, want %q", got, links)
	}
	pSetWindowText.Call(edit.hwnd, uintptr(unsafe.Pointer(nativeString("typed by the user"))))
	setEditText(edit, links)
	if got := editText(edit); got != links {
		t.Fatalf("a preset written over the user's text was skipped: %q", got)
	}
	if got := expert.ParseLinks(editText(edit)).Hashes; len(got) != 2 || got[1] != "second_link_2" {
		t.Fatalf("parsed %v", got)
	}
}

// Режим эксперта ложится на копию конфига: сохранённый остаётся таким, каким его
// выдал бот, а ссылки хранятся под DPAPI и читаются обратно.
func TestApplyExpertOverridesACopy(t *testing.T) {
	cfg := &winbridge.TunnelConfig{MTU: 1280, DNS: []string{"8.8.8.8", "8.8.4.4"},
		TURN: proxy.Config{VKLink: "config_link_1,config_link_2"}}
	var s winbridge.AppSettings
	e := expert.Settings{Enabled: true, MTU: 1200, DNS: "1.1.1.1, 1.0.0.1", VKLinks: "https://vk.ru/call/join/own_link_1"}
	if err := s.SetExpertSettings(e); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.Expert.VKLinks, "own_link_1") {
		t.Fatal("the VK links are stored in the clear")
	}
	if got := s.ExpertSettings(); got != e {
		t.Fatalf("round trip: got %+v, want %+v", got, e)
	}

	out, on := winbridge.ApplyExpert(cfg, s.ExpertSettings())
	if !on || out == cfg {
		t.Fatal("overrides not applied to a copy")
	}
	if out.MTU != 1200 || strings.Join(out.DNS, ",") != "1.1.1.1,1.0.0.1" || out.TURN.VKLink != "own_link_1" {
		t.Fatalf("applied: MTU %d, DNS %v, links %q", out.MTU, out.DNS, out.TURN.VKLink)
	}
	if cfg.MTU != 1280 || cfg.DNS[0] != "8.8.8.8" || cfg.TURN.VKLink != "config_link_1,config_link_2" {
		t.Fatal("the saved config was changed")
	}

	e.Enabled = false
	if out, on := winbridge.ApplyExpert(cfg, e); on || out != cfg {
		t.Fatal("overrides applied while the mode is off")
	}
}

func TestDashboardSaysExpertMode(t *testing.T) {
	cfg := &winbridge.TunnelConfig{MTU: 1200}
	a := &App{savedConfig: cfg, cfg: cfg, manager: winbridge.NewManager(cfg), expertActive: true}
	if s := a.dashboardSnapshot(); !strings.Contains(s.configNote, "режим эксперта") {
		t.Fatalf("note %q does not mention expert mode", s.configNote)
	}
}

func TestLinkVerdictText(t *testing.T) {
	for code, want := range map[int32]string{
		winbridge.LinkCheckOK:          "звонок жив",
		winbridge.LinkCheckUnavailable: "завершён",
		winbridge.LinkCheckCaptcha:     "капчу",
		winbridge.LinkCheckTemporary:   "позже",
	} {
		if got := linkVerdictText(3, code); !strings.HasPrefix(got, "Ссылка 3: ") || !strings.Contains(got, want) {
			t.Errorf("verdict %d: %q", code, got)
		}
	}
}
