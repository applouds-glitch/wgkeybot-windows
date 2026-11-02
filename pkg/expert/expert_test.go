package expert

import (
	"reflect"
	"strings"
	"testing"
)

// Кейсы — из андроидных ExpertOverridesTest и VkLinksTest.

func TestMTURange(t *testing.T) {
	for mtu, want := range map[int]bool{1000: true, 1500: true, 999: false, 1501: false, 0: false} {
		if got := ValidMTU(mtu); got != want {
			t.Errorf("ValidMTU(%d) = %v, want %v", mtu, got, want)
		}
	}
}

func TestParseDNS(t *testing.T) {
	servers, bad := ParseDNS(" 1.1.1.1, 8.8.8.8 ,77.88.8.8 ")
	if want := []string{"1.1.1.1", "8.8.8.8", "77.88.8.8"}; !reflect.DeepEqual(servers, want) || bad != nil {
		t.Fatalf("got %v (bad %v), want %v", servers, bad, want)
	}
	if servers, bad := ParseDNS(" , "); servers != nil || bad != nil {
		t.Fatalf("blank text: got %v, %v — want an empty list, not an error", servers, bad)
	}
	// Имя, сломанный адрес, порт и IPv6 — не годятся.
	_, bad = ParseDNS("dns.google, 300.1.1.1, 1.1.1.1:53, 2606:4700:4700::1111, 1.0.0.1")
	if want := []string{"dns.google", "300.1.1.1", "1.1.1.1:53", "2606:4700:4700::1111"}; !reflect.DeepEqual(bad, want) {
		t.Fatalf("bad = %v, want %v", bad, want)
	}
}

func TestLinkHash(t *testing.T) {
	for raw, want := range map[string]string{
		"https://vk.ru/call/join/abc_-123":          "abc_-123",
		"https://vk.com/call/join/abc_-123?x=1#top": "abc_-123",
		"vk.com/call/join/abc_-123/":                "abc_-123",
		"  abc_-123  ":                              "abc_-123",
	} {
		if got, ok := LinkHash(raw); !ok || got != want {
			t.Errorf("LinkHash(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"", "https://vk.com/id1", "https://vk.com/call/join/", "short", "has space"} {
		if got, ok := LinkHash(raw); ok {
			t.Errorf("LinkHash(%q) = %q accepted, want refused", raw, got)
		}
	}
}

func TestParseLinks(t *testing.T) {
	p := ParseLinks("https://vk.ru/call/join/first_1\nsecond_2, https://vk.com/call/join/first_1 | third_3 fourth_4\r\n")
	if want := []string{"first_1", "second_2", "third_3", "fourth_4"}; !reflect.DeepEqual(p.Hashes, want) || p.Invalid != nil || p.Truncated {
		t.Fatalf("got %+v, want hashes %v", p, want)
	}

	p = ParseLinks("first_1\nhttps://vk.com/im\nsecond_2")
	if !reflect.DeepEqual(p.Hashes, []string{"first_1", "second_2"}) || !reflect.DeepEqual(p.Invalid, []string{"https://vk.com/im"}) {
		t.Fatalf("invalid entry: got %+v", p)
	}

	var nine []string
	for i := 1; i <= 9; i++ {
		nine = append(nine, "hash_number_"+string(rune('0'+i)))
	}
	p = ParseLinks(strings.Join(nine, "\n"))
	if len(p.Hashes) != MaxLinks || p.Hashes[MaxLinks-1] != "hash_number_8" || !p.Truncated {
		t.Fatalf("nine links: got %+v", p)
	}
}

func TestSplitConfigLinks(t *testing.T) {
	if got, want := SplitConfigLinks(" a_link_1 , b_link_2|c_link_3,"), []string{"a_link_1", "b_link_2", "c_link_3"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := SplitConfigLinks(""); got != nil {
		t.Fatalf("empty value: got %v", got)
	}
}

// Пока режим выключен, ничего не действует, а значения хранятся; включённый
// отдаёт только то, что разбирается.
func TestOverrides(t *testing.T) {
	s := Settings{MTU: 1200, DNS: "1.1.1.1", VKLinks: "https://vk.ru/call/join/own_link_1"}
	if _, ok := s.Overrides(); ok {
		t.Fatal("overrides while the mode is off")
	}
	s.Enabled = true
	o, ok := s.Overrides()
	if !ok || o.MTU != 1200 || !reflect.DeepEqual(o.DNS, []string{"1.1.1.1"}) || !reflect.DeepEqual(o.VKLinks, []string{"own_link_1"}) {
		t.Fatalf("got %+v, %v", o, ok)
	}
	o, _ = Settings{Enabled: true, MTU: 9000, DNS: "dns.google"}.Overrides()
	if !o.Empty() {
		t.Fatalf("values that do not parse must read as the config's: %+v", o)
	}
}
