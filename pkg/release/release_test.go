package release

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTagFromLocation(t *testing.T) {
	const repo = "owner/wgkeybot-windows"
	cases := []struct {
		location string
		tag      string
		ok       bool
	}{
		{"https://github.com/owner/wgkeybot-windows/releases/tag/v1.5.0", "v1.5.0", true},
		{"/owner/wgkeybot-windows/releases/tag/v1.5.0", "v1.5.0", true},
		{"https://github.com/Owner/WgKeyBot-Windows/releases/tag/v1.5.0", "v1.5.0", true},
		{"https://github.com/owner/wgkeybot-windows/releases", "", false}, // ни одного релиза
		{"https://github.com/owner/wgkeybot-windows/releases/tag/", "", false},
		{"https://github.com/owner/wgkeybot-windows/releases/tag/v1/extra", "", false},
		{"https://github.com/other/repo/releases/tag/v9.9.9", "", false},
		{"", "", false},
		{"::not a url", "", false},
	}
	for _, c := range cases {
		tag, ok := TagFromLocation(repo, c.location)
		if ok != c.ok || tag != c.tag {
			t.Errorf("%q: got %q %v, want %q %v", c.location, tag, ok, c.tag, c.ok)
		}
	}
}

func TestVersionOf(t *testing.T) {
	for tag, want := range map[string]string{"v1.5.0": "1.5.0", "1.5": "1.5", "v2.0.6.1": "2.0.6.1", "nightly": "", "v1": "", "v1.5.0-rc1": ""} {
		got, ok := VersionOf(tag)
		if ok != (want != "") || (ok && got != want) {
			t.Errorf("%q: got %q %v, want %q", tag, got, ok, want)
		}
	}
}

func TestIsNewer(t *testing.T) {
	cases := []struct {
		latest, installed string
		want              bool
	}{
		{"1.5.1", "1.5.0", true},
		{"1.5.0", "1.5.0", false},
		{"1.4.9", "1.5.0", false},
		{"2.0.0", "1.9.9", true},
		{"1.5.0", "1.5.0-debug", false},
		{"1.5.1", "1.5.0-rc1", true},
		{"0.0.1", "dev", true}, // сборке для разработки любой релиз новее
		{"1.10.0", "1.9.0", true},
	}
	for _, c := range cases {
		if got := IsNewer(c.latest, c.installed); got != c.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v", c.latest, c.installed, got, c.want)
		}
	}
}

func TestAssetName(t *testing.T) {
	if got := AssetName("v1.5.0", "amd64"); got != "wgkeybot-v1.5.0-windows-amd64.zip" {
		t.Fatalf("asset name %q does not match release.yml", got)
	}
}

// latestServer отвечает на HEAD /<repo>/releases/latest так, как отвечает GitHub.
func latestServer(t *testing.T, status int, location string) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("method %s, want HEAD", r.Method)
		}
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	client := srv.Client()
	// Any host the test names lands on the test server; its certificate is
	// for example.com, so the name is not checked (a test-only client).
	transport := client.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	transport.TLSClientConfig.InsecureSkipVerify = true
	return srv, client
}

func TestLatestReadsTheRedirect(t *testing.T) {
	const repo = "owner/wgkeybot-windows"
	_, client := latestServer(t, http.StatusFound, "https://github.com/"+repo+"/releases/tag/v1.6.0")
	rel, err := Latest(context.Background(), client, repo)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version != "1.6.0" || rel.Tag != "v1.6.0" || rel.PageURL != "https://github.com/"+repo+"/releases/tag/v1.6.0" {
		t.Fatalf("release %+v", rel)
	}
}

func TestLatestWithoutAReleaseOrWithAnOddAnswer(t *testing.T) {
	const repo = "owner/wgkeybot-windows"
	_, client := latestServer(t, http.StatusFound, "https://github.com/"+repo+"/releases")
	if _, err := Latest(context.Background(), client, repo); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("a repository without releases: %v", err)
	}
	_, client = latestServer(t, http.StatusFound, "https://github.com/"+repo+"/releases/tag/nightly")
	if _, err := Latest(context.Background(), client, repo); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("a tag that is not a version: %v", err)
	}
	_, client = latestServer(t, http.StatusNotFound, "")
	if _, err := Latest(context.Background(), client, repo); err == nil || errors.Is(err, ErrNoRelease) {
		t.Fatalf("a 404: %v", err)
	}
	if _, err := Latest(context.Background(), client, "not a repo"); err == nil {
		t.Fatal("a malformed repository name was asked about")
	}
}
