package winbridge

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// SolveCaptchaProxy starts a local HTTP reverse proxy that serves the VK captcha
// page. Security headers (CSP, X-Frame-Options) are stripped from proxied
// responses so injected JavaScript can hook XHR/fetch calls and intercept the
// success_token automatically. The user only needs to solve the captcha itself
// — token extraction is fully automatic.
//
// Falls back to a manual PowerShell InputBox dialog on timeout or if the proxy
// fails to start.
func SolveCaptchaProxy(ctx context.Context, redirectURI string, timeout time.Duration) (string, error) {
	targetURL, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("parse captcha URL: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Printf("[Captcha] Cannot start proxy listener: %v — falling back to dialog", err)
		return solveCaptchaDialog(ctx, redirectURI, timeout)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	localOrigin := fmt.Sprintf("http://127.0.0.1:%d", port)
	upstreamOrigin := targetURL.Scheme + "://" + targetURL.Host

	tokenCh := make(chan string, 1)

	proxy := &httputil.ReverseProxy{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 10 * time.Second,
		},
		Rewrite: func(req *httputil.ProxyRequest) {
			req.Out.URL.Scheme = targetURL.Scheme
			req.Out.URL.Host = targetURL.Host
			req.Out.Host = targetURL.Host
			req.Out.Header.Del("Accept-Encoding")
			for _, h := range []string{"Origin", "Referer"} {
				if v := req.Out.Header.Get(h); v != "" {
					req.Out.Header.Set(h, strings.ReplaceAll(v, localOrigin, upstreamOrigin))
				}
			}
		},
		ModifyResponse: func(res *http.Response) error {
			stripSecurityHeaders(res)
			rewriteProxyCookies(res)

			if res.StatusCode >= 300 && res.StatusCode < 400 {
				if loc := res.Header.Get("Location"); loc != "" {
					res.Header.Set("Location", strings.ReplaceAll(loc, upstreamOrigin, localOrigin))
				}
			}

			contentType := res.Header.Get("Content-Type")
			isHTML := strings.Contains(contentType, "text/html")
			isCaptchaCheck := strings.Contains(res.Request.URL.Path, "captchaNotRobot.check")

			if !isHTML && !isCaptchaCheck {
				return nil
			}

			bodyBytes, err := readResponseBody(res)
			if err != nil {
				return err
			}

			if isCaptchaCheck {
				if token := extractSuccessToken(bodyBytes); token != "" {
					select {
					case tokenCh <- token:
					default:
					}
				}
			}

			if isHTML {
				bodyBytes = injectCaptchaJS(bodyBytes, localOrigin, upstreamOrigin)
				res.Header.Del("Content-Encoding")
			}

			res.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			res.ContentLength = int64(len(bodyBytes))
			res.Header.Set("Content-Length", fmt.Sprint(len(bodyBytes)))
			return nil
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/captcha-result", func(w http.ResponseWriter, r *http.Request) {
		if token := r.FormValue("token"); token != "" {
			select {
			case tokenCh <- token:
			default:
			}
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && targetURL.Path != "" && targetURL.Path != "/" && r.URL.RawQuery == "" {
			localPath := targetURL.Path
			if targetURL.RawQuery != "" {
				localPath += "?" + targetURL.RawQuery
			}
			http.Redirect(w, r, localPath, http.StatusTemporaryRedirect)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	log.Printf("[Captcha] Reverse proxy at %s → %s", localOrigin, upstreamOrigin)
	if err := openBrowser(localOrigin); err != nil {
		log.Printf("[Captcha] Cannot open browser: %v", err)
	}

	select {
	case token := <-tokenCh:
		log.Printf("[Captcha] Token intercepted automatically (%d bytes)", len(token))
		return token, nil
	case <-time.After(timeout):
		log.Printf("[Captcha] Proxy timeout after %v — falling back to manual dialog", timeout)
		return solveCaptchaDialog(ctx, redirectURI, timeout/2)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// ── Reverse proxy helpers ──────────────────────────────────────────────────────

func stripSecurityHeaders(res *http.Response) {
	for _, h := range []string{
		"Content-Security-Policy", "Content-Security-Policy-Report-Only",
		"X-Content-Security-Policy", "X-WebKit-CSP",
		"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
		"Cross-Origin-Resource-Policy", "X-Frame-Options",
	} {
		res.Header.Del(h)
	}
}

func rewriteProxyCookies(res *http.Response) {
	cookies := res.Cookies()
	if len(cookies) == 0 {
		return
	}
	res.Header.Del("Set-Cookie")
	for _, c := range cookies {
		c.Domain = ""
		c.Secure = false
		c.Partitioned = false
		if c.SameSite == http.SameSiteNoneMode || c.SameSite == http.SameSiteStrictMode {
			c.SameSite = http.SameSiteLaxMode
		}
		res.Header.Add("Set-Cookie", c.String())
	}
}

func readResponseBody(res *http.Response) ([]byte, error) {
	reader := res.Body
	if res.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(res.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	}
	body, err := io.ReadAll(reader)
	res.Body.Close()
	return body, err
}

func extractSuccessToken(body []byte) string {
	var payload struct {
		Response struct {
			SuccessToken string `json:"success_token"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return payload.Response.SuccessToken
}

func injectCaptchaJS(html []byte, localOrigin, upstreamOrigin string) []byte {
	script := fmt.Sprintf(`<script>
(function() {
	var localOrigin = %[1]q;
	var upstreamOrigin = %[2]q;

	function rewriteURL(u) {
		if (!u || typeof u !== 'string') return u;
		if (u.indexOf(localOrigin) === 0) return u;
		if (u.indexOf(upstreamOrigin) === 0) return localOrigin + u.slice(upstreamOrigin.length);
		return u;
	}

	function deliverToken(token) {
		if (!token) return;
		var x = new XMLHttpRequest();
		x.open('POST', '/captcha-result', true);
		x.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
		x.send('token=' + encodeURIComponent(token));
	}

	// Hook XMLHttpRequest
	var origOpen = XMLHttpRequest.prototype.open;
	XMLHttpRequest.prototype.open = function() {
		if (arguments[1] && typeof arguments[1] === 'string') {
			this.__captchaURL = arguments[1];
			arguments[1] = rewriteURL(arguments[1]);
		}
		return origOpen.apply(this, arguments);
	};
	var origSend = XMLHttpRequest.prototype.send;
	XMLHttpRequest.prototype.send = function() {
		var xhr = this;
		if (xhr.__captchaURL && xhr.__captchaURL.indexOf('captchaNotRobot.check') !== -1) {
			xhr.addEventListener('load', function() {
				try {
					var r = JSON.parse(xhr.responseText);
					if (r.response && r.response.success_token) deliverToken(r.response.success_token);
				} catch(_) {}
			});
		}
		return origSend.apply(this, arguments);
	};

	// Hook fetch
	if (window.fetch) {
		var origFetch = window.fetch;
		window.fetch = function() {
			var u = arguments[0];
			var rawURL = (typeof u === 'object' && u && u.url) ? u.url : (typeof u === 'string' ? u : '');
			if (typeof u === 'object' && u && u.url) {
				u.url = rewriteURL(u.url);
			} else if (typeof u === 'string') {
				arguments[0] = rewriteURL(u);
			}
			var p = origFetch.apply(this, arguments);
			if (rawURL && rawURL.indexOf('captchaNotRobot.check') !== -1) {
				p.then(function(r) { return r.clone().json(); }).then(function(d) {
					if (d.response && d.response.success_token) deliverToken(d.response.success_token);
				}).catch(function() {});
			}
			return p;
		};
	}

	// Rewrite attributes in existing DOM
	function rewriteDoc(root) {
		if (!root || !root.querySelectorAll) return;
		['href','src','action'].forEach(function(attr) {
			root.querySelectorAll('[' + attr + ']').forEach(function(el) {
				var v = el.getAttribute(attr);
				if (v) { var r = rewriteURL(v); if (r !== v) el.setAttribute(attr, r); }
			});
		});
	}
	rewriteDoc(document);

	// Watch for dynamically added elements
	if (window.MutationObserver) {
		new MutationObserver(function(mutations) {
			mutations.forEach(function(m) {
				m.addedNodes.forEach(function(n) {
					if (n.nodeType === 1) rewriteDoc(n);
				});
			});
		}).observe(document.documentElement, {subtree: true, childList: true});
	}
})();
</script>
`, localOrigin, upstreamOrigin)

	if idx := bytes.Index(html, []byte("</head>")); idx >= 0 {
		return append(append([]byte{}, html[:idx]...), append([]byte(script), html[idx:]...)...)
	}
	if idx := bytes.Index(html, []byte("</body>")); idx >= 0 {
		return append(append([]byte{}, html[:idx]...), append([]byte(script), html[idx:]...)...)
	}
	return append(html, []byte(script)...)
}

// ── Manual dialog fallback ─────────────────────────────────────────────────────

func solveCaptchaDialog(ctx context.Context, redirectURI string, timeout time.Duration) (string, error) {
	log.Printf("[Captcha] Opening browser for manual captcha solve")
	if err := openBrowser(redirectURI); err != nil {
		log.Printf("[Captcha] Cannot open browser: %v", err)
	}

	dlCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tokenCh := make(chan string, 1)
	go func() {
		token := psInputDialog(dlCtx,
			"WgKeyBot — Captcha",
			"Решите captcha в браузере.\nСкопируйте success_token из адресной строки браузера и вставьте сюда:",
		)
		if token != "" {
			select {
			case tokenCh <- token:
			default:
			}
		}
	}()

	select {
	case token := <-tokenCh:
		log.Printf("[Captcha] Token from dialog (%d bytes)", len(token))
		return token, nil
	case <-dlCtx.Done():
		return "", fmt.Errorf("captcha: %w", dlCtx.Err())
	}
}

func psInputDialog(ctx context.Context, title, prompt string) string {
	esc := func(s string) string {
		s = strings.ReplaceAll(s, "'", "''")
		s = strings.ReplaceAll(s, "\n", "' + \"`n\" + '")
		return s
	}
	script := fmt.Sprintf(`
Add-Type -AssemblyName Microsoft.VisualBasic
$r = [Microsoft.VisualBasic.Interaction]::InputBox('%s', '%s', '')
Write-Output $r
`, esc(prompt), esc(title))
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	out, err := cmd.Output()
	if err != nil {
		log.Printf("[Captcha] psInputDialog error: %v", err)
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ── Browser ────────────────────────────────────────────────────────────────────

func openBrowser(rawURL string) error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/c", "start", "", rawURL)
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
		return cmd.Start()
	default:
		log.Printf("[Captcha] Would open browser: %s", rawURL)
		return nil
	}
}

// ── System DNS ─────────────────────────────────────────────────────────────────

func GetSystemDNS() []string {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var servers []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		ip := strings.TrimSpace(line)
		if net.ParseIP(ip) != nil && !seen[ip] {
			seen[ip] = true
			servers = append(servers, ip)
		}
	}
	return servers
}
