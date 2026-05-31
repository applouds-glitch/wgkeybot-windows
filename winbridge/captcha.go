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
// page. Every resource the page references — including third-party hosts and
// protocol-relative URLs — is rewritten to load through 127.0.0.1, so from the
// browser's point of view everything is same-origin and no CORS/CSP rule can
// block the captcha widget. Injected JavaScript hooks XHR/fetch to intercept the
// success_token automatically; the user only solves the captcha itself.
//
// The browser opens once and the proxy stays alive until the token is
// intercepted or ctx is cancelled (disconnect). There is no internal timeout —
// the user solves the captcha at their own pace.
func SolveCaptchaProxy(ctx context.Context, redirectURI string) (string, error) {
	targetURL, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("parse captcha URL: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("captcha proxy listener: %w", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	localOrigin := fmt.Sprintf("http://127.0.0.1:%d", port)
	upstreamOrigin := targetURL.Scheme + "://" + targetURL.Host

	tokenCh := make(chan string, 1)
	deliver := func(token string) {
		if token == "" {
			return
		}
		select {
		case tokenCh <- token:
		default:
		}
	}

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   false,
	}

	// Main proxy: serves the captcha page from the redirect_uri host.
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(req *httputil.ProxyRequest) {
			req.Out.URL.Scheme = targetURL.Scheme
			req.Out.URL.Host = targetURL.Host
			if req.Out.URL.Path == "" {
				req.Out.URL.Path = targetURL.Path
			}
			req.Out.Host = targetURL.Host
			req.Out.Header.Del("Accept-Encoding")
			req.Out.Header.Del("TE")
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
			isCheck := strings.Contains(res.Request.URL.Path, "captchaNotRobot.check")
			if !isHTMLLike(contentType) && !isCheck {
				return nil
			}

			bodyBytes, err := readResponseBody(res)
			if err != nil {
				return err
			}

			if isCheck {
				deliver(extractSuccessToken(bodyBytes))
			}

			if isHTMLLike(contentType) {
				bodyBytes = []byte(rewriteCaptchaHTML(string(bodyBytes), localOrigin, upstreamOrigin))
				res.Header.Del("Content-Encoding")
			}

			res.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			res.ContentLength = int64(len(bodyBytes))
			res.Header.Set("Content-Length", fmt.Sprint(len(bodyBytes)))
			return nil
		},
	}

	mux := http.NewServeMux()

	// JS-hook delivery endpoint for the intercepted success_token.
	mux.HandleFunc("/local-captcha-result", func(w http.ResponseWriter, r *http.Request) {
		deliver(r.FormValue("token"))
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprint(w, "ok")
	})

	// Catch-all proxy for any third-party host the widget loads from. Because
	// the browser requests these from 127.0.0.1, everything stays same-origin
	// and no CORS rule applies.
	mux.HandleFunc("/generic_proxy", func(w http.ResponseWriter, r *http.Request) {
		parsed, err := url.Parse(r.URL.Query().Get("proxy_url"))
		if err != nil || parsed.Host == "" {
			http.Error(w, "bad proxy_url", http.StatusBadRequest)
			return
		}
		generic := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(req *httputil.ProxyRequest) {
				req.Out.URL.Scheme = parsed.Scheme
				req.Out.URL.Host = parsed.Host
				req.Out.URL.Path = parsed.Path
				req.Out.URL.RawQuery = parsed.RawQuery
				req.Out.Host = parsed.Host
				req.Out.Header.Del("Accept-Encoding")
			},
			ModifyResponse: func(res *http.Response) error {
				stripSecurityHeaders(res)
				if strings.Contains(parsed.Path, "captchaNotRobot.check") {
					body, err := readResponseBody(res)
					if err != nil {
						return err
					}
					deliver(extractSuccessToken(body))
					res.Header.Del("Content-Encoding")
					res.Body = io.NopCloser(bytes.NewReader(body))
					res.ContentLength = int64(len(body))
					res.Header.Set("Content-Length", fmt.Sprint(len(body)))
				}
				return nil
			},
		}
		generic.ServeHTTP(w, r)
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
	return presentCaptcha(ctx, localOrigin, tokenCh)
}

// ── Reverse proxy helpers ──────────────────────────────────────────────────────

func stripSecurityHeaders(res *http.Response) {
	for _, h := range []string{
		"Content-Security-Policy", "Content-Security-Policy-Report-Only",
		"X-Content-Security-Policy", "X-WebKit-CSP",
		"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
		"Cross-Origin-Resource-Policy", "X-Frame-Options",
		"Strict-Transport-Security", "Alt-Svc",
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

func isHTMLLike(contentType string) bool {
	return strings.Contains(contentType, "text/html") ||
		strings.Contains(contentType, "application/xhtml+xml")
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

// rewriteCaptchaHTML rewrites absolute upstream URLs to the local proxy in the
// raw HTML, then injects a script that reroutes every runtime URL (XHR, fetch,
// window.open, dynamically added href/src/action) through the local proxy so
// the whole captcha flow stays same-origin.
func rewriteCaptchaHTML(html, localOrigin, upstreamOrigin string) string {
	html = strings.ReplaceAll(html, upstreamOrigin, localOrigin)

	script := fmt.Sprintf(`
<script>
(function() {
    var localOrigin = %q;
    var upstreamOrigin = %q;

    function rewriteUrl(urlStr) {
        if (!urlStr || typeof urlStr !== 'string') return urlStr;
        if (urlStr.indexOf(localOrigin) === 0) return urlStr;
        if (urlStr.indexOf(upstreamOrigin) === 0) return localOrigin + urlStr.slice(upstreamOrigin.length);
        if (urlStr.indexOf('//') === 0) {
            return '/generic_proxy?proxy_url=' + encodeURIComponent(window.location.protocol + urlStr);
        }
        if (urlStr.indexOf('http://') === 0 || urlStr.indexOf('https://') === 0) {
            return '/generic_proxy?proxy_url=' + encodeURIComponent(urlStr);
        }
        return urlStr;
    }

    function rewriteElementAttr(el, attr) {
        if (!el || !el.getAttribute) return;
        var value = el.getAttribute(attr);
        if (!value) return;
        var rewritten = rewriteUrl(value);
        if (rewritten !== value) el.setAttribute(attr, rewritten);
    }

    function rewriteDocument(root) {
        if (!root || !root.querySelectorAll) return;
        root.querySelectorAll('[href]').forEach(function(el) { rewriteElementAttr(el, 'href'); });
        root.querySelectorAll('[src]').forEach(function(el) { rewriteElementAttr(el, 'src'); });
        root.querySelectorAll('form[action]').forEach(function(el) { rewriteElementAttr(el, 'action'); });
    }

    function handleSuccessToken(token) {
        if (!token) return;
        fetch('/local-captcha-result', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'token=' + encodeURIComponent(token)
        }).catch(function() {});
    }

    var origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function() {
        if (arguments[1] && typeof arguments[1] === 'string') {
            this._origUrl = arguments[1];
            arguments[1] = rewriteUrl(arguments[1]);
        }
        return origOpen.apply(this, arguments);
    };
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function() {
        var xhr = this;
        if (this._origUrl && this._origUrl.indexOf('captchaNotRobot.check') !== -1) {
            xhr.addEventListener('load', function() {
                try {
                    var data = JSON.parse(xhr.responseText);
                    if (data.response && data.response.success_token) handleSuccessToken(data.response.success_token);
                } catch (e) {}
            });
        }
        return origSend.apply(this, arguments);
    };

    var origFetch = window.fetch;
    if (origFetch) {
        window.fetch = function() {
            var url = arguments[0];
            var urlStr = (typeof url === 'object' && url && url.url) ? url.url : url;
            var origUrlStr = urlStr;
            if (typeof urlStr === 'string') {
                urlStr = rewriteUrl(urlStr);
                arguments[0] = urlStr;
            }
            var p = origFetch.apply(this, arguments);
            if (typeof origUrlStr === 'string' && origUrlStr.indexOf('captchaNotRobot.check') !== -1) {
                p.then(function(r) { return r.clone().json(); }).then(function(data) {
                    if (data.response && data.response.success_token) handleSuccessToken(data.response.success_token);
                }).catch(function() {});
            }
            return p;
        };
    }

    var origWindowOpen = window.open;
    if (origWindowOpen) {
        window.open = function(url) {
            if (typeof url === 'string') arguments[0] = rewriteUrl(url);
            return origWindowOpen.apply(this, arguments);
        };
    }

    rewriteDocument(document);
    if (document.documentElement && window.MutationObserver) {
        new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.type === 'attributes' && mutation.target) {
                    rewriteElementAttr(mutation.target, mutation.attributeName);
                    return;
                }
                mutation.addedNodes.forEach(function(node) {
                    if (node.nodeType === 1) rewriteDocument(node);
                });
            });
        }).observe(document.documentElement, {
            subtree: true, childList: true, attributes: true,
            attributeFilter: ['href', 'src', 'action']
        });
    }
})();
</script>
`, localOrigin, upstreamOrigin)

	if idx := strings.Index(html, "</head>"); idx >= 0 {
		return html[:idx] + script + html[idx:]
	}
	if idx := strings.Index(html, "</body>"); idx >= 0 {
		return html[:idx] + script + html[idx:]
	}
	return html + script
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
