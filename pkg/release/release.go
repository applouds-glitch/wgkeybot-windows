// Package release спрашивает у GitHub, какая версия WgKeyBot для Windows
// опубликована последней. Порт проверки из Android-клиента
// (ui/.../updater/GithubReleases.kt): проверка ручная, по кнопке.
//
// Ответ читается не из API, а из редиректа: `/releases/latest` отвечает 302 на
// `/releases/tag/<tag>`, и тег — это версия. api.github.com сказал бы то же
// самое в JSON, но пускает неавторизованный адрес 60 раз в час — а трафик
// приложения выходит через туннель, так что все пользователи одного сервера
// для GitHub один адрес. У редиректа страницы такой квоты нет.
//
// Цена — имя файла релиза не узнать, его надо знать: оно такое, каким его
// загружает release.yml (AssetName), и меняются они вместе. Скачивание здесь
// не делается: пользователю открывается страница релиза в браузере.
package release

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultRepo — репозиторий GitHub, где release.yml публикует сборки.
// Подставляется при сборке через -ldflags "-X .../pkg/release.DefaultRepo=owner/name".
var DefaultRepo = "applouds-glitch/wgkeybot-windows"

// Release — последняя опубликованная версия.
type Release struct {
	Version string // 1.5.0
	Tag     string // v1.5.0
	PageURL string // страница релиза
}

// ErrNoRelease — GitHub ответил, но назвал не релиз приложения: в репозитории
// нет ни одного релиза (редирект на /releases) или тег не похож на версию.
var ErrNoRelease = errors.New("no published release")

var (
	repoRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	versionRe = regexp.MustCompile(`^\d+(\.\d+){1,3}$`)
)

// IsRepo — value выглядит как owner/name.
func IsRepo(value string) bool { return repoRe.MatchString(value) }

// LatestURL — адрес, редирект с которого называет последний релиз.
func LatestURL(repo string) string { return "https://github.com/" + repo + "/releases/latest" }

// PageURL — страница релиза с тегом tag.
func PageURL(repo, tag string) string { return "https://github.com/" + repo + "/releases/tag/" + tag }

// AssetName — имя архива для архитектуры arch (runtime.GOARCH), как его
// называет release.yml: wgkeybot-v1.5.0-windows-amd64.zip.
func AssetName(tag, arch string) string { return "wgkeybot-" + tag + "-windows-" + arch + ".zip" }

// TagFromLocation достаёт тег из адреса, куда редиректит /releases/latest.
// Репозиторий без единого релиза редиректит на /releases, где тега нет; всё,
// что не страница тега этого репозитория, тоже не ответ.
func TagFromLocation(repo, location string) (string, bool) {
	if location == "" {
		return "", false
	}
	u, err := url.Parse(location)
	if err != nil {
		return "", false
	}
	prefix := "/" + repo + "/releases/tag/"
	path := u.Path
	if len(path) < len(prefix) || !strings.EqualFold(path[:len(prefix)], prefix) {
		return "", false
	}
	tag := path[len(prefix):]
	if tag == "" || strings.Contains(tag, "/") {
		return "", false
	}
	return tag, true
}

// VersionOf — «v2.0.6» → «2.0.6»; тег, который не версия (nightly, черновик),
// не считается.
func VersionOf(tag string) (string, bool) {
	v := strings.TrimPrefix(tag, "v")
	return v, versionRe.MatchString(v)
}

// CompareVersions сравнивает первые три числа версий; нечисловые части — 0.
func CompareVersions(a, b string) int {
	ap, bp := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		diff := part(ap, i) - part(bp, i)
		if diff != 0 {
			return diff
		}
	}
	return 0
}

func part(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	n, err := strconv.Atoi(parts[i])
	if err != nil {
		return 0
	}
	return n
}

// IsNewer — latest новее установленной installed. Суффикс сборки
// («1.4.0-debug») не часть номера; «dev» читается как 0.0.0, так что сборке
// для разработки любой релиз новее.
func IsNewer(latest, installed string) bool {
	return CompareVersions(latest, strings.SplitN(installed, "-", 2)[0]) > 0
}

// Latest спрашивает GitHub о последнем релизе repo. client может быть nil.
func Latest(ctx context.Context, client *http.Client, repo string) (Release, error) {
	if !IsRepo(repo) {
		return Release{}, errors.New("no release repository configured")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	// Редирект — сам ответ; следовать ему незачем.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, LatestURL(repo), nil)
	if err != nil {
		return Release{}, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 301, 302, 303, 307, 308:
	default:
		return Release{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tag, ok := TagFromLocation(repo, resp.Header.Get("Location"))
	if !ok {
		return Release{}, ErrNoRelease
	}
	version, ok := VersionOf(tag)
	if !ok {
		return Release{}, ErrNoRelease
	}
	return Release{Version: version, Tag: tag, PageURL: PageURL(repo, tag)}, nil
}
