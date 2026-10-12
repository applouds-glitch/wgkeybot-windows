//go:build windows

package tray

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/wgkeybot/windows/pkg/release"
	"golang.org/x/sys/windows"
)

// doCheckUpdate — пункт «Проверить обновление»: спрашивает GitHub о последнем
// релизе (pkg/release) и предлагает открыть его страницу в браузере. Проверка
// ручная, как в Android; серверный сигнал 426 «Требуется обновление» через
// control plane остаётся сам по себе. Скачивание и замена exe здесь не
// делаются: сборки не подписаны, проверить скачанное нечем.
func (a *App) doCheckUpdate() {
	if !a.checkingUpdate.CompareAndSwap(false, true) {
		return
	}
	defer a.checkingUpdate.Store(false)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rel, err := release.Latest(ctx, nil, release.DefaultRepo)
	switch {
	case errors.Is(err, release.ErrNoRelease):
		go ShowInfo("Проверка обновления", "На GitHub пока нет опубликованной версии.")
		return
	case err != nil:
		log.Printf("[Tray] update check failed: %v", err)
		go ShowError("Проверка обновления", "Не удалось проверить: "+err.Error())
		return
	}
	if !release.IsNewer(rel.Version, Version) {
		go ShowInfo("Проверка обновления", fmt.Sprintf("У вас последняя версия (v%s).", Version))
		return
	}
	log.Printf("[Tray] update available: v%s (installed v%s)", rel.Version, Version)
	msg := fmt.Sprintf("Доступна версия %s (у вас v%s).\n\nОткрыть страницу релиза в браузере?\nДля вашей системы: %s",
		rel.Version, Version, release.AssetName(rel.Tag, runtime.GOARCH))
	if askYesNo("Доступно обновление", msg) {
		if err := openURL(rel.PageURL); err != nil {
			log.Printf("[Tray] open release page: %v", err)
			go ShowError("Проверка обновления", "Не удалось открыть браузер. Страница релиза:\n"+rel.PageURL)
		}
	}
}

// askYesNo — MessageBox с кнопками «Да»/«Нет»; true, если нажали «Да».
func askYesNo(title, message string) bool {
	const (
		mbYesNo         = 0x00000004
		mbIconQuestion  = 0x00000020
		mbSetForeground = 0x00010000
		idYes           = 6
	)
	r, _ := windows.MessageBox(0, nativeString(message), nativeString(title), mbYesNo|mbIconQuestion|mbSetForeground)
	return r == idYes
}

// openURL открывает адрес в браузере по умолчанию через ShellExecute — без
// спавна cmd.exe из процесса с правами администратора.
func openURL(rawURL string) error {
	const swShowNormal = 1
	return windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(rawURL), nil, nil, swShowNormal)
}
