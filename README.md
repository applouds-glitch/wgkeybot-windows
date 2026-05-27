# WgKeyBot для Windows

WireGuard VPN клиент с TURN/DTLS прокси и авторизацией через ВКонтакте.

Приложение в системном трее. Один `.exe` файл + wintun.dll.

## Скачать

[Последний релиз](https://github.com/applouds-glitch/wgkeybot-windows/releases/latest) — выберите `.zip` для вашей архитектуры (amd64, x86, arm64).

В архиве `wgkeybot.exe` и `wintun.dll`. Положите оба файла в одну папку.

## Быстрый старт

1. Получите токен у бота [@wg_key_bot](https://t.me/wg_key_bot) в Telegram
2. Запустите `wgkeybot.exe` (подтвердите запрос UAC — права администратора нужны для виртуального сетевого адаптера)
3. Правый клик по иконке в трее → **Импорт токена...** → вставьте токен
4. Правый клик → **Подключить...** → VPN поднят (один конфиг — сразу, несколько — выбор)

## Требования

- Windows 10 1903 или новее
- [wintun.dll](https://www.wintun.net/) рядом с `.exe` (есть в архиве релиза)
- Права администратора (UAC elevation встроен в манифест)

## Меню трея

| Пункт | Описание |
|---|---|
| Подключить... | Подключиться (один конфиг — сразу, несколько — выбор) |
| Отключить | Остановить VPN туннель |
| Импорт токена... | Получить конфиг по токену |
| Подключаться при запуске | Автоматический подъём VPN при старте |
| О программе | Версия и информация |
| Выход | Отключиться и закрыть программу |

## Сборка из исходников

```bash
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
goversioninfo -o rsrc_windows.syso versioninfo.json
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o wgkeybot.exe .
```

## Как это работает

```
Приложение → WireGuard (wintun) → TURN/DTLS прокси → TURN сервер → WireGuard сервер → Интернет
```

- WireGuard туннель на userspace реализации (wireguard-go)
- TURN/DTLS для обхода NAT и защиты от DPI
- Обрафускация трафика WRAP (ChaCha20)
- Авторизация через VK OAuth
- Автоматическое решение капчи через браузер + reverse proxy
- Хранение конфигов через DPAPI (шифрование учётной записью Windows)

## Отказ от ответственности

Автор не несёт ответственности за использование программы. Вы используете её на свой страх и риск.
Программа предназначена исключительно для законного использования в образовательных и исследовательских целях.

---

## English

WireGuard VPN client with TURN/DTLS proxy and VK authentication.

System tray app for Windows. Build with `GOOS=windows go build`.

Downloads and quick start: [see Russian section above](#быстрый-старт).

## License

Copyright (c) 2026 WgKeyBot. Все права защищены.

Данное программное обеспечение предоставляется исключительно для личного некоммерческого использования.
Запрещается распространение, модификация, продажа и коммерческое использование без письменного разрешения автора.

This software is provided for personal, non-commercial use only.
Redistribution, modification, sale, and commercial use are prohibited without the author's written permission.
