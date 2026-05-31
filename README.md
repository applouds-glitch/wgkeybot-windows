# WgKeyBot для Windows

WireGuard VPN клиент с TURN/DTLS прокси и авторизацией через ВКонтакте.

Приложение в системном трее. Один `.exe` файл + wintun.dll.

## Скачать

[Последний релиз](https://github.com/applouds-glitch/wgkeybot-windows/releases/latest) — выберите `.zip` для вашей архитектуры (amd64, x86, arm64).

В архиве `wgkeybot.exe` и `wintun.dll`. Положите оба файла в одну папку.

## Быстрый старт

1. Получите токен у бота [@wg_key_bot](https://t.me/wg_key_bot) в Telegram
2. Запустите `wgkeybot.exe` (подтвердите запрос UAC — права администратора нужны для VPN режима)
3. Правый клик по иконке в трее → **Импорт токена...** → вставьте токен
4. Правый клик → **Подключить...** → туннель поднят (один конфиг — сразу, несколько — выбор)

## Режимы работы

### VPN режим (по умолчанию)

Весь системный трафик идёт через туннель. Нужны права администратора — создаётся виртуальный сетевой адаптер (wintun), системные маршруты настраиваются автоматически.

### SOCKS прокси режим

Запускает локальный SOCKS5-сервер на `127.0.0.1:1080` (порт настраивается в меню). Права администратора **не нужны**. Отдельные приложения проксируются вручную — системный трафик остаётся прямым.

Поддерживаются:
- **CONNECT** — TCP-соединения (HTTP, HTTPS, SSH и т.д.)
- **UDP ASSOCIATE** — UDP через туннель (голосовые звонки, игры)
- DNS резолвится удалённо (socks5h) — утечек DNS нет

#### Подключение Telegram

В настройках Telegram:
**Настройки → Конфиденциальность и безопасность → Прокси-сервер → Добавить прокси**

| Поле | Значение |
|------|----------|
| Тип | SOCKS5 |
| Хост | 127.0.0.1 |
| Порт | 1080 |

Нажмите **Сохранить** → Telegram переключится на туннель. В статусе появится задержка до прокси.

#### Подключение Chrome

Вариант 1 — запустить Chrome с флагом (рекомендуется, не затрагивает другие браузеры):

```bat
chrome.exe --proxy-server="socks5://127.0.0.1:1080" --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"
```

Вариант 2 — расширение [Proxy SwitchyOmega](https://chromewebstore.google.com/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif):
- Создайте профиль: протокол **SOCKS5**, сервер `127.0.0.1`, порт `1080`
- Активируйте профиль — трафик браузера пойдёт через туннель

#### Другие приложения

Любое приложение с поддержкой SOCKS5 прокси подключается аналогично:
- **curl**: `curl --socks5-hostname 127.0.0.1:1080 https://example.com`
- **Python requests**: через библиотеку `PySocks` или `httpx`
- Системный прокси Windows: Параметры → Сеть → Прокси → Ручная настройка (только для приложений, уважающих системный прокси)

## Требования

| | VPN режим | SOCKS режим |
|--|-----------|-------------|
| Windows 10 1903+ | ✓ | ✓ |
| wintun.dll | ✓ | — |
| Права администратора | ✓ | — |

## Меню трея

| Пункт | Описание |
|---|---|
| Подключить... | Подключиться (один конфиг — сразу, несколько — выбор) |
| Отключить | Остановить туннель |
| Импорт токена... | Получить конфиг по токену |
| Обновить конфиг | Перезагрузить конфиг по сохранённому токену |
| Подключаться при запуске | Автоматический подъём туннеля при старте |
| Режим → VPN | Весь трафик через туннель |
| Режим → SOCKS прокси | Локальный SOCKS5 без захвата системы |
| О программе | Версия и информация |
| Выход | Отключиться и закрыть программу |

## Как это работает

```
Приложение → [wintun / userspace netstack] → TURN/DTLS прокси → TURN сервер → WireGuard сервер → Интернет
```

- WireGuard туннель на userspace реализации (wireguard-go)
- TURN/DTLS для обхода NAT и защиты от DPI
- Авторизация через VK OAuth
- Watchdog: автоматический переподъём туннеля при зависшем handshake

## Сборка из исходников

```bash
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
goversioninfo -o rsrc_windows.syso versioninfo.json
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o wgkeybot.exe .
```

## Отказ от ответственности

Автор не несёт ответственности за использование программы. Вы используете её на свой страх и риск.
Программа предназначена исключительно для законного использования в образовательных и исследовательских целях.

---

## English

WireGuard VPN client with TURN/DTLS proxy and VK authentication.

System tray app for Windows. Supports two modes:
- **VPN** — full system routing via wintun adapter (requires admin)
- **SOCKS5 proxy** — local proxy on `127.0.0.1:1080`, no admin required; configure per-app (Telegram, Chrome, curl, etc.)

Downloads and quick start: [see Russian section above](#быстрый-старт).

## License

Copyright (c) 2026 WgKeyBot. Все права защищены.

Данное программное обеспечение предоставляется исключительно для личного некоммерческого использования.
Запрещается распространение, модификация, продажа и коммерческое использование без письменного разрешения автора.

This software is provided for personal, non-commercial use only.
Redistribution, modification, sale, and commercial use are prohibited without the author's written permission.
