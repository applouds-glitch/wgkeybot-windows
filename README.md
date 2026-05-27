# WgKeyBot Windows

WireGuard VPN client with TURN/DTLS proxy and VK authentication for Windows.

System tray app. Single binary with wintun.dll.

## Download

[Latest release](https://github.com/applouds-glitch/wgkeybot-windows/releases/latest) — pick the `.zip` for your architecture (amd64, x86, arm64).

Each zip contains `wgkeybot.exe` and `wintun.dll`. Place both in the same folder.

## Quick start

1. Get a token from [@wg_key_bot](https://t.me/wg_key_bot) in Telegram
2. Launch `wgkeybot.exe` (accept UAC prompt — admin rights required for virtual network adapter)
3. Right-click tray icon → **Import token** → paste the token
4. Right-click tray icon → **Connect...** → pick the config → VPN is up

## System requirements

- Windows 10 1903 or later
- [wintun.dll](https://www.wintun.net/) next to the `.exe` (included in release zip)
- Administrator rights (UAC elevation is automatic)

## Tray menu

| Item | Description |
|---|---|
| Connect... | Pick a config and connect |
| Disconnect | Stop the VPN tunnel |
| Import token... | Fetch config from token |
| Auto-connect | Toggle automatic connect on startup |
| About | Version info |
| Exit | Disconnect and quit |

## Build from source

```bash
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
goversioninfo -o rsrc_windows.syso versioninfo.json
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o wgkeybot.exe .
```

## How it works

```
App → WireGuard (wintun) → TURN/DTLS proxy → TURN server → WireGuard backend → Internet
```

- WireGuard tunnel with userspace implementation (wireguard-go)
- TURN/DTLS for NAT traversal and DPI resistance
- WRAP obfuscation layer (ChaCha20)
- VK OAuth authentication
- Automatic captcha solving via browser + reverse proxy

## License

MIT
