module github.com/wgkeybot/windows

go 1.25

require (
	github.com/bogdanfinn/fhttp v0.6.8
	github.com/cbeuw/connutil v1.0.1
	github.com/getlantern/systray v1.2.2
	github.com/google/uuid v1.6.0
	github.com/jchv/go-webview2 v0.0.0-20260205173254-56598839c808
	github.com/kiper292/tls-client v1.14.1
	github.com/pion/dtls/v3 v3.0.10
	github.com/pion/logging v0.2.4
	github.com/pion/turn/v5 v5.0.2
	golang.org/x/sys v0.39.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	golang.zx2c4.com/wireguard/windows v0.5.3
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/bdandy/go-errors v1.2.2 // indirect
	github.com/bdandy/go-socks4 v1.2.3 // indirect
	github.com/bogdanfinn/quic-go-utls v1.0.9-utls // indirect
	github.com/bogdanfinn/utls v1.7.7-barnius // indirect
	github.com/bogdanfinn/websocket v1.5.5-barnius // indirect
	github.com/getlantern/context v0.0.0-20190109183933-c447772a6520 // indirect
	github.com/getlantern/errors v0.0.0-20190325191628-abdb3e3e36f7 // indirect
	github.com/getlantern/golog v0.0.0-20190830074920-4ef2e798c2d7 // indirect
	github.com/getlantern/hex v0.0.0-20190417191902-c6586a6fe0b7 // indirect
	github.com/getlantern/hidden v0.0.0-20190325191715-f02dbb02be55 // indirect
	github.com/getlantern/ops v0.0.0-20190325191751-d70cb0d6f85f // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/jchv/go-winloader v0.0.0-20250406163304-c1995be93bd1 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/oxtoacart/bpool v0.0.0-20190530202638-03653db5a59c // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/stun/v3 v3.1.1 // indirect
	github.com/pion/transport/v4 v4.0.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/tam7t/hpkp v0.0.0-20160821193359-2b70b4024ed5 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	golang.org/x/time v0.10.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)

replace github.com/bogdanfinn/tls-client v1.14.0 => github.com/kiper292/tls-client v1.14.1
