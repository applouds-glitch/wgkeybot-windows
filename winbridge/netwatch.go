package winbridge

import (
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// netChangeDebounce — пауза между уведомлением IP Helper и вызовом onChange.
// На одно событие (пропал шлюз, поднялся адаптер, сменился Wi-Fi) Windows
// присылает пачку уведомлений по маршрутам и интерфейсам за доли секунды;
// нам нужен один пересчёт после того, как таблица маршрутов устоялась.
const netChangeDebounce = time.Second

// NetworkWatcher подписывается через IP Helper API на изменения таблицы
// маршрутов и IP-интерфейсов и дёргает onChange с дебаунсом. Это событийная
// замена опросу дефолтного шлюза раз в 5 с из tray: отвал Wi-Fi или смена сети
// доходят до прокси за секунду, а не за цикл опроса. Сам опрос остаётся
// страховкой — уведомления Windows не гарантированы.
//
// Колбэки IP Helper приходят на потоке Windows; здесь они лишь взводят таймер,
// а onChange выполняется уже на горутине таймера.
type NetworkWatcher struct {
	routeCb *winipcfg.RouteChangeCallback
	ifaceCb *winipcfg.InterfaceChangeCallback

	mu     sync.Mutex
	timer  *time.Timer
	closed bool
}

// WatchNetwork регистрирует подписки и возвращает watcher. onChange вызывается
// не чаще одного раза на netChangeDebounce после последнего уведомления.
func WatchNetwork(onChange func()) (*NetworkWatcher, error) {
	w := &NetworkWatcher{}
	kick := func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.closed {
			return
		}
		if w.timer != nil {
			w.timer.Stop()
		}
		w.timer = time.AfterFunc(netChangeDebounce, onChange)
	}
	rc, err := winipcfg.RegisterRouteChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPforwardRow2) { kick() })
	if err != nil {
		return nil, err
	}
	ic, err := winipcfg.RegisterInterfaceChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPInterfaceRow) { kick() })
	if err != nil {
		rc.Unregister()
		return nil, err
	}
	w.routeCb, w.ifaceCb = rc, ic
	return w, nil
}

// Close снимает подписки и отменяет взведённый, но не сработавший таймер.
func (w *NetworkWatcher) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.closed = true
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	w.mu.Unlock()
	w.routeCb.Unregister()
	w.ifaceCb.Unregister()
}
