package watchdog

import (
	"testing"
	"time"
)

// pollEvery прогоняет n опросов с шагом PollInterval и возвращает последнее
// событие и момент последнего опроса.
func pollEvery(h *Handshake, from time.Time, n int, hs time.Time, tx func(i int) uint64) (Event, time.Time) {
	now := from
	ev := Alive
	for i := 1; i <= n; i++ {
		now = from.Add(time.Duration(i) * PollInterval)
		ev = h.Poll(now, hs, tx(i))
		if ev == Dead {
			return ev, now
		}
	}
	return ev, now
}

func growing(i int) uint64 { return uint64(i) * 1000 }

// Прежнее поведение не меняется: устаревший handshake при растущем TX —
// мёртвый туннель после DeadChecksMax опросов подряд.
func TestStaleHandshakeWithGrowingTxIsDead(t *testing.T) {
	start := time.Now()
	h := New(start)
	hs := start.Add(-StaleAfter - time.Minute)
	ev, at := pollEvery(h, start, 5, hs, growing)
	if ev != Dead {
		t.Fatalf("stale handshake with growing TX read as %v", ev)
	}
	// Первый опрос только запоминает TX, два следующих — мёртвые.
	if want := start.Add(3 * PollInterval); !at.Equal(want) {
		t.Fatalf("dead at +%v, want +%v", at.Sub(start), want.Sub(start))
	}
}

func TestStaleHandshakeWithoutTxIsAlive(t *testing.T) {
	start := time.Now()
	h := New(start)
	hs := start.Add(-StaleAfter - time.Minute)
	if ev, _ := pollEvery(h, start, 10, hs, func(int) uint64 { return 42 }); ev != Alive {
		t.Fatalf("idle tunnel read as %v", ev)
	}
}

func TestNoHandshakeIsDeadAfterNeverAfter(t *testing.T) {
	start := time.Now()
	h := New(start)
	ev, at := pollEvery(h, start, 20, time.Time{}, growing)
	if ev != Dead {
		t.Fatalf("no handshake at all read as %v", ev)
	}
	if at.Sub(start) <= NeverAfter {
		t.Fatalf("declared dead %v after start, before NeverAfter", at.Sub(start))
	}
}

// Сон ноутбука: первый тик после пробуждения приходит с разрывом во всю длину
// сна, а handshake к этому моменту заведомо устарел. Это не мёртвый туннель —
// он получает NeverAfter на свежий handshake.
func TestResumeGivesTheTunnelAGrace(t *testing.T) {
	start := time.Now()
	h := New(start)
	h.Poll(start.Add(PollInterval), start, 1000)

	woke := start.Add(PollInterval + 2*time.Hour)
	if ev := h.Poll(woke, start, 2000); ev != Resumed {
		t.Fatalf("a two-hour gap read as %v", ev)
	}
	// Handshake из-до сна, TX растёт: в пределах grace — живой.
	now := woke
	for now.Sub(woke) < NeverAfter {
		now = now.Add(PollInterval)
		if ev := h.Poll(now, start, uint64(now.Sub(woke))); ev == Dead {
			t.Fatalf("declared dead %v after resume, inside the grace", now.Sub(woke))
		}
	}
	// Grace кончился, handshake так и не обновился — теперь мёртвый.
	ev := Alive
	for i := 0; i < DeadChecksMax+1 && ev != Dead; i++ {
		now = now.Add(PollInterval)
		ev = h.Poll(now, start, uint64(now.Sub(woke)))
	}
	if ev != Dead {
		t.Fatal("a tunnel that never recovered after resume was never declared dead")
	}
}

// Свежий handshake после пробуждения — туннель жив и дальше судится как обычно.
func TestResumeThenFreshHandshakeIsAlive(t *testing.T) {
	start := time.Now()
	h := New(start)
	woke := start.Add(time.Hour)
	h.Poll(woke, start, 0)
	for i := 1; i <= 20; i++ {
		now := woke.Add(time.Duration(i) * PollInterval)
		if ev := h.Poll(now, now.Add(-10*time.Second), uint64(i)*1000); ev != Alive {
			t.Fatalf("poll %d with a fresh handshake read as %v", i, ev)
		}
	}
}

// Без сети туннель не судят; вернувшейся сети дают NeverAfter.
func TestOfflineHoldsTheVerdict(t *testing.T) {
	start := time.Now()
	h := New(start)
	stale := start.Add(-time.Hour)
	now := start
	for i := 0; i < 20; i++ {
		now = now.Add(PollInterval)
		h.Offline(now)
	}
	back := now
	for now.Sub(back) < NeverAfter {
		now = now.Add(PollInterval)
		if ev := h.Poll(now, stale, uint64(now.Sub(start))); ev == Dead {
			t.Fatalf("declared dead %v after the network returned", now.Sub(back))
		}
	}
}

// Капча: наблюдение начинается заново, но без grace — как было.
func TestHoldRestartsWithoutGrace(t *testing.T) {
	start := time.Now()
	h := New(start)
	h.Hold(start.Add(10 * time.Minute))
	from := start.Add(10 * time.Minute)
	ev, at := pollEvery(h, from, 5, start, growing)
	if ev != Dead || at.Sub(from) != 3*PollInterval {
		t.Fatalf("after a hold: %v at +%v, want dead at +%v", ev, at.Sub(from), 3*PollInterval)
	}
}
