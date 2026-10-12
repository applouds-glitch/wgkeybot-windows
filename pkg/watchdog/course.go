package watchdog

import "time"

// Step — что делать по итогам очередного опроса Course.
type Step int

const (
	// StepNone — ничего: туннель жив или решать пока рано.
	StepNone Step = iota
	// StepResumed — машина проснулась: счётчики сброшены, туннелю дан grace.
	StepResumed
	// StepRecovered — после перезапуска транспорта пришёл handshake: транспорт
	// вернулся, следующий отказ начнёт курс с первого шага.
	StepRecovered
	// StepRebuild — перезапустить TURN-транспорт на тех же кредах.
	StepRebuild
	// StepRebuildNewCreds — перезапустить его на новых кредах (один поход в VK).
	StepRebuildNewCreds
	// StepTearDown — сдаться: гасить туннель и переподключаться целиком.
	StepTearDown
)

const (
	// RebuiltGrace — сколько ждать первого handshake от только что
	// перезапущенного транспорта. WireGuard повторяет initiation каждые 5 с,
	// так что рабочий путь даёт handshake за секунды; вместе с двумя опросами
	// на вердикт — около 2,5 мин на шаг.
	RebuiltGrace = 90 * time.Second
	// Rebuilds — сколько раз транспорт перезапускается, прежде чем туннель
	// гасят; все, кроме первого, — на новых кредах.
	Rebuilds = 2
)

// Course — курс фонового watchdog'а по одной сессии туннеля: что делать с
// каждым вердиктом Handshake.
//
// Мёртвый вердикт раньше сразу гасил туннель — примерно через четыре минуты
// после последнего handshake. Воркеры прокси всё это время переподключаются
// сами, так что ждать дольше ничего не даёт; даёт другое действие. Поэтому
// первые два вердикта перезапускают TURN-транспорт — второй раз на новой
// VK-идентичности — и только третий гасит туннель: около девяти минут в сумме
// (Android d6bd64c4).
//
// После перезапуска старый handshake не считается: у нового транспорта есть
// RebuiltGrace на свой, от момента перезапуска. Handshake после перезапуска —
// значит, сработало, и следующий отказ начинает курс заново.
type Course struct {
	h        *Handshake
	since    time.Time // handshake старше этого момента не считается
	rebuilds int
}

// NewCourse начинает курс по туннелю, поднятому к моменту now.
func NewCourse(now time.Time) *Course {
	return &Course{h: New(now), since: now}
}

// Hold — см. Handshake.Hold; счёт перезапусков сохраняется.
func (c *Course) Hold(now time.Time) { c.h.Hold(now) }

// Offline — см. Handshake.Offline; без сети перезапускать нечего, счёт
// перезапусков сохраняется.
func (c *Course) Offline(now time.Time) { c.h.Offline(now) }

// Rebuilds — сколько перезапусков сделано с последнего handshake; 0, пока
// сессия здорова.
func (c *Course) Rebuilds() int { return c.rebuilds }

// Poll оценивает очередной опрос (аргументы — как у Handshake.Poll).
func (c *Course) Poll(now, lastHandshake time.Time, tx uint64) Step {
	hs := lastHandshake
	if hs.Before(c.since) {
		hs = time.Time{}
	}
	recovered := !hs.IsZero() && c.rebuilds > 0
	if recovered {
		c.rebuilds = 0
	}
	switch c.h.Poll(now, hs, tx) {
	case Resumed:
		return StepResumed
	case Dead:
		switch {
		case c.rebuilds >= Rebuilds:
			return StepTearDown
		case c.rebuilds == 0:
			c.rebuilds++
			return StepRebuild
		default:
			c.rebuilds++
			return StepRebuildNewCreds
		}
	}
	if recovered {
		return StepRecovered
	}
	return StepNone
}

// Rebuilt — транспорт перезапущен в момент at: новый судится от него, с
// RebuiltGrace на первый handshake.
func (c *Course) Rebuilt(at time.Time) {
	c.since = at
	c.h.Hold(at)
	c.h.never = RebuiltGrace
}
