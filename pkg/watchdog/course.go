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
	// StepHold — вердикт пришёл, пока ни один релей не отвечает по живой сети:
	// ждать, ничего не перезапуская.
	StepHold
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
	// SilentHold — сколько держится вердикт при молчащих релеях, прежде чем
	// туннель гасят: те два шага перезапуска, вместо которых он стоит, по
	// ~2,5 мин каждый.
	SilentHold = 5 * time.Minute
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
//
// Ни один перезапуск не делается, пока прокси говорит, что по живой сети не
// отвечает ни один релей (pathSilent — найденная темнота пути,
// pkg/proxy/dark_scout.go): вердикт тогда — StepHold (Android 8133eb44). В
// тёмные полосы Android 18.10 сеть по две-семь минут ничего не везла;
// перезапуск в такой полосе перезапускал прокси, который забывал темноту и
// снова посылал в неё всех воркеров, а второй сбрасывал креды ради похода в VK,
// который не мог пройти, — и, когда сеть возвращалась, стоил добычи, которую
// кеш сберёг бы, с шансом капчи. Темноту тем временем дозванивают разведчики,
// и первый же ответивший релей её заканчивает. Туннель всё равно гаснет —
// через SilentHold после удержанного вердикта, проверяемого на каждом опросе,
// пока релеи молчат, а не на следующем вердикте: тому нужен растущий TX, а
// WireGuard, бросив initiation, ничего не шлёт. Удержание заканчивают только
// handshake после его начала или пропавшая сеть. Вердикт, когда релеи снова
// отвечают, берёт тот шаг, что был следующим.
type Course struct {
	h        *Handshake
	since    time.Time // handshake старше этого момента не считается
	rebuilds int
	// heldSince — когда вердикт при молчащих релеях был удержан; ноль, пока
	// удержания нет.
	heldSince time.Time
}

// NewCourse начинает курс по туннелю, поднятому к моменту now.
func NewCourse(now time.Time) *Course {
	return &Course{h: New(now), since: now}
}

// Hold — см. Handshake.Hold; счёт перезапусков сохраняется.
func (c *Course) Hold(now time.Time) { c.h.Hold(now) }

// Offline — см. Handshake.Offline; без сети перезапускать нечего, счёт
// перезапусков сохраняется. Удержание при молчащих релеях кончается: сеть,
// которая вернётся, получит его целиком, а не остаток старого.
func (c *Course) Offline(now time.Time) {
	c.h.Offline(now)
	c.heldSince = time.Time{}
}

// Rebuilds — сколько перезапусков сделано с последнего handshake; 0, пока
// сессия здорова.
func (c *Course) Rebuilds() int { return c.rebuilds }

// Poll оценивает очередной опрос (первые три аргумента — как у
// Handshake.Poll); pathSilent — прокси туннеля не слышит ни одного релея по
// живой сети (см. Course).
func (c *Course) Poll(now, lastHandshake time.Time, tx uint64, pathSilent bool) Step {
	hs := lastHandshake
	if hs.Before(c.since) {
		hs = time.Time{}
	}
	recovered := !hs.IsZero() && c.rebuilds > 0
	if recovered {
		c.rebuilds = 0
	}
	if !c.heldSince.IsZero() && !lastHandshake.Before(c.heldSince) {
		c.heldSince = time.Time{} // handshake после начала удержания
	}
	ev := c.h.Poll(now, hs, tx)
	if ev == Resumed {
		c.heldSince = time.Time{}
		return StepResumed
	}
	if !c.heldSince.IsZero() && pathSilent {
		c.h.deadChecks = 0
		if now.Sub(c.heldSince) >= SilentHold {
			return StepTearDown
		}
		return StepNone
	}
	switch ev {
	case Dead:
		if pathSilent {
			c.heldSince = now
			c.h.deadChecks = 0
			return StepHold
		}
		c.heldSince = time.Time{}
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
