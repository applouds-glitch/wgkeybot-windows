package watchdog

import (
	"testing"
	"time"
)

// session — туннель, который шлёт постоянно (TX растёт на каждом опросе),
// опрашиваемый раз в PollInterval.
type session struct {
	c         *Course
	now       time.Time
	handshake time.Time
	tx        uint64
	silent    bool // прокси не слышит ни одного релея (pathSilent)
	idle      bool // TX не растёт
	offline   bool // физической сети нет: опрос — Course.Offline
}

func newSession(start time.Time) *session {
	return &session{c: NewCourse(start), now: start}
}

func (s *session) poll() Step {
	s.now = s.now.Add(PollInterval)
	if s.offline {
		s.c.Offline(s.now)
		return StepNone
	}
	if !s.idle {
		s.tx += 1000
	}
	return s.c.Poll(s.now, s.handshake, s.tx, s.silent)
}

// untilPastHolds опрашивает мимо удержаний до следующего другого шага; курс,
// который только и делает, что держит, валит тест.
func (s *session) untilPastHolds(t *testing.T) (Step, time.Time) {
	t.Helper()
	for i := 0; i < 20; i++ {
		if step, at := s.untilStep(t); step != StepHold {
			return step, at
		}
	}
	t.Fatal("held 20 verdicts in a row")
	return StepNone, s.now
}

// untilStep опрашивает, пока что-нибудь не случится; возвращает шаг и момент.
func (s *session) untilStep(t *testing.T) (Step, time.Time) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if step := s.poll(); step != StepNone {
			return step, s.now
		}
	}
	t.Fatal("nothing happened in 100 polls")
	return StepNone, s.now
}

// Прежде первый же вердикт гасил туннель.
func TestDeadSessionIsRebuiltTwiceBeforeTheTunnelGoesDown(t *testing.T) {
	start := time.Now()
	s := newSession(start)
	s.handshake = start.Add(5 * time.Second)

	first, firstAt := s.untilStep(t)
	if first != StepRebuild {
		t.Fatalf("first verdict %v, want a rebuild", first)
	}
	if firstAt.Sub(s.handshake) <= StaleAfter {
		t.Fatal("first verdict before the handshake went stale")
	}
	s.c.Rebuilt(firstAt)

	second, secondAt := s.untilStep(t)
	if second != StepRebuildNewCreds {
		t.Fatalf("second verdict %v, want a rebuild on new creds", second)
	}
	if secondAt.Sub(firstAt) <= RebuiltGrace {
		t.Fatal("second verdict inside the rebuilt transport's grace")
	}
	if secondAt.Sub(firstAt) > RebuiltGrace+2*PollInterval {
		t.Fatalf("second verdict %v after the rebuild, later than grace plus two polls", secondAt.Sub(firstAt))
	}
	s.c.Rebuilt(secondAt)

	third, thirdAt := s.untilStep(t)
	if third != StepTearDown {
		t.Fatalf("third verdict %v, want the tear-down", third)
	}
	if thirdAt.Sub(s.handshake) > 10*time.Minute {
		t.Fatalf("the whole course ran %v, over ten minutes", thirdAt.Sub(s.handshake))
	}
}

// Без этого устаревший handshake из-до перезапуска приговорил бы новый
// транспорт на следующем же опросе.
func TestHandshakeFromBeforeARebuildDoesNotCountAgainstTheNewTransport(t *testing.T) {
	start := time.Now()
	s := newSession(start)
	s.handshake = start.Add(5 * time.Second)
	_, at := s.untilStep(t)
	s.c.Rebuilt(at)

	for s.now.Add(PollInterval).Sub(at) <= RebuiltGrace {
		if step := s.poll(); step != StepNone {
			t.Fatalf("within the grace at +%v: %v", s.now.Sub(at), step)
		}
	}
}

func TestHandshakeAfterARebuildIsARecoveryAndTheNextFailureStartsOver(t *testing.T) {
	start := time.Now()
	s := newSession(start)
	s.handshake = start.Add(5 * time.Second)
	_, at := s.untilStep(t)
	s.c.Rebuilt(at)

	s.handshake = at.Add(3 * time.Second)
	if step := s.poll(); step != StepRecovered {
		t.Fatalf("a fresh handshake after the rebuild read as %v", step)
	}
	if s.c.Rebuilds() != 0 {
		t.Fatalf("rebuilds %d after a recovery, want 0", s.c.Rebuilds())
	}
	if step, _ := s.untilStep(t); step != StepRebuild {
		t.Fatalf("the next failure read as %v, want the first step again", step)
	}
}

// Без сети курс стоит; вернувшаяся сеть получает NeverAfter (как у Handshake —
// в отличие от Android, где после сети хватает двух опросов), а счёт
// перезапусков сохраняется: следующий шаг — на новых кредах.
func TestNoPhysicalNetworkHoldsTheCourse(t *testing.T) {
	start := time.Now()
	s := newSession(start)
	s.handshake = start.Add(5 * time.Second)
	_, at := s.untilStep(t)
	s.c.Rebuilt(at)

	for i := 0; i < 20; i++ {
		s.now = s.now.Add(PollInterval)
		s.c.Offline(s.now)
	}
	back := s.now
	for s.now.Add(PollInterval).Sub(back) < NeverAfter {
		if step := s.poll(); step != StepNone {
			t.Fatalf("%v after the network came back: %v", s.now.Sub(back), step)
		}
	}
	if step, _ := s.untilStep(t); step != StepRebuildNewCreds {
		t.Fatalf("after the grace: %v, want the second step, not a restart of the course", step)
	}
}

func TestATunnelThatNeverConnectsIsRebuiltToo(t *testing.T) {
	start := time.Now()
	s := newSession(start)
	step, at := s.untilStep(t)
	if step != StepRebuild {
		t.Fatalf("%v, want a rebuild", step)
	}
	if at.Sub(start) <= NeverAfter {
		t.Fatalf("rebuilt %v after start, before NeverAfter", at.Sub(start))
	}
}

// Сон машины проходит сквозь курс как у Handshake: grace на handshake, счёт
// перезапусков не трогается.
func TestResumePassesThroughTheCourse(t *testing.T) {
	start := time.Now()
	s := newSession(start)
	s.handshake = start.Add(5 * time.Second)
	_, at := s.untilStep(t)
	s.c.Rebuilt(at)

	s.now = s.now.Add(2 * time.Hour)
	if step := s.c.Poll(s.now, s.handshake, s.tx, false); step != StepResumed {
		t.Fatalf("a two-hour gap read as %v", step)
	}
	if s.c.Rebuilds() != 1 {
		t.Fatalf("rebuilds %d after a resume, want the one already made", s.c.Rebuilds())
	}
}

// Тёмные полосы Android 18.10: перезапуск рестартовал прокси в темноту, второй
// сбрасывал креды ради похода в VK, который не мог пройти. Вместо этого вердикт
// удерживается — и туннель всё равно гаснет примерно тогда же, когда его
// погасил бы весь курс.
func TestVerdictsWhileNoRelayAnswersAreHeldThenTheTunnelGoesDown(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	s := newSession(start)
	s.handshake = start.Add(5 * time.Second)
	s.silent = true

	first, firstAt := s.untilStep(t)
	if first != StepHold {
		t.Fatalf("первый вердикт при молчащих релеях: %v, want StepHold", first)
	}
	step, at := s.untilPastHolds(t)
	if step != StepTearDown {
		t.Fatalf("при молчащих релеях: %v, want StepTearDown", step)
	}
	if s.c.Rebuilds() != 0 {
		t.Fatalf("перезапусков при молчащих релеях: %d", s.c.Rebuilds())
	}
	if d := at.Sub(firstAt); d < SilentHold || d > SilentHold+PollInterval {
		t.Fatalf("туннель погашен через %v после удержания, want %v и не больше опроса сверх", d, SilentHold)
	}
	if d := at.Sub(s.handshake); d > 10*time.Minute {
		t.Fatalf("весь курс занял %v, больше десяти минут", d)
	}
}

// Удержание не занимает шага курса: когда релеи снова отвечают, а handshake
// так и нет, берётся тот шаг, что был следующим.
func TestTheCourseGoesOnFromWhereItWasOnceRelaysAnswer(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	s := newSession(start)
	s.handshake = start.Add(5 * time.Second)
	first, at := s.untilStep(t)
	if first != StepRebuild {
		t.Fatalf("первый шаг %v, want StepRebuild", first)
	}
	s.c.Rebuilt(at)

	s.silent = true
	if step, _ := s.untilStep(t); step != StepHold {
		t.Fatalf("новые креды при молчащих релеях: %v, want StepHold", step)
	}
	s.silent = false
	if step, _ := s.untilStep(t); step != StepRebuildNewCreds {
		t.Fatalf("после того как релеи ответили: %v, want StepRebuildNewCreds", step)
	}
}

// Handshake заканчивает удержание, и следующая тишина получает его целиком.
func TestAHandshakeEndsTheHold(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	s := newSession(start)
	s.handshake = start.Add(5 * time.Second)
	s.silent = true
	_, heldAt := s.untilStep(t)

	s.handshake = heldAt.Add(3 * time.Second)
	if step := s.poll(); step != StepNone {
		t.Fatalf("опрос после handshake: %v", step)
	}
	again, againAt := s.untilStep(t)
	if again != StepHold {
		t.Fatalf("вторая тишина: %v, want StepHold", again)
	}
	step, at := s.untilPastHolds(t)
	if step != StepTearDown || at.Sub(againAt) < SilentHold {
		t.Fatalf("вторая тишина: %v через %v, want StepTearDown не раньше %v", step, at.Sub(againAt), SilentHold)
	}
}

// WireGuard бросает initiation, простой туннель ничего не шлёт, TX не растёт —
// и ни один опрос больше не выглядит мёртвым: удержание всё равно истекает
// (Codex review of the Android port, 19.10).
func TestTheHoldRunsOutWithNothingSent(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	s := newSession(start)
	s.handshake = start.Add(5 * time.Second)
	s.silent = true
	held, heldAt := s.untilStep(t)
	if held != StepHold {
		t.Fatalf("первый вердикт: %v, want StepHold", held)
	}
	s.idle = true
	step, at := s.untilStep(t)
	if step != StepTearDown {
		t.Fatalf("без трафика: %v, want StepTearDown", step)
	}
	if d := at.Sub(heldAt); d < SilentHold || d > SilentHold+PollInterval {
		t.Fatalf("погашен через %v после удержания, want %v", d, SilentHold)
	}
}

// Пропавшая сеть заканчивает удержание; вернувшаяся получает новое целиком, а
// не остаток старого.
func TestTheNetworkLostEndsTheHold(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	s := newSession(start)
	s.handshake = start.Add(5 * time.Second)
	s.silent = true
	if step, _ := s.untilStep(t); step != StepHold {
		t.Fatalf("первый вердикт: %v, want StepHold", step)
	}
	s.offline = true
	for i := 0; i < 20; i++ {
		s.poll()
	}
	s.offline = false
	step, at := s.untilStep(t)
	if step != StepHold {
		t.Fatalf("после возврата сети: %v, want StepHold — удержание пережило пропажу сети", step)
	}
	next, nextAt := s.untilStep(t)
	if next != StepTearDown || nextAt.Sub(at) < SilentHold {
		t.Fatalf("после возврата сети: %v через %v, want StepTearDown не раньше %v", next, nextAt.Sub(at), SilentHold)
	}
}
