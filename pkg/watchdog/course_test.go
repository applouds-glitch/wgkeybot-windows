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
}

func newSession(start time.Time) *session {
	return &session{c: NewCourse(start), now: start}
}

func (s *session) poll() Step {
	s.now = s.now.Add(PollInterval)
	s.tx += 1000
	return s.c.Poll(s.now, s.handshake, s.tx)
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
	if step := s.c.Poll(s.now, s.handshake, s.tx); step != StepResumed {
		t.Fatalf("a two-hour gap read as %v", step)
	}
	if s.c.Rebuilds() != 1 {
		t.Fatalf("rebuilds %d after a resume, want the one already made", s.c.Rebuilds())
	}
}
