/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */
package proxy

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

// choosyPeer echoes the relay proof to the allocations answers lets through:
// the nth allocation it has heard from, and when it first heard it.
func choosyPeer(t *testing.T, answers func(nth int, firstSeen time.Time) bool) *net.UDPAddr {
	t.Helper()
	pc := listenFakeRelay(t)
	var mu sync.Mutex
	order := map[string]int{}
	first := map[string]time.Time{}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			key := from.String()
			if _, seen := order[key]; !seen {
				order[key] = len(order)
				first[key] = time.Now()
			}
			nth, since := order[key], first[key]
			mu.Unlock()
			if isStunKeepalive(buf[:n]) && answers(nth, since) {
				pc.WriteTo(buf[:n], from)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func TestRelayHeardByOthers(t *testing.T) {
	now := time.Now()
	witness := dispatchStream(1, true, now, 8)
	failing := dispatchStream(2, false, now, 8)
	const relay, other = "relay-a:19302", "relay-b:19302"
	defer trackLiveSession(relay, failing)()

	if relayHeardByOthers(relay, failing, now) {
		t.Fatal("a relay with nobody else on it had an alibi")
	}
	done := trackLiveSession(relay, witness)
	if !relayHeardByOthers(relay, failing, now) {
		t.Fatal("a ready stream that has just heard the relay is no alibi")
	}
	if relayHeardByOthers(relay, witness, now) {
		t.Fatal("a stream vouched for its own relay")
	}
	if relayHeardByOthers(other, failing, now) {
		t.Fatal("a stream on one relay vouched for another")
	}
	if relayHeardByOthers(relay, failing, now.Add(dispatchStaleAfter+time.Second)) {
		t.Fatal("a stream silent for longer than dispatchStaleAfter still vouched")
	}
	witness.ready.Store(false)
	if relayHeardByOthers(relay, failing, now) {
		t.Fatal("a stream that is not ready vouched")
	}
	witness.ready.Store(true)
	witness.activity.Store(nil)
	if relayHeardByOthers(relay, failing, now) {
		t.Fatal("a stream that has received nothing yet vouched")
	}
	witness.activity.Store(newStreamActivity(now, 0))
	done()
	if relayHeardByOthers(relay, failing, now) {
		t.Fatal("a session that ended still vouched")
	}
}

// The Rostelecom bench of relay_heard_by_others.go (Android 22.10): one
// allocation that never proves itself while another stream on the same
// relay hears it is that flow's failure — the relay stays in the rotation and
// takes no strike, and the stream dials it again.
func TestDeafUDPFlowIsNotHeldAgainstARelayOthersHear(t *testing.T) {
	first, _ := twoRelaySockets(t)
	relay := startTestRelay(t, first, 0)
	peer := choosyPeer(t, func(nth int, _ time.Time) bool { return nth == 0 })

	h := runWorkersAgainstPeer(t, 135, 2, []string{relay.addr}, peer)
	waitFor(t, "one stream up and the other's flow given up and dialed again", 10*time.Second, func() bool {
		return h.ready() == 1 && relay.seen.count() >= 3
	})
	if serverDemoted(relay.addr) {
		t.Fatal("the relay went out of rotation with a stream hearing it")
	}
	if n := relayStrikes(relay.addr); n != 0 {
		t.Fatalf("the relay took %d strike(s) with a stream hearing it", n)
	}
}

// A handshake cut short by the machine's own network is excused before the alibi
// is weighed (stream_run_with_creds.go), so it is no flow failure either: two
// of them must not send the relay to the end of the stream's list (Codex
// review of the iOS port, 22.10).
func TestHandshakeFailedWithTheNetworkLeftIsNoFlowFailure(t *testing.T) {
	// First, so that its cleanup runs last — after the goroutine below has
	// stopped moving leftAt.
	resetNetworkAvailabilityForTest()
	t.Cleanup(resetNetworkAvailabilityForTest)
	first, _ := twoRelaySockets(t)
	relay := startTestRelay(t, first, 0)
	peer := choosyPeer(t, func(nth int, _ time.Time) bool { return nth == 0 })
	// A worker goes into its wait after the attempt has been judged: its
	// second wait is two handshakes judged.
	var mu sync.Mutex
	waits := map[int]int{}
	prev := workerWaits
	workerWaits = func(w workerWait) {
		mu.Lock()
		waits[w.stream]++
		mu.Unlock()
	}
	t.Cleanup(func() { workerWaits = prev })
	// Every attempt has the network left under it (networkLeftSince), from
	// before the first: the deaf stream's handshakes are the network's.
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			noteNetworkLeft()
			select {
			case <-tick.C:
			case <-stop:
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})

	h := runWorkersAgainstPeer(t, 138, 2, []string{relay.addr}, peer)
	waitFor(t, "one stream up and the other's handshake judged twice", 12*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, n := range waits {
			if n >= 2 {
				return h.ready() == 1
			}
		}
		return false
	})
	for _, s := range h.streams {
		if run := s.flowFails.Load(); run != nil {
			t.Fatalf("stream %d counted %d flow failure(s) on %s with the network left under it", s.id, run.n, run.relay)
		}
	}
}

// With nobody on the relay to vouch for it the verdict stands over UDP: a relay
// that allocates and carries nothing is out after its first handshake — by the
// time its worker goes into the wait before its second attempt.
func TestDeafUDPRelayNobodyHearsIsStillDemoted(t *testing.T) {
	first, _ := twoRelaySockets(t)
	relay := startTestRelay(t, first, 0)
	peer := choosyPeer(t, func(int, time.Time) bool { return false })
	var waited, demotedThen atomic.Bool
	prev := workerWaits
	workerWaits = func(workerWait) {
		if !waited.Swap(true) {
			demotedThen.Store(serverDemoted(relay.addr))
		}
	}
	t.Cleanup(func() { workerWaits = prev })

	runWorkersAgainstPeer(t, 136, 1, []string{relay.addr}, peer)
	waitFor(t, "the worker's wait after its first attempt", 5*time.Second, waited.Load)
	if !demotedThen.Load() {
		t.Fatal("the relay was still in rotation after its first failed handshake")
	}
}

// The same relay with the machine waking from a sleep — the reporter's clock
// overdue — is not held to account: the handshake's deadline ran on through
// the sleep, and the relay never got those seconds (Codex review of the
// Windows port, 2026-10-23).
func TestAHandshakeAcrossASleepDemotesNothing(t *testing.T) {
	withReporterClock(t, &reporterClock{turn: time.Now().Add(-time.Hour)})
	first, _ := twoRelaySockets(t)
	relay := startTestRelay(t, first, 0)
	peer := choosyPeer(t, func(int, time.Time) bool { return false })
	var waited, demotedThen atomic.Bool
	prev := workerWaits
	workerWaits = func(workerWait) {
		if !waited.Swap(true) {
			demotedThen.Store(serverDemoted(relay.addr))
		}
	}
	t.Cleanup(func() { workerWaits = prev })

	runWorkersAgainstPeer(t, 139, 1, []string{relay.addr}, peer)
	waitFor(t, "the worker's wait after its first attempt", 5*time.Second, waited.Load)
	if demotedThen.Load() {
		t.Fatal("a handshake that timed out across a sleep demoted the relay")
	}
}

// taggedRelayGenerator records the relay that owns each allocated UDP port.
// Binding a second relay to 127.0.0.2 is not portable across CI hosts.
type taggedRelayGenerator struct {
	*turn.RelayAddressGeneratorStatic
	label string
	ports *sync.Map
}

func (g *taggedRelayGenerator) AllocatePacketConn(conf turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	conn, addr, err := g.RelayAddressGeneratorStatic.AllocatePacketConn(conf)
	if err == nil {
		g.ports.Store(addr.(*net.UDPAddr).Port, g.label)
	}
	return conn, addr, err
}

func startTestRelayOn(t *testing.T, pc net.PacketConn, label string, ports *sync.Map) *testRelay {
	t.Helper()
	seen := &sourceCounter{PacketConn: pc, seen: map[string]bool{}}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "head-start-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "head-start-test", "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: seen,
			RelayAddressGenerator: &taggedRelayGenerator{
				RelayAddressGeneratorStatic: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1",
				},
				label: label, ports: ports,
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return &testRelay{addr: pc.LocalAddr().String(), server: server, seen: seen}
}

// relayPickyPeer echoes the relay proof for selected allocations. The port
// registry identifies their relay even when both bind the same loopback IP.
func relayPickyPeer(t *testing.T, ports *sync.Map, answers func(relay string, nthOfRelay int) bool) *net.UDPAddr {
	t.Helper()
	pc := listenFakeRelay(t)
	order := map[string]int{}
	perRelay := map[string]int{}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			u := from.(*net.UDPAddr)
			value, ok := ports.Load(u.Port)
			if !ok {
				continue
			}
			relay := value.(string)
			key := u.String()
			if _, seen := order[key]; !seen {
				order[key] = perRelay[relay]
				perRelay[relay]++
			}
			if isStunKeepalive(buf[:n]) && answers(relay, order[key]) {
				pc.WriteTo(buf[:n], from)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

// A relay that carries its old session and fails every new one, with a healthy
// relay beside it: the stream whose head it is fails there twice under the
// alibi — no verdict against the relay — and then dials it last, and gets
// through on the other one (codex review 2026-10-22: without this it kept
// dialing the failing relay for as long as the old session lived).
func TestAStreamLeavesARelayItKeepsFailingOnWhileOthersHearIt(t *testing.T) {
	first, second := twoRelaySockets(t)
	var ports sync.Map
	failing := startTestRelayOn(t, first, "failing", &ports)
	healthy := startTestRelayOn(t, second, "healthy", &ports)
	peer := relayPickyPeer(t, &ports, func(relay string, nth int) bool {
		return relay == "healthy" || nth == 0
	})

	// Streams 0 and 2 have the failing relay at their head, stream 1 the
	// healthy one: the first of 0 and 2 there takes the one allocation it
	// carries and vouches for it.
	h := runWorkersAgainstPeer(t, 137, 3, []string{failing.addr, healthy.addr}, peer)
	waitFor(t, "all three streams up", 15*time.Second, func() bool { return h.ready() == 3 })
	if failing.seen.count() < 3 {
		t.Fatalf("the failing relay saw %d allocation(s): want stream 2 to have tried it twice", failing.seen.count())
	}
	if serverDemoted(failing.addr) || relayStrikes(failing.addr) != 0 {
		t.Fatal("the relay was held to account with a stream hearing it")
	}
	// Which of streams 0 and 2 took the one allocation the relay carries is a
	// race; whichever failed, its run ended with its own session.
	for _, s := range h.streams {
		if a := s.avoidedRelay(); a != "" {
			t.Fatalf("stream %d still dials %s last: the run of flow failures outlived its own session", s.id, a)
		}
	}
}
