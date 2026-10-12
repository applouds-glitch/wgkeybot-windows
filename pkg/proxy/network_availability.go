/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"context"
	"sync"
	"time"
)

// transportPathProofTTL keeps reconnects enabled long enough for a stream to
// reach the 90s dead threshold and still have a full reconnect window. Healthy
// streams renew the proof on every validated RX, so working networks that
// Android never marks VALIDATED remain usable indefinitely. On a real outage
// the proof expires and the gate stops further credential/Allocate churn.
const transportPathProofTTL = 3 * time.Minute

// unvalidatedProbeInterval prevents a circular wait after a real outage on a
// network that never gains Android validation. One worker may probe; success
// renews transport proof and releases all siblings, failure leaves them parked.
const unvalidatedProbeInterval = time.Minute

// networkAvailability gates only new TURN connection work. Android validation
// and observed TURN reachability are deliberately separate signals: either one
// may open the gate. Existing relay sessions never wait here.
//
// androidValidated defaults to true for hosts that do not publish Android
// connectivity state (iOS, Windows and tests).
var networkAvailability = struct {
	sync.Mutex
	androidValidated     bool
	transportProvenUntil time.Time
	transportGeneration  uint64
	nextUnvalidatedProbe time.Time
	unvalidatedProbeBusy bool
	unvalidatedProbeID   uint64
	becameAvailable      chan struct{}

	// leftAt is when the host last reported the network gone or exchanged for
	// another — what networkLeftSince measures an attempt against.
	leftAt time.Time
}{
	androidValidated: true,
	becameAvailable:  make(chan struct{}),
}

func networkAvailableLocked(now time.Time) bool {
	return networkAvailability.androidValidated || now.Before(networkAvailability.transportProvenUntil)
}

func signalNetworkWaitersLocked() {
	close(networkAvailability.becameAvailable)
	networkAvailability.becameAvailable = make(chan struct{})
}

// setNetworkAvailable updates Android's NET_CAPABILITY_VALIDATED signal. A
// false value does not erase fresh proof obtained from the TURN transport.
func setNetworkAvailable(validated bool) {
	networkAvailability.Lock()
	defer networkAvailability.Unlock()

	now := time.Now()
	wasAvailable := networkAvailableLocked(now)
	left := networkAvailability.androidValidated && !validated
	if left {
		networkAvailability.leftAt = now
	}
	networkAvailability.androidValidated = validated
	if validated {
		networkAvailability.nextUnvalidatedProbe = time.Time{}
		networkAvailability.unvalidatedProbeBusy = false
		networkAvailability.unvalidatedProbeID++
	}
	if !wasAvailable && networkAvailableLocked(now) {
		signalNetworkWaitersLocked()
	}
	if left {
		// The sockets' network is gone: the allocations they hold can no longer
		// release themselves (orphaned_allocations.go). Only on the transition —
		// the host repeats "no network" on every poll.
		networkAvailability.Unlock()
		orphanLiveAllocations(now)
		networkAvailability.Lock()
	}
}

// markNetworkPathProven records real TURN reachability for the current proxy
// generation. Callers must only invoke it after an authenticated transport
// handshake or a packet accepted by the strict RX path.
func markNetworkPathProven(generation uint64) {
	networkAvailability.Lock()
	defer networkAvailability.Unlock()

	if generation != networkAvailability.transportGeneration {
		return
	}
	now := time.Now()
	wasAvailable := networkAvailableLocked(now)
	networkAvailability.transportProvenUntil = now.Add(transportPathProofTTL)
	networkAvailability.nextUnvalidatedProbe = time.Time{}
	networkAvailability.unvalidatedProbeBusy = false
	if !wasAvailable {
		signalNetworkWaitersLocked()
	}
}

// beginNetworkPathGeneration invalidates proof and markers from every older
// proxy generation, then returns the token new streams must present.
func beginNetworkPathGeneration() uint64 {
	networkAvailability.Lock()
	defer networkAvailability.Unlock()

	networkAvailability.transportGeneration++
	networkAvailability.transportProvenUntil = time.Time{}
	networkAvailability.nextUnvalidatedProbe = time.Time{}
	networkAvailability.unvalidatedProbeBusy = false
	networkAvailability.unvalidatedProbeID++
	return networkAvailability.transportGeneration
}

// resetNetworkPathProof prevents proof from an old proxy generation from
// authorising work for the next one.
func resetNetworkPathProof() {
	beginNetworkPathGeneration()
}

// clearNetworkPathProof drops what the old physical network proved, so it cannot
// authorise work on the new one. Unlike resetNetworkPathProof it keeps the
// proxy's generation: the streams carry the token they were started with for
// the proxy's whole life, reconnects included, so a new generation here would
// turn every later proof — from streams already on the new path too — into a
// no-op until the proxy is restarted.
func clearNetworkPathProof() {
	networkAvailability.Lock()
	defer networkAvailability.Unlock()

	networkAvailability.transportProvenUntil = time.Time{}
	networkAvailability.nextUnvalidatedProbe = time.Time{}
	networkAvailability.unvalidatedProbeBusy = false
	networkAvailability.unvalidatedProbeID++
}

// noteNetworkLeft records that the network the sessions were started on has been
// exchanged for another (the host's network-change signal).
func noteNetworkLeft() {
	networkAvailability.Lock()
	networkAvailability.leftAt = time.Now()
	networkAvailability.Unlock()
}

// networkLeftSince reports whether the host says there is no network now, or
// the network in use at since has been lost or exchanged for another after it.
//
// It asks the host's signal, not the effective gate: fresh transport proof keeps
// the gate open for minutes after the host has said the network is gone, and
// what fails in those minutes is exactly what must not be held against a relay.
func networkLeftSince(since time.Time) bool {
	networkAvailability.Lock()
	defer networkAvailability.Unlock()
	return !networkAvailability.androidValidated || networkAvailability.leftAt.After(since)
}

func isNetworkAvailable() bool {
	networkAvailability.Lock()
	defer networkAvailability.Unlock()
	return networkAvailableLocked(time.Now())
}

func networkAvailabilitySnapshot() (androidValidated, transportProven, effective bool, proofRemaining time.Duration) {
	networkAvailability.Lock()
	defer networkAvailability.Unlock()

	androidValidated = networkAvailability.androidValidated
	proofRemaining = networkAvailability.transportProvenUntil.Sub(time.Now())
	if proofRemaining < 0 {
		proofRemaining = 0
	}
	transportProven = proofRemaining > 0
	effective = androidValidated || transportProven
	return
}

type networkPermit struct {
	unvalidatedProbe bool
	probeID          uint64
}

func waitForNetworkPermit(ctx context.Context, allowUnvalidatedProbe bool) (networkPermit, bool) {
	for {
		networkAvailability.Lock()
		now := time.Now()
		if networkAvailableLocked(now) {
			networkAvailability.Unlock()
			return networkPermit{}, true
		}

		var probeAt time.Time
		if allowUnvalidatedProbe {
			if !networkAvailability.unvalidatedProbeBusy {
				probeAt = networkAvailability.nextUnvalidatedProbe
			}
			if !networkAvailability.unvalidatedProbeBusy && (probeAt.IsZero() || !now.Before(probeAt)) {
				networkAvailability.nextUnvalidatedProbe = now.Add(unvalidatedProbeInterval)
				networkAvailability.unvalidatedProbeBusy = true
				networkAvailability.unvalidatedProbeID++
				probeID := networkAvailability.unvalidatedProbeID
				networkAvailability.Unlock()
				return networkPermit{unvalidatedProbe: true, probeID: probeID}, true
			}
		}
		becameAvailable := networkAvailability.becameAvailable
		networkAvailability.Unlock()

		if probeAt.IsZero() {
			select {
			case <-becameAvailable:
			case <-ctx.Done():
				return networkPermit{}, false
			}
			continue
		}

		timer := time.NewTimer(time.Until(probeAt))
		select {
		case <-becameAvailable:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return networkPermit{}, false
		}
	}
}

func releaseNetworkPermit(permit networkPermit) {
	if !permit.unvalidatedProbe {
		return
	}
	networkAvailability.Lock()
	if !networkAvailability.unvalidatedProbeBusy || permit.probeID != networkAvailability.unvalidatedProbeID {
		networkAvailability.Unlock()
		return
	}
	networkAvailability.unvalidatedProbeBusy = false
	// Wake parked workers so exactly one can either claim an overdue probe or
	// install a timer for the remaining rate-limit interval.
	signalNetworkWaitersLocked()
	networkAvailability.Unlock()
}

func waitForNetworkAvailable(ctx context.Context) bool {
	_, ok := waitForNetworkPermit(ctx, false)
	return ok
}
