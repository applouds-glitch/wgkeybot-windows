//go:build windows

/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package proxy

import (
	"errors"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// setTCPUserTimeout puts relayTCPUserTimeout on the connection as Windows has
// it: the limit on retransmission, TCP_MAXRTMS in milliseconds (Windows 10
// 1709 and later), TCP_MAXRT in whole seconds where that one is refused.
func setTCPUserTimeout(c *net.TCPConn, d time.Duration) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		optErr = windows.SetsockoptInt(h, windows.IPPROTO_TCP, windows.TCP_MAXRTMS, int(d/time.Millisecond))
		if optErr != nil {
			optErr = windows.SetsockoptInt(h, windows.IPPROTO_TCP, windows.TCP_MAXRT, int((d+time.Second-1)/time.Second))
		}
	}); err != nil {
		return err
	}
	return optErr
}

// errMaxSegmentNotSettable: Winsock's TCP_MAXSEG is read-only.
var errMaxSegmentNotSettable = errors.New("Windows sets no MSS per socket")

// setTCPMaxSegment has nothing to set on Windows (see relayTCPMaxSegment).
func setTCPMaxSegment(syscall.RawConn, int) error { return errMaxSegmentNotSettable }

// sioTCPInfo is SIO_TCP_INFO, _WSAIORW(IOC_VENDOR, 39): the connection's
// TCP_INFO, Windows 10 1703 and later (version 1 from 1809).
const sioTCPInfo = 0xD8000027

// tcpInfoV1 is TCP_INFO_v1 (mstcpip.h) as Windows lays it out, on amd64 and
// 386 alike; its first 88 bytes are TCP_INFO_v0.
type tcpInfoV1 struct {
	State             uint32
	Mss               uint32
	ConnectionTimeMs  uint64
	TimestampsEnabled uint8
	RttUs             uint32
	MinRttUs          uint32
	BytesInFlight     uint32
	Cwnd              uint32
	SndWnd            uint32
	RcvWnd            uint32
	RcvBuf            uint32
	BytesOut          uint64
	BytesIn           uint64
	BytesReordered    uint32
	BytesRetrans      uint32
	FastRetrans       uint32
	DupAcksIn         uint32
	TimeoutEpisodes   uint32
	SynRetrans        uint8
	SndLimTransRwin   uint32
	SndLimTimeRwin    uint32
	SndLimBytesRwin   uint64
	SndLimTransCwnd   uint32
	SndLimTimeCwnd    uint32
	SndLimBytesCwnd   uint64
	SndLimTransSnd    uint32
	SndLimTimeSnd     uint32
	SndLimBytesSnd    uint64
}

const tcpInfoV0Size = 88

// The layout is Windows', not Go's to choose: a field out of place fails the
// build here rather than reading the wrong counters.
var _ [136]byte = [unsafe.Sizeof(tcpInfoV1{})]byte{}

// readRelaySocket reads the system's view of one relay connection: one
// SIO_TCP_INFO on a socket we opened, version 1 where it is there and version
// 0 before 1809.
//
// What Windows counts is not what Linux counts, and the sample says so where it
// matters. The timeouts are the connection's since it opened (episodic: the
// watcher derives the run, timeoutsInARow). Retransmissions are bytes, not
// segments. What the relay acknowledged is not kept: it is what went out, less
// what went out again and what is in flight — taken whichever way Winsock
// counts retransmitted bytes in BytesOut, a retransmission never makes it look
// like more acknowledged. Not kept at all: the time since the relay's last data
// or ACK, the MSS in, the path MTU, what waits unsent behind the window, and
// the time limited by our send buffer. The time with data to send is version
// 1's: limited by the relay's window or by the congestion window. Its third
// state, sender-limited, is the application giving the socket nothing to
// send — idle time, not a wait (mstcpip.h; Codex review of the Windows port,
// 2026-10-23).
func readRelaySocket(c *net.TCPConn) (relaySocketSample, bool) {
	raw, err := c.SyscallConn()
	if err != nil {
		return relaySocketSample{}, false
	}
	var info tcpInfoV1
	v1 := false
	var ioErr error
	if err := raw.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		var n uint32
		ver := uint32(1)
		ioErr = windows.WSAIoctl(h, sioTCPInfo, (*byte)(unsafe.Pointer(&ver)), 4,
			(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), &n, nil, 0)
		if ioErr == nil {
			v1 = true
			return
		}
		ver = 0
		ioErr = windows.WSAIoctl(h, sioTCPInfo, (*byte)(unsafe.Pointer(&ver)), 4,
			(*byte)(unsafe.Pointer(&info)), tcpInfoV0Size, &n, nil, 0)
	}); err != nil || ioErr != nil {
		return relaySocketSample{}, false
	}

	unique := info.BytesOut - min(info.BytesOut, uint64(info.BytesRetrans))
	s := relaySocketSample{
		acked:           unique - min(unique, uint64(info.BytesInFlight)),
		received:        info.BytesIn,
		retransBytes:    uint64(info.BytesRetrans),
		backlog:         int(info.BytesInFlight),
		timeoutEpisodes: uint64(info.TimeoutEpisodes),
		episodic:        true,
		rtt:             time.Duration(info.RttUs) * time.Microsecond,
		sndMSS:          int(info.Mss),
	}
	s.noSendBuffer = true
	if v1 {
		ms := func(v uint32) time.Duration { return time.Duration(v) * time.Millisecond }
		s.waitedOnPeerWindow = ms(info.SndLimTimeRwin)
		s.busy = ms(info.SndLimTimeRwin) + ms(info.SndLimTimeCwnd)
	}
	return s, true
}
