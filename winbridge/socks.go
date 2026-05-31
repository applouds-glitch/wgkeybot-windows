package winbridge

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// SOCKS5 константы (RFC 1928).
const (
	socksVersion5 = 0x05

	socksAuthNone        = 0x00
	socksAuthNoAccept    = 0xFF
	socksCmdConnect      = 0x01
	socksCmdUDPAssociate = 0x03
	socksAddrIPv4        = 0x01
	socksAddrDomain      = 0x03
	socksAddrIPv6        = 0x04
	socksReplySuccess    = 0x00
	socksReplyGenFail    = 0x01
	socksReplyCmdNoSup   = 0x07
)

// udpSessionTimeout — простой UDP-сессии (outbound conn) до её закрытия.
const udpSessionTimeout = 60 * time.Second

// DialFunc дайлит соединение через туннель (netstack *Net.DialContext).
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// SocksServer — минимальный SOCKS5-сервер (только метод no-auth и команда
// CONNECT). DNS резолвится удалённо: домен передаётся прямо в dial, поэтому
// клиенты должны использовать socks5h (remote DNS).
type SocksServer struct {
	listener net.Listener
	dial     DialFunc

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closed  bool
	closeWG sync.WaitGroup
}

// NewSocksServer открывает listener на addr (например "127.0.0.1:1080").
// dial проксирует исходящие соединения через туннель.
func NewSocksServer(addr string, dial DialFunc) (*SocksServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("socks listen %s: %w", addr, err)
	}
	return &SocksServer{
		listener: ln,
		dial:     dial,
		conns:    make(map[net.Conn]struct{}),
	}, nil
}

// Addr возвращает фактический адрес, на котором слушает сервер.
func (s *SocksServer) Addr() string { return s.listener.Addr().String() }

// Serve принимает соединения до вызова Close. Блокирует.
func (s *SocksServer) Serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			log.Printf("[SOCKS] accept error: %v", err)
			return
		}
		s.track(conn)
		s.closeWG.Add(1)
		go func() {
			defer s.closeWG.Done()
			defer s.untrack(conn)
			s.handle(conn)
		}()
	}
}

// Close останавливает приём и закрывает все активные соединения.
func (s *SocksServer) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.listener.Close()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.closeWG.Wait()
}

func (s *SocksServer) track(c net.Conn) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
}

func (s *SocksServer) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *SocksServer) handle(client net.Conn) {
	defer client.Close()

	client.SetReadDeadline(time.Now().Add(30 * time.Second))
	if err := socksHandshake(client); err != nil {
		log.Printf("[SOCKS] handshake: %v", err)
		return
	}

	cmd, target, err := socksReadRequest(client)
	if err != nil {
		log.Printf("[SOCKS] request: %v", err)
		socksReply(client, socksReplyGenFail)
		return
	}
	// Снимаем дедлайн на чтение запроса — дальше потоковая передача.
	client.SetReadDeadline(time.Time{})

	switch cmd {
	case socksCmdConnect:
		s.handleConnect(client, target)
	case socksCmdUDPAssociate:
		s.handleUDPAssociate(client)
	default:
		socksReply(client, socksReplyCmdNoSup)
	}
}

// handleConnect обслуживает TCP CONNECT: дайлит target через туннель и
// двунаправленно проксирует поток.
func (s *SocksServer) handleConnect(client net.Conn, target string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	remote, err := s.dial(ctx, "tcp", target)
	cancel()
	if err != nil {
		log.Printf("[SOCKS] dial %s: %v", target, err)
		socksReply(client, socksReplyGenFail)
		return
	}
	defer remote.Close()

	if err := socksReply(client, socksReplySuccess); err != nil {
		return
	}
	relay(client, remote)
}

// socksHandshake обрабатывает метод аутентификации: принимаем только no-auth.
func socksHandshake(c net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil {
		return err
	}
	if header[0] != socksVersion5 {
		return fmt.Errorf("unsupported version 0x%02x", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == socksAuthNone {
			_, err := c.Write([]byte{socksVersion5, socksAuthNone})
			return err
		}
	}
	c.Write([]byte{socksVersion5, socksAuthNoAccept})
	return fmt.Errorf("no acceptable auth method")
}

// socksReadRequest читает запрос (VER, CMD, RSV, ATYP, ADDR, PORT) и возвращает
// команду и target "host:port". Домен НЕ резолвится локально — передаётся как
// есть (remote DNS).
func socksReadRequest(c net.Conn) (cmd byte, target string, err error) {
	header := make([]byte, 4)
	if _, err = io.ReadFull(c, header); err != nil {
		return 0, "", err
	}
	if header[0] != socksVersion5 {
		return 0, "", fmt.Errorf("unsupported version 0x%02x", header[0])
	}
	cmd = header[1]

	host, err := readSocksAddr(c, header[3])
	if err != nil {
		return 0, "", err
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(c, portBuf); err != nil {
		return 0, "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return cmd, net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// readSocksAddr читает адрес из соединения по заданному ATYP.
func readSocksAddr(c net.Conn, atyp byte) (string, error) {
	switch atyp {
	case socksAddrIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socksAddrIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socksAddrDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(c, lenByte); err != nil {
			return "", err
		}
		buf := make([]byte, int(lenByte[0]))
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf("unsupported address type 0x%02x", atyp)
	}
}

// socksReply отправляет ответ с заданным кодом и BND.ADDR = 0.0.0.0:0.
func socksReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{socksVersion5, code, 0x00, socksAddrIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// socksReplyAddr отправляет ответ с конкретным BND.ADDR/BND.PORT
// (нужно для UDP ASSOCIATE — клиент шлёт датаграммы на этот адрес).
func socksReplyAddr(c net.Conn, code byte, ip net.IP, port int) error {
	reply := []byte{socksVersion5, code, 0x00}
	if ip4 := ip.To4(); ip4 != nil {
		reply = append(reply, socksAddrIPv4)
		reply = append(reply, ip4...)
	} else {
		reply = append(reply, socksAddrIPv6)
		reply = append(reply, ip.To16()...)
	}
	reply = append(reply, byte(port>>8), byte(port))
	_, err := c.Write(reply)
	return err
}

// ── UDP ASSOCIATE ───────────────────────────────────────────────────────────

// handleUDPAssociate открывает локальный UDP-relay на loopback, сообщает клиенту
// его адрес и проксирует датаграммы через туннель, пока живо управляющее
// TCP-соединение. Поддерживается только клиент с того же loopback.
func (s *SocksServer) handleUDPAssociate(client net.Conn) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		log.Printf("[SOCKS] udp listen: %v", err)
		socksReply(client, socksReplyGenFail)
		return
	}
	defer relay.Close()

	local := relay.LocalAddr().(*net.UDPAddr)
	if err := socksReplyAddr(client, socksReplySuccess, local.IP, local.Port); err != nil {
		return
	}

	assoc := &udpAssoc{
		server:   s,
		relay:    relay,
		sessions: make(map[string]*udpSession),
	}
	defer assoc.close()
	go assoc.relayLoop()

	// Ассоциация живёт, пока открыто управляющее TCP-соединение (RFC 1928).
	io.Copy(io.Discard, client)
}

// udpSession — исходящее UDP-соединение через туннель к одному target.
type udpSession struct {
	conn   net.Conn
	target string
}

// udpAssoc — UDP-ассоциация: один loopback-relay + набор сессий по target.
type udpAssoc struct {
	server *SocksServer
	relay  *net.UDPConn

	mu         sync.Mutex
	clientAddr *net.UDPAddr
	sessions   map[string]*udpSession
	closed     bool
}

func (a *udpAssoc) close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	for _, s := range a.sessions {
		s.conn.Close()
	}
	a.sessions = nil
	a.mu.Unlock()
	a.relay.Close()
}

// relayLoop читает датаграммы от клиента, парсит SOCKS-UDP-заголовок и шлёт
// payload наружу через туннель.
func (a *udpAssoc) relayLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, src, err := a.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}

		a.mu.Lock()
		if a.clientAddr == nil {
			a.clientAddr = src
		}
		clientAddr := a.clientAddr
		a.mu.Unlock()
		// Принимаем датаграммы только от клиента ассоциации.
		if clientAddr == nil || src.Port != clientAddr.Port || !src.IP.Equal(clientAddr.IP) {
			continue
		}

		target, payload, ok := parseUDPHeader(buf[:n])
		if !ok {
			continue // фрагментация или битый заголовок
		}
		if sess := a.session(target); sess != nil {
			sess.conn.Write(payload)
		}
	}
}

// session возвращает (создавая при необходимости) исходящее UDP-соединение к target.
func (a *udpAssoc) session(target string) *udpSession {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	if s, ok := a.sessions[target]; ok {
		a.mu.Unlock()
		return s
	}
	a.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := a.server.dial(ctx, "udp", target)
	cancel()
	if err != nil {
		log.Printf("[SOCKS] udp dial %s: %v", target, err)
		return nil
	}

	sess := &udpSession{conn: conn, target: target}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		conn.Close()
		return nil
	}
	if existing, ok := a.sessions[target]; ok {
		a.mu.Unlock()
		conn.Close()
		return existing
	}
	a.sessions[target] = sess
	a.mu.Unlock()

	go a.readBack(sess)
	return sess
}

// readBack читает ответы из туннеля и шлёт их клиенту, оборачивая в SOCKS-UDP-заголовок.
func (a *udpAssoc) readBack(sess *udpSession) {
	defer a.removeSession(sess)

	// Адрес источника для заголовка — реальный resolved IP:port из туннеля.
	host, portStr, err := net.SplitHostPort(sess.conn.RemoteAddr().String())
	if err != nil {
		host, portStr, _ = net.SplitHostPort(sess.target)
	}
	port, _ := strconv.Atoi(portStr)

	buf := make([]byte, 64*1024)
	for {
		sess.conn.SetReadDeadline(time.Now().Add(udpSessionTimeout))
		n, err := sess.conn.Read(buf)
		if err != nil {
			return
		}

		a.mu.Lock()
		clientAddr := a.clientAddr
		a.mu.Unlock()
		if clientAddr == nil {
			continue
		}
		a.relay.WriteToUDP(buildUDPHeader(host, port, buf[:n]), clientAddr)
	}
}

func (a *udpAssoc) removeSession(sess *udpSession) {
	a.mu.Lock()
	if a.sessions[sess.target] == sess {
		delete(a.sessions, sess.target)
	}
	a.mu.Unlock()
	sess.conn.Close()
}

// parseUDPHeader разбирает SOCKS-UDP-датаграмму: RSV(2), FRAG(1), ATYP(1),
// ADDR, PORT(2), DATA. FRAG != 0 (фрагментация) не поддерживается.
func parseUDPHeader(b []byte) (target string, data []byte, ok bool) {
	if len(b) < 4 || b[2] != 0 {
		return "", nil, false
	}
	atyp := b[3]
	rest := b[4:]

	var host string
	switch atyp {
	case socksAddrIPv4:
		if len(rest) < 4 {
			return "", nil, false
		}
		host = net.IP(rest[:4]).String()
		rest = rest[4:]
	case socksAddrIPv6:
		if len(rest) < 16 {
			return "", nil, false
		}
		host = net.IP(rest[:16]).String()
		rest = rest[16:]
	case socksAddrDomain:
		if len(rest) < 1 {
			return "", nil, false
		}
		l := int(rest[0])
		rest = rest[1:]
		if len(rest) < l {
			return "", nil, false
		}
		host = string(rest[:l])
		rest = rest[l:]
	default:
		return "", nil, false
	}

	if len(rest) < 2 {
		return "", nil, false
	}
	port := binary.BigEndian.Uint16(rest[:2])
	data = rest[2:]
	return net.JoinHostPort(host, strconv.Itoa(int(port))), data, true
}

// buildUDPHeader оборачивает payload в SOCKS-UDP-заголовок с указанным источником.
func buildUDPHeader(host string, port int, data []byte) []byte {
	ip := net.ParseIP(host)
	var out []byte
	out = append(out, 0x00, 0x00, 0x00) // RSV(2) + FRAG(0)
	switch {
	case ip == nil:
		out = append(out, socksAddrDomain, byte(len(host)))
		out = append(out, host...)
	case ip.To4() != nil:
		out = append(out, socksAddrIPv4)
		out = append(out, ip.To4()...)
	default:
		out = append(out, socksAddrIPv6)
		out = append(out, ip.To16()...)
	}
	out = append(out, byte(port>>8), byte(port))
	return append(out, data...)
}

// relay двунаправленно копирует данные между двумя соединениями до закрытия любого.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		// Будим вторую горутину, закрывая обе стороны.
		dst.Close()
		src.Close()
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
