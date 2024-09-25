package turn

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AlchemillaHQ/simple-turn/internal/config"
	"github.com/pion/logging"
	"github.com/pion/stun"
	"github.com/pion/turn/v4"
	"github.com/sirupsen/logrus"
)

type STUNTURNServer struct {
	config       *config.Config
	httpClient   *http.Client
	sessionStats map[string]*sessionInfo
	statsMutex   sync.Mutex
}

func NewSTUNTURNServer(cfg *config.Config) *STUNTURNServer {
	return &STUNTURNServer{config: cfg, httpClient: &http.Client{Timeout: 10 * time.Second}}
}

func (s *STUNTURNServer) Start() error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.startServer(s.config.IPv4Bind, false); err != nil {
			errChan <- fmt.Errorf("IPv4 server error: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.startServer(s.config.IPv6Bind, true); err != nil {
			errChan <- fmt.Errorf("IPv6 server error: %v", err)
		}
	}()

	go func() {
		wg.Wait()
		close(errChan)
	}()

	go func() {
		s.startPeriodicStatsUpdate()
		s.cleanupExpiredAuthKeys()
	}()

	for err := range errChan {
		return err
	}

	return nil
}

func (s *STUNTURNServer) startServer(bindAddress string, isIPv6 bool) error {
	udpListener, err := createUDPListener(bindAddress, isIPv6)
	if err != nil {
		return fmt.Errorf("failed to create UDP listener: %v", err)
	}

	tcpListener, err := createTCPListener(bindAddress, isIPv6)
	if err != nil {
		return fmt.Errorf("failed to create TCP listener: %v", err)
	}

	publicIP := extractIP(bindAddress)

	loggerFactory := logging.NewDefaultLoggerFactory()
	loggerFactory.DefaultLogLevel = logging.LogLevelDisabled

	relayAddrGen := &customRelayAddressGenerator{
		relayAddress: net.ParseIP(publicIP),
		address:      publicIP,
		isIPv6:       isIPv6,
	}

	_, err = turn.NewServer(turn.ServerConfig{
		Realm:       s.config.Realm,
		AuthHandler: s.handleAuth,
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn:            s.wrapUDPConn(udpListener),
				RelayAddressGenerator: relayAddrGen,
			},
		},
		ListenerConfigs: []turn.ListenerConfig{
			{
				Listener:              s.wrapTCPListener(tcpListener),
				RelayAddressGenerator: relayAddrGen,
			},
		},
		LoggerFactory: loggerFactory,
	})

	if err != nil {
		return fmt.Errorf("failed to create STUN/TURN server: %v", err)
	}

	logrus.Infof("STUN/TURN server started on %s (UDP and TCP)", bindAddress)

	return nil
}

func (s *STUNTURNServer) wrapUDPConn(conn net.PacketConn) net.PacketConn {
	return &wrappedPacketConn{PacketConn: conn, server: s}
}

func (s *STUNTURNServer) wrapTCPListener(listener net.Listener) net.Listener {
	return &wrappedListener{Listener: listener, server: s}
}

type wrappedPacketConn struct {
	net.PacketConn
	server *STUNTURNServer
}

func (w *wrappedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = w.PacketConn.ReadFrom(p)
	if err == nil {
		msg := &stun.Message{Raw: p[:n]}
		if err := msg.Decode(); err == nil {
			if msg.Type.Class == stun.ClassRequest && msg.Type.Method == stun.MethodBinding {
				host, _, _ := net.SplitHostPort(addr.String())
				w.server.updateStunClient(host)
			} else {
				// Handle TURN message
				var username stun.Username
				if username.GetFrom(msg) == nil {
					w.server.updateTurnStats(addr.String(), username.String(), 0, int64(n))
				}
			}
		}
	}
	return
}

func (w *wrappedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = w.PacketConn.WriteTo(p, addr)
	if err == nil {
		host, _, _ := net.SplitHostPort(addr.String())
		username := "" // You need to extract the username for the TURN session
		w.server.updateTurnStats(host, username, int64(n), 0)
	}
	return
}

type wrappedListener struct {
	net.Listener
	server *STUNTURNServer
}

func (w *wrappedListener) Accept() (net.Conn, error) {
	conn, err := w.Listener.Accept()
	if err == nil {
		return &wrappedConn{Conn: conn, server: w.server}, nil
	}
	return conn, err
}

// Update the wrappedConn
type wrappedConn struct {
	net.Conn
	server *STUNTURNServer
}

func (w *wrappedConn) Read(b []byte) (n int, err error) {
	n, err = w.Conn.Read(b)
	if err == nil {
		host, _, _ := net.SplitHostPort(w.Conn.RemoteAddr().String())
		username := "" // You need to extract the username for the TURN session
		w.server.updateTurnStats(host, username, 0, int64(n))
	}
	return
}

func (w *wrappedConn) Write(b []byte) (n int, err error) {
	n, err = w.Conn.Write(b)
	if err == nil {
		host, _, _ := net.SplitHostPort(w.Conn.RemoteAddr().String())
		username := "" // You need to extract the username for the TURN session
		w.server.updateTurnStats(host, username, int64(n), 0)
	}
	return
}

func (s *STUNTURNServer) startPeriodicStatsUpdate() {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			s.flushStats()
		}
	}()
}

func (s *STUNTURNServer) flushStats() {
	s.statsMutex.Lock()
	defer s.statsMutex.Unlock()

	for ip, info := range s.sessionStats {
		s.updateTurnStats(ip, info.username, info.bytesSent, info.bytesReceived)
		// Reset counters after flushing
		info.bytesSent = 0
		info.bytesReceived = 0
	}
}

type sessionInfo struct {
	username      string
	bytesReceived int64
	bytesSent     int64
}

type customRelayAddressGenerator struct {
	relayAddress net.IP
	address      string
	isIPv6       bool
}

func (g *customRelayAddressGenerator) AllocatePacketConn(network string, requestedPort int) (net.PacketConn, net.Addr, error) {
	var conn net.PacketConn
	var err error
	var listenAddress string

	if g.isIPv6 {
		listenAddress = fmt.Sprintf("[%s]:%d", g.address, requestedPort)
		conn, err = net.ListenPacket("udp6", listenAddress)
	} else {
		listenAddress = fmt.Sprintf("%s:%d", g.address, requestedPort)
		conn, err = net.ListenPacket("udp4", listenAddress)
	}

	if err != nil {
		return nil, nil, err
	}

	return conn, conn.LocalAddr(), nil
}

func (g *customRelayAddressGenerator) AllocateConn(network string, requestedPort int) (net.Conn, net.Addr, error) {
	var listenAddr string
	if g.isIPv6 {
		listenAddr = fmt.Sprintf("[%s]:%d", g.address, requestedPort)
	} else {
		listenAddr = fmt.Sprintf("%s:%d", g.address, requestedPort)
	}

	conn, err := net.Dial(network, listenAddr)
	if err != nil {
		return nil, nil, err
	}

	return conn, conn.LocalAddr(), nil
}

func (g *customRelayAddressGenerator) Validate() error {
	if g.relayAddress == nil {
		return fmt.Errorf("relay address is nil")
	}
	if g.address == "" {
		return fmt.Errorf("address is empty")
	}
	return nil
}

func createUDPListener(bindAddress string, isIPv6 bool) (net.PacketConn, error) {
	network := "udp4"
	if isIPv6 {
		network = "udp6"
	}

	if isIPv6 {
		fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
		if err != nil {
			return nil, fmt.Errorf("failed to create IPv6 UDP socket: %v", err)
		}

		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("failed to set IPV6_V6ONLY: %v", err)
		}

		file := os.NewFile(uintptr(fd), "")
		defer file.Close()
		return net.FilePacketConn(file)
	}

	return net.ListenPacket(network, bindAddress)
}

func createTCPListener(bindAddress string, isIPv6 bool) (net.Listener, error) {
	network := "tcp4"
	if isIPv6 {
		network = "tcp6"
	}

	if isIPv6 {
		fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
		if err != nil {
			return nil, fmt.Errorf("failed to create IPv6 TCP socket: %v", err)
		}

		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("failed to set IPV6_V6ONLY: %v", err)
		}

		tcpAddr, err := net.ResolveTCPAddr(network, bindAddress)
		if err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("failed to resolve TCP address: %v", err)
		}
		sockaddr := &syscall.SockaddrInet6{
			Port: tcpAddr.Port,
		}
		copy(sockaddr.Addr[:], tcpAddr.IP.To16())
		if err := syscall.Bind(fd, sockaddr); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("failed to bind IPv6 TCP socket: %v", err)
		}

		if err := syscall.Listen(fd, syscall.SOMAXCONN); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("failed to listen on IPv6 TCP socket: %v", err)
		}

		file := os.NewFile(uintptr(fd), "")
		defer file.Close()
		return net.FileListener(file)
	}

	return net.Listen(network, bindAddress)
}

func extractIP(bindAddress string) string {
	ip, _, _ := net.SplitHostPort(bindAddress)
	return strings.Trim(ip, "[]")
}

func StartTurnServer(cfg *config.Config) error {
	server := NewSTUNTURNServer(cfg)
	return server.Start()
}
