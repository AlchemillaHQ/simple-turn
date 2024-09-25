package turn

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/AlchemillaHQ/simple-turn/internal/config"
	"github.com/pion/logging"
	"github.com/pion/stun"
	"github.com/pion/turn/v4"
	"github.com/sirupsen/logrus"
)

type STUNTURNServer struct {
	config *config.Config
}

func NewSTUNTURNServer(cfg *config.Config) *STUNTURNServer {
	cfg.Realm = "stun.difuse.io"
	return &STUNTURNServer{config: cfg}
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
	loggerFactory.DefaultLogLevel = logging.LogLevelError

	wrappedUDPListener := &stunInterceptor{PacketConn: udpListener}

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
				PacketConn:            wrappedUDPListener,
				RelayAddressGenerator: relayAddrGen,
			},
		},
		ListenerConfigs: []turn.ListenerConfig{
			{
				Listener:              tcpListener,
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

type stunInterceptor struct {
	net.PacketConn
}

func (si *stunInterceptor) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = si.PacketConn.ReadFrom(p)
	if err == nil {
		msg := &stun.Message{Raw: p[:n]}
		if err := msg.Decode(); err == nil {
			if msg.Type.Class == stun.ClassRequest && msg.Type.Method == stun.MethodBinding {
				logrus.Infof("Received STUN binding request from %s", addr.String())
			}
		}
	}
	return
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
	var listener net.Listener
	var err error
	var listenAddress string

	if g.isIPv6 {
		listenAddress = fmt.Sprintf("[%s]:%d", g.address, requestedPort)
		listener, err = net.Listen("tcp6", listenAddress)
	} else {
		listenAddress = fmt.Sprintf("%s:%d", g.address, requestedPort)
		listener, err = net.Listen("tcp4", listenAddress)
	}

	if err != nil {
		return nil, nil, err
	}

	conn, err := listener.Accept()
	if err != nil {
		listener.Close()
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
	return net.ListenPacket(network, bindAddress)
}

func createTCPListener(bindAddress string, isIPv6 bool) (net.Listener, error) {
	network := "tcp4"
	if isIPv6 {
		network = "tcp6"
	}
	return net.Listen(network, bindAddress)
}

func extractIP(bindAddress string) string {
	ip, _, _ := net.SplitHostPort(bindAddress)
	return strings.Trim(ip, "[]")
}

func (s *STUNTURNServer) handleAuth(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
	logrus.Infof("Auth attempt: username=%s, realm=%s, srcAddr=%s", username, realm, srcAddr)
	if len(username) > 0 {
		key := turn.GenerateAuthKey(username, realm, username)
		logrus.Infof("Generated auth key for user %s", username)
		return key, true
	}
	logrus.Warnf("Auth failed for username: %s", username)
	return nil, false
}

func StartTurnServer(cfg *config.Config) error {
	server := NewSTUNTURNServer(cfg)
	return server.Start()
}
