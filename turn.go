package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun"
	"github.com/pion/turn/v4"
	"github.com/sirupsen/logrus"
)

var (
	httpClient    = &http.Client{Timeout: 5 * time.Second}
	clientsMutex  sync.Mutex
	activeClients = make(map[string]*time.Timer)
)

const clientTimeout = 5 * time.Minute

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
		return nil, nil, fmt.Errorf("failed to create TCP listener: %v", err)
	}

	connChan := make(chan net.Conn, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			logrus.Errorf("Failed to accept TCP connection: %v", err)
			close(connChan)
			return
		}
		connChan <- conn
		close(connChan)
	}()

	select {
	case conn := <-connChan:
		if conn == nil {
			return nil, nil, fmt.Errorf("failed to establish TCP connection")
		}
		return conn, conn.LocalAddr(), nil
	case <-time.After(5 * time.Second):
		listener.Close()
		return nil, nil, fmt.Errorf("timeout waiting for TCP connection")
	}
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

type monitoringPacketConn struct {
	net.PacketConn
	clientIP string
}

func (m *monitoringPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = m.PacketConn.ReadFrom(p)
	if err == nil {
		updateClientData("turn", m.clientIP, 0, int64(n))
		updateClientActivity(m.clientIP)
	}
	return
}

func (m *monitoringPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = m.PacketConn.WriteTo(p, addr)
	if err == nil {
		updateClientData("turn", m.clientIP, int64(n), 0)
		updateClientActivity(m.clientIP)
	}
	return
}

type monitoringConn struct {
	net.Conn
	clientIP string
}

func (m *monitoringConn) Read(b []byte) (n int, err error) {
	n, err = m.Conn.Read(b)
	if err == nil {
		updateClientData("turn", m.clientIP, 0, int64(n))
		updateClientActivity(m.clientIP)
	}
	return
}

func (m *monitoringConn) Write(b []byte) (n int, err error) {
	n, err = m.Conn.Write(b)
	if err == nil {
		updateClientData("turn", m.clientIP, int64(n), 0)
		updateClientActivity(m.clientIP)
	}
	return
}

func updateClientActivity(clientIP string) {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	if timer, exists := activeClients[clientIP]; exists {
		timer.Reset(clientTimeout)
	} else {
		activeClients[clientIP] = time.AfterFunc(clientTimeout, func() {
			setClientInactive("turn", clientIP)
			clientsMutex.Lock()
			delete(activeClients, clientIP)
			clientsMutex.Unlock()
		})
	}
}

func wrapPacketConn(conn net.PacketConn, clientIP string) net.PacketConn {
	return &monitoringPacketConn{PacketConn: conn, clientIP: clientIP}
}

func wrapConn(conn net.Conn, clientIP string) net.Conn {
	return &monitoringConn{Conn: conn, clientIP: clientIP}
}

type customRelayListener struct {
	turn.RelayAddressGenerator
	clientIP string
}

func (g *customRelayListener) AllocatePacketConn(network string, requestedPort int) (net.PacketConn, net.Addr, error) {
	conn, addr, err := g.RelayAddressGenerator.AllocatePacketConn(network, requestedPort)
	if err != nil {
		return nil, nil, err
	}
	return wrapPacketConn(conn, g.clientIP), addr, nil
}

func (g *customRelayListener) AllocateConn(network string, requestedPort int) (net.Conn, net.Addr, error) {
	conn, addr, err := g.RelayAddressGenerator.AllocateConn(network, requestedPort)
	if err != nil {
		return nil, nil, err
	}
	return wrapConn(conn, g.clientIP), addr, nil
}

type stunTurnPacketConn struct {
	net.PacketConn
}

func (s *stunTurnPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	if err == nil && n >= 20 {
		msg := &stun.Message{
			Raw: p[:n],
		}
		if msg.Decode() == nil && msg.Type == stun.BindingRequest {
			ip, _, _ := net.SplitHostPort(addr.String())
			err := logClient("stun", ip, nil)
			if err != nil {
				logrus.Debugf("Failed to log STUN client connection: %v", err)
			} else {
				logrus.Debugf("Logged STUN client connection: ip=%s", ip)
			}
		}
	}
	return
}

func (s *stunTurnPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = s.PacketConn.WriteTo(p, addr)
	if err == nil {
		ip, _, _ := net.SplitHostPort(addr.String())
		updateClientData("stun", ip, int64(n), 0)
	}
	return
}

func wrapStunTurnPacketConn(conn net.PacketConn) net.PacketConn {
	return &stunTurnPacketConn{PacketConn: conn}
}

func StartServer(config *Config) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := startTURNServer(config, false); err != nil {
			errChan <- fmt.Errorf("IPv4 server error: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := startTURNServer(config, true); err != nil {
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

	select {}
}

func startTURNServer(config *Config, isIPv6 bool) error {
	var bindAddress, publicIP string
	var udpListener net.PacketConn
	var tcpListener net.Listener
	var err error

	if isIPv6 {
		bindAddress = config.IPv6Bind
		publicIP, _, err = net.SplitHostPort(bindAddress)
		if err != nil {
			return fmt.Errorf("failed to parse IPv6 bind address: %v", err)
		}
		publicIP = strings.Trim(publicIP, "[]")
		udpListener, err = net.ListenPacket("udp6", bindAddress)
		if err != nil {
			return fmt.Errorf("failed to create UDP6 listener: %v", err)
		}
		tcpListener, err = net.Listen("tcp6", bindAddress)
		if err != nil {
			return fmt.Errorf("failed to create TCP6 listener: %v", err)
		}
	} else {
		bindAddress = config.IPv4Bind
		publicIP, _, err = net.SplitHostPort(bindAddress)
		if err != nil {
			return fmt.Errorf("failed to parse IPv4 bind address: %v", err)
		}
		udpListener, err = net.ListenPacket("udp4", bindAddress)
		if err != nil {
			return fmt.Errorf("failed to create UDP4 listener: %v", err)
		}
		tcpListener, err = net.Listen("tcp4", bindAddress)
		if err != nil {
			return fmt.Errorf("failed to create TCP4 listener: %v", err)
		}
	}

	relayIP := net.ParseIP(publicIP)
	if relayIP == nil {
		return fmt.Errorf("failed to parse IP address: %s", publicIP)
	}

	wrappedUDPListener := wrapStunTurnPacketConn(udpListener)

	s, err := turn.NewServer(turn.ServerConfig{
		Realm: config.Realm,
		AuthHandler: func(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
			logrus.Debugf("TURN Auth request: username=%s, realm=%s, srcAddr=%s", username, realm, srcAddr.String())

			resp, err := httpClient.Get(fmt.Sprintf("%s/%s", config.AuthEndpoint, username))
			if err != nil {
				logrus.Debugf("TURN Auth request failed: %v", err)
				return nil, false
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				logrus.Debugf("TURN Auth request denied: status=%d", resp.StatusCode)
				return nil, false
			}

			ip, _, _ := net.SplitHostPort(srcAddr.String())
			active := true
			err = logClient("turn", ip, &active)
			if err != nil {
				logrus.Debugf("Failed to log TURN client connection: %v", err)
			} else {
				logrus.Debugf("Logged TURN client connection: username=%s, ip=%s", username, ip)
			}

			updateClientActivity(ip)

			return turn.GenerateAuthKey(username, realm, username), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: wrappedUDPListener,
				RelayAddressGenerator: &customRelayListener{
					RelayAddressGenerator: &customRelayAddressGenerator{
						relayAddress: relayIP,
						address:      publicIP,
						isIPv6:       isIPv6,
					},
				},
			},
		},
		ListenerConfigs: []turn.ListenerConfig{
			{
				Listener: tcpListener,
				RelayAddressGenerator: &customRelayListener{
					RelayAddressGenerator: &customRelayAddressGenerator{
						relayAddress: relayIP,
						address:      publicIP,
						isIPv6:       isIPv6,
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to create TURN server: %v", err)
	}

	logrus.Infof("TURN server started on %s (UDP and TCP)", bindAddress)
	defer s.Close()
	select {}
}
