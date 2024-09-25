package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pion/turn/v4"
	"github.com/sirupsen/logrus"
)

var httpClient = &http.Client{Timeout: 5 * time.Second}

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

	// Create a channel to receive the connection
	connChan := make(chan net.Conn, 1)

	// Start a goroutine to accept the connection
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

	// Wait for the connection or timeout
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

func wrapPacketConn(conn net.PacketConn) net.PacketConn {
	return &loggingPacketConn{PacketConn: conn}
}

type loggingPacketConn struct {
	net.PacketConn
}

func (l *loggingPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = l.PacketConn.ReadFrom(p)
	if err == nil && n >= 20 {
		if p[0]&0xC0 == 0 {
			ip, _, _ := net.SplitHostPort(addr.String())
			err := logClient("stun", ip)
			if err != nil {
				logrus.Debugf("Failed to log STUN client: %v", err)
			} else {
				logrus.Debugf("Logged STUN client: ip=%s", ip)
			}
		}
	}
	return
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

	s, err := turn.NewServer(turn.ServerConfig{
		Realm: config.Realm,
		AuthHandler: func(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
			logrus.Infof("TURN Auth request: username=%s, realm=%s, srcAddr=%s", username, realm, srcAddr.String())

			resp, err := httpClient.Get(fmt.Sprintf("%s/%s", config.AuthEndpoint, username))
			if err != nil {
				logrus.Errorf("TURN Auth request failed: %v", err)
				return nil, false
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				logrus.Warnf("TURN Auth request denied: status=%d", resp.StatusCode)
				return nil, false
			}

			ip, _, _ := net.SplitHostPort(srcAddr.String())
			err = logClient("turn", ip)
			if err != nil {
				logrus.Errorf("Failed to log TURN client connection: %v", err)
			} else {
				logrus.Infof("Logged TURN client connection: username=%s, ip=%s", username, ip)
			}

			return turn.GenerateAuthKey(username, realm, username), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: wrapPacketConn(udpListener),
				RelayAddressGenerator: &customRelayAddressGenerator{
					relayAddress: relayIP,
					address:      publicIP,
					isIPv6:       isIPv6,
				},
			},
		},
		ListenerConfigs: []turn.ListenerConfig{
			{
				Listener: tcpListener,
				RelayAddressGenerator: &customRelayAddressGenerator{
					relayAddress: relayIP,
					address:      publicIP,
					isIPv6:       isIPv6,
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
