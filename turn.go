package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"github.com/pion/turn/v4"
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
	return nil, nil, fmt.Errorf("AllocateConn not implemented")
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

func StartServer(config *Config) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// Start IPv4 server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := startTURNServer(config, false); err != nil {
			errChan <- fmt.Errorf("IPv4 server error: %v", err)
		}
	}()

	// Start IPv6 server
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
	var err error

	if isIPv6 {
		bindAddress = config.IPv6Bind
		publicIP, _, err = net.SplitHostPort(bindAddress)
		publicIP = strings.Trim(publicIP, "[]")
		udpListener, err = net.ListenPacket("udp6", bindAddress)
	} else {
		bindAddress = config.IPv4Bind
		publicIP, _, err = net.SplitHostPort(bindAddress)
		udpListener, err = net.ListenPacket("udp4", bindAddress)
	}

	if err != nil {
		return fmt.Errorf("failed to create UDP listener: %v", err)
	}

	relayIP := net.ParseIP(publicIP)
	if relayIP == nil {
		return fmt.Errorf("failed to parse IP address: %s", publicIP)
	}

	s, err := turn.NewServer(turn.ServerConfig{
		Realm: config.Realm,
		AuthHandler: func(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
			resp, err := httpClient.Get(fmt.Sprintf("%s/%s", config.AuthEndpoint, username))
			if err != nil {
				return nil, false
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return nil, false
			}
			return turn.GenerateAuthKey(username, realm, username), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
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

	defer s.Close()
	select {}
}
