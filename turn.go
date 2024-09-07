package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pion/turn/v4"
	"github.com/sirupsen/logrus"
)

var httpClient = &http.Client{Timeout: 5 * time.Second}

func StartServer(config *Config) error {
	udpListenerIPv4, err := net.ListenPacket("udp4", config.IPv4Bind)
	if err != nil {
		return fmt.Errorf("failed to create UDP listener for IPv4: %v", err)
	}
	defer udpListenerIPv4.Close()

	udpListenerIPv6, err := net.ListenPacket("udp6", config.IPv6Bind)
	if err != nil {
		return fmt.Errorf("failed to create UDP listener for IPv6: %v", err)
	}
	defer udpListenerIPv6.Close()

	realm := config.Realm

	_, err = turn.NewServer(turn.ServerConfig{
		Realm: realm,
		AuthHandler: func(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
			resp, err := httpClient.Get(fmt.Sprintf("%s/%s", config.AuthEndpoint, username))
			if err != nil {
				logrus.Errorf("Failed to contact auth server: %v", err)
				return nil, false
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				logrus.Infof("Authentication failed for token %s", username)
				return nil, false
			} else {
				logrus.Debugf("Authentication succeeded for token %s", username)
			}

			return turn.GenerateAuthKey(username, realm, username), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListenerIPv4,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP(strings.Split(config.IPv4Bind, ":")[0]),
					Address:      "0.0.0.0",
				},
			},
			{
				PacketConn: udpListenerIPv6,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP(strings.Split(config.IPv6Bind, "]")[0][1:]),
					Address:      "::",
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create STUN/TURN server: %v", err)
	}

	logrus.Infof("STUN/TURN server is running on %s (IPv4) and %s (IPv6)", config.IPv4Bind, config.IPv6Bind)

	select {}
}
