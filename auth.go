package main

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pion/turn/v4"
	"github.com/sirupsen/logrus"
)

type authCacheEntry struct {
	key     []byte
	expires time.Time
}

var (
	authCache      = make(map[string]authCacheEntry)
	authCacheMutex sync.RWMutex
	cacheDuration  = 5 * time.Minute
)

func getCachedAuthKey(username string) ([]byte, bool) {
	authCacheMutex.RLock()
	defer authCacheMutex.RUnlock()

	entry, exists := authCache[username]
	if !exists || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.key, true
}

func setCachedAuthKey(username string, key []byte) {
	authCacheMutex.Lock()
	defer authCacheMutex.Unlock()

	authCache[username] = authCacheEntry{
		key:     key,
		expires: time.Now().Add(cacheDuration),
	}
}

func createAuthHandler(config *Config) turn.AuthHandler {
	return func(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
		logrus.Debugf("TURN Auth request: username=%s, realm=%s, srcAddr=%s", username, realm, srcAddr.String())

		// Check cache first
		if key, ok := getCachedAuthKey(username); ok {
			logrus.Debugf("Using cached auth key for user: %s", username)
			return key, true
		}

		// If not in cache, check with auth endpoint
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

		// Generate auth key and cache it
		key := turn.GenerateAuthKey(username, realm, username)
		setCachedAuthKey(username, key)

		ip, _, _ := net.SplitHostPort(srcAddr.String())
		active := true
		err = logClient("turn", ip, &active, username)
		if err != nil {
			logrus.Debugf("Failed to log TURN client connection: %v", err)
		} else {
			logrus.Debugf("Logged TURN client connection: username=%s, ip=%s", username, ip)
		}

		updateClientActivity(ip, username)

		return key, true
	}
}
