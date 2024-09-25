package turn

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/AlchemillaHQ/simple-turn/internal/db"
	"github.com/AlchemillaHQ/simple-turn/internal/db/models"
	"github.com/pion/turn/v4"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func (s *STUNTURNServer) handleAuth(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
	logrus.Debugf("TURN Auth request: username=%s, realm=%s, srcAddr=%s", username, realm, srcAddr.String())

	var authKey models.AuthKeys
	result := db.DB.Where("username = ?", username).First(&authKey)

	if result.Error == nil && time.Now().Before(authKey.Expiry) {
		return []byte(authKey.Key), true
	}

	resp, err := s.httpClient.Get(fmt.Sprintf("%s/%s", s.config.AuthEndpoint, username))
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false
	}

	key := turn.GenerateAuthKey(username, realm, username)
	logrus.Debugf("Generated new auth key for user %s", username)

	expiry := time.Now().Add(30 * time.Minute)
	newAuthKey := models.AuthKeys{
		Username: username,
		Key:      string(key),
		Expiry:   expiry,
	}

	if result.Error == gorm.ErrRecordNotFound {
		db.DB.Create(&newAuthKey)
	} else {
		db.DB.Model(&authKey).Updates(newAuthKey)
	}

	host, _, _ := net.SplitHostPort(srcAddr.String())
	s.updateTurnClientRecord(username, host)

	return key, true
}

func (s *STUNTURNServer) updateTurnClientRecord(username, ip string) {
	var client models.Client
	result := db.DB.Where("ip = ?", ip).First(&client)
	active := true

	if result.Error == gorm.ErrRecordNotFound {
		client = models.Client{
			Type:     "TURN",
			IP:       ip,
			Username: &username,
			Count:    1,
			Active:   &active,
		}
		db.DB.Create(&client)
	} else {
		db.DB.Model(&client).Updates(models.Client{
			Username: &username,
			Count:    client.Count + 1,
			Active:   &active,
		})
	}
}
