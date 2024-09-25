package turn

import (
	"sync"
	"time"

	"github.com/AlchemillaHQ/simple-turn/internal/db"
	"github.com/AlchemillaHQ/simple-turn/internal/db/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *STUNTURNServer) updateStunClient(ipAddress string) {
	var client models.Client
	result := db.DB.Where("ip = ?", ipAddress).First(&client)

	if result.Error == gorm.ErrRecordNotFound {
		client = models.Client{
			Type:  "STUN",
			IP:    ipAddress,
			Count: 1,
		}
		db.DB.Create(&client)
	} else {
		db.DB.Model(&client).Updates(models.Client{
			Count: client.Count + 1,
		})
	}
}

type clientStats struct {
	client       *models.Client
	dataSent     int64
	dataReceived int64
	count        int
	lastUpdate   time.Time
}

var (
	clientCache      = make(map[string]*clientStats)
	clientCacheMutex sync.RWMutex
	updateInterval   = 5 * time.Second
)

func (s *STUNTURNServer) updateTurnStats(ipAddress, username string, dataSent, dataReceived int64) {
	clientCacheMutex.Lock()
	defer clientCacheMutex.Unlock()

	stats, exists := clientCache[ipAddress]
	if !exists {
		stats = &clientStats{
			client: &models.Client{
				IP:     ipAddress,
				Type:   "TURN",
				Active: new(bool),
			},
			lastUpdate: time.Now(),
		}
		*stats.client.Active = true
		clientCache[ipAddress] = stats
	}

	stats.dataSent += dataSent
	stats.dataReceived += dataReceived
	stats.count++
	if username != "" && stats.client.Username == nil {
		stats.client.Username = &username
	}

	if time.Since(stats.lastUpdate) >= updateInterval {
		s.flushClientStats(ipAddress, stats)
	}
}

func (s *STUNTURNServer) flushClientStats(ipAddress string, stats *clientStats) {
	tx := db.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Error; err != nil {
		return
	}

	updates := map[string]interface{}{
		"type":          "TURN",
		"count":         gorm.Expr("COALESCE(count, 0) + ?", stats.count),
		"data_sent":     gorm.Expr("COALESCE(data_sent, 0) + ?", stats.dataSent),
		"data_received": gorm.Expr("COALESCE(data_received, 0) + ?", stats.dataReceived),
		"active":        true,
	}
	if stats.client.Username != nil {
		updates["username"] = stats.client.Username
	}

	// Upsert operation
	err := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "ip"}},
		DoUpdates: clause.Assignments(updates),
	}).Create(&models.Client{
		IP:           ipAddress,
		Type:         "TURN",
		Username:     stats.client.Username,
		Count:        stats.count,
		Active:       new(bool),
		DataSent:     &stats.dataSent,
		DataReceived: &stats.dataReceived,
	}).Error

	if err != nil {
		tx.Rollback()
		return
	}

	if err := tx.Commit().Error; err != nil {
		return
	}

	// Refresh the client data in the cache
	if err := db.DB.Where("ip = ?", ipAddress).First(stats.client).Error; err == nil {
		// Reset counters after successful update
		stats.dataSent = 0
		stats.dataReceived = 0
		stats.count = 0
		stats.lastUpdate = time.Now()
	}
}

func (s *STUNTURNServer) StartPeriodicFlush() {
	ticker := time.NewTicker(updateInterval)
	go func() {
		for range ticker.C {
			s.flushAllClientStats()
		}
	}()
}

func (s *STUNTURNServer) flushAllClientStats() {
	clientCacheMutex.Lock()
	defer clientCacheMutex.Unlock()

	for ipAddress, stats := range clientCache {
		if stats.count > 0 || stats.dataSent > 0 || stats.dataReceived > 0 {
			s.flushClientStats(ipAddress, stats)
		}
	}
}

func (s *STUNTURNServer) cleanupExpiredAuthKeys() {
	db.DB.Where("expiry < ?", time.Now()).Delete(&models.AuthKeys{})
}
