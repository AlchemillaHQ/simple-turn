package db

import (
	"time"

	"github.com/AlchemillaHQ/simple-turn/internal/db/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() error {
	var err error
	DB, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		return err
	}

	return DB.AutoMigrate(&models.Client{})
}

func LogClient(clientType, ip string, active *bool, username string) error {
	client := models.Client{
		Type:     clientType,
		IP:       ip,
		Username: username,
		Active:   active,
	}

	result := DB.Where(models.Client{Type: clientType, IP: ip, Username: username}).
		Attrs(models.Client{FirstConnected: time.Now()}).
		Assign(models.Client{
			LastConnected: time.Now(),
			Active:        active,
		}).FirstOrCreate(&client).Update("count", gorm.Expr("count + 1"))

	return result.Error
}
