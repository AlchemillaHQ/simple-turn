package db

import (
	"github.com/AlchemillaHQ/simple-turn/internal/db/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() error {
	var err error
	DB, err = gorm.Open(sqlite.Open("simple-turn.db"), &gorm.Config{})
	if err != nil {
		return err
	}

	DB.Exec("PRAGMA journal_mode=WAL;")
	DB.Exec("PRAGMA synchronous=1;")
	DB.Exec("PRAGMA foreign_keys=ON;")
	DB.Exec("PRAGMA cache_size=-64000;")
	DB.Exec("PRAGMA busy_timeout=5000;")

	return DB.AutoMigrate(&models.Client{}, &models.AuthKeys{})
}
