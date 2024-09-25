package models

import (
	"time"

	"gorm.io/gorm"
)

type AuthKeys struct {
	gorm.Model
	Username string    `gorm:"unique" json:"username"`
	Key      string    `json:"key"`
	Expiry   time.Time `json:"expiry"`
}
