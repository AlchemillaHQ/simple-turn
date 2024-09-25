package models

import (
	"time"

	"gorm.io/gorm"
)

type Client struct {
	gorm.Model
	Type           string
	IP             string
	Username       string
	FirstConnected time.Time
	LastConnected  time.Time
	Count          int
	Active         *bool
	DataSent       int64
	DataReceived   int64
}
