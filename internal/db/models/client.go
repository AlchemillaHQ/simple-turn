package models

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

type Client struct {
	gorm.Model
	Type         string  `json:"type"`
	IP           string  `gorm:"unique" json:"ip"`
	Username     *string `json:"username,omitempty"`
	Count        int     `gorm:"default:0" json:"count"`
	Active       *bool   `json:"active,omitempty"`
	DataSent     *int64  `json:"dataSent,omitempty"`
	DataReceived *int64  `json:"dataReceived,omitempty"`
}

func (c Client) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID        uint      `json:"id"`
		CreatedAt time.Time `json:"createdAt"`
		UpdatedAt time.Time `json:"updatedAt"`
		Type      string    `json:"type"`
		IP        string    `json:"ip"`
		Username  *string   `json:"username,omitempty"`
		Count     int       `json:"count"`
		Active    *bool     `json:"active,omitempty"`
		DataSent  *int64    `json:"dataSent,omitempty"`
		DataRcvd  *int64    `json:"dataReceived,omitempty"`
	}{
		ID:        c.ID,
		CreatedAt: c.CreatedAt.UTC(),
		UpdatedAt: c.UpdatedAt.UTC(),
		Type:      c.Type,
		IP:        c.IP,
		Username:  c.Username,
		Count:     c.Count,
		Active:    c.Active,
		DataSent:  c.DataSent,
		DataRcvd:  c.DataReceived,
	})
}

func (c *Client) BeforeSave(tx *gorm.DB) (err error) {
	now := time.Now().UTC()
	if c.ID == 0 {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	return
}
