package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

type Client struct {
	ID             int64     `json:"id"`
	Type           string    `json:"type"`
	IP             string    `json:"ip"`
	FirstConnected time.Time `json:"first_connected"`
	LastConnected  time.Time `json:"last_connected"`
	Count          int       `json:"count"`
	Active         bool      `json:"active"`
	DataSent       int64     `json:"data_sent"`
	DataReceived   int64     `json:"data_received"`
}

var (
	db            *sql.DB
	activeClients sync.Map
)

func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", "./clients.db")
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            ip TEXT,
            first_connected DATETIME,
            last_connected DATETIME,
            count INTEGER,
            active BOOLEAN,
            data_sent INTEGER,
            data_received INTEGER,
            UNIQUE(type, ip)
        )
    `)
	if err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	return nil
}

func logClient(clientType, ip string, active bool) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	now := time.Now()

	// Try to update existing record
	result, err := tx.Exec(`
        UPDATE clients
        SET last_connected = ?, count = count + 1, active = ?
        WHERE type = ? AND ip = ?
    `, now, active, clientType, ip)
	if err != nil {
		return fmt.Errorf("failed to update client: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}

	if rowsAffected == 0 {
		// If no existing record, insert new one
		_, err = tx.Exec(`
            INSERT INTO clients (type, ip, first_connected, last_connected, count, active, data_sent, data_received)
            VALUES (?, ?, ?, ?, 1, ?, 0, 0)
        `, clientType, ip, now, now, active)
		if err != nil {
			return fmt.Errorf("failed to insert client: %v", err)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	return nil
}

func updateClientData(clientType, ip string, dataSent, dataReceived int64) error {
	_, err := db.Exec(`
        UPDATE clients
        SET data_sent = data_sent + ?, data_received = data_received + ?, last_connected = CURRENT_TIMESTAMP
        WHERE type = ? AND ip = ?
    `, dataSent, dataReceived, clientType, ip)

	if err != nil {
		return fmt.Errorf("failed to update client data: %v", err)
	}

	return nil
}

func getClients(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
        SELECT id, type, ip, first_connected, last_connected, count, active, data_sent, data_received
        FROM clients
        ORDER BY last_connected DESC
        LIMIT 100
    `)
	if err != nil {
		logrus.Errorf("Failed to query clients: %v", err)
		http.Error(w, fmt.Sprintf("Failed to query clients: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var c Client
		err := rows.Scan(&c.ID, &c.Type, &c.IP, &c.FirstConnected, &c.LastConnected, &c.Count, &c.Active, &c.DataSent, &c.DataReceived)
		if err != nil {
			logrus.Errorf("Failed to scan row: %v", err)
			http.Error(w, fmt.Sprintf("Failed to scan row: %v", err), http.StatusInternalServerError)
			return
		}
		clients = append(clients, c)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

func startWebServer(addr string) error {
	http.HandleFunc("/clients", getClients)
	logrus.Infof("Starting web server on %s", addr)
	return http.ListenAndServe(addr, nil)
}
