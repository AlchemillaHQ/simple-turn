package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

type Client struct {
	ID             int64     `json:"id"`
	Username       string    `json:"username"`
	Type           string    `json:"type"`
	IP             string    `json:"ip"`
	FirstConnected time.Time `json:"first_connected"`
	LastConnected  time.Time `json:"last_connected"`
	Count          int       `json:"count"`
	Active         *bool     `json:"active"`
	DataSent       int64     `json:"data_sent"`
	DataReceived   int64     `json:"data_received"`
}

var (
	db             *sql.DB
	clientActivity = make(map[string]time.Time)
	activityMutex  sync.Mutex
)

const inactivityThreshold = 1 * time.Minute

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
			username TEXT,
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

func logClient(clientType, ip string, active *bool, username string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()

	var result sql.Result
	if active == nil {
		result, err = tx.Exec(`
            UPDATE clients
            SET last_connected = ?, count = count + 1, active = NULL
			WHERE type = ? AND ip = ? AND username = ?
        `, now, clientType, ip, username)
	} else {
		result, err = tx.Exec(`
            UPDATE clients
            SET last_connected = ?, count = count + 1, active = ?
			WHERE type = ? AND ip = ? AND username = ?
        `, now, *active, clientType, ip, username)
	}
	if err != nil {
		return fmt.Errorf("failed to update client: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}

	if rowsAffected == 0 {
		if active == nil {
			_, err = tx.Exec(`
                INSERT INTO clients (type, username, ip, first_connected, last_connected, count, active, data_sent, data_received)
                VALUES (?, ?, ?, ?, ?, 1, NULL, 0, 0)
            `, clientType, username, ip, now, now)
		} else {
			_, err = tx.Exec(`
                INSERT INTO clients (type, username, ip, first_connected, last_connected, count, active, data_sent, data_received)
                VALUES (?, ?, ?, ?, ?, 1, ?, 0, 0)
            `, clientType, username, ip, now, now, *active)
		}
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

func updateClientData(clientType, ip string, dataSent, dataReceived int64, username string) error {
	logrus.Infof("Updating client data: type=%s, ip=%s, sent=%d, received=%d, username=%s", clientType, ip, dataSent, dataReceived, username)

	activityMutex.Lock()
	clientActivity[clientType+":"+ip+":"+username] = time.Now()
	activityMutex.Unlock()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	var result sql.Result
	result, err = tx.Exec(`
	UPDATE clients
	SET data_sent = data_sent + ?, data_received = data_received + ?, last_connected = CURRENT_TIMESTAMP, active = true
	WHERE type = ? AND ip = ?`, dataSent, dataReceived, clientType, ip)

	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("failed to update client data: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}

	if rowsAffected == 0 {
		_, err = tx.Exec(`
            INSERT INTO clients (type, ip, first_connected, last_connected, count, active, data_sent, data_received)
            VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, true, ?, ?)
        `, clientType, ip, username, dataSent, dataReceived)
		if err != nil {
			return fmt.Errorf("failed to insert new client data: %v", err)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	return nil
}

func setClientInactive(clientType, ip, username string) error {
	var err error
	if username == "" {
		_, err = db.Exec(`
            UPDATE clients
            SET active = false
            WHERE type = ? AND ip = ? AND username IS NULL
        `, clientType, ip)
	} else {
		_, err = db.Exec(`
            UPDATE clients
            SET active = false
            WHERE type = ? AND ip = ? AND username = ?
        `, clientType, ip, username)
	}

	if err != nil {
		return fmt.Errorf("failed to set client inactive: %v", err)
	}

	return nil
}

func checkInactiveClients() {
	for {
		time.Sleep(30 * time.Second)

		activityMutex.Lock()
		now := time.Now()
		for key, lastActivity := range clientActivity {
			if now.Sub(lastActivity) > inactivityThreshold {
				parts := strings.SplitN(key, ":", 2)
				if len(parts) == 2 {
					clientType, ip := parts[0], parts[1]
					err := setClientInactive(clientType, ip, "")
					if err != nil {
						logrus.Errorf("Failed to set client inactive: %v", err)
					} else {
						logrus.Infof("Set client inactive due to inactivity: type=%s, ip=%s", clientType, ip)
					}
					delete(clientActivity, key)
				}
			}
		}
		activityMutex.Unlock()
	}
}

func getClients(w http.ResponseWriter, r *http.Request) {
	limit := r.URL.Query().Get("limit")
	if limit == "" {
		limit = "100"
	}

	rows, err := db.Query(fmt.Sprintf(`
		SELECT id, type, ip, first_connected, last_connected, count, active, data_sent, data_received, username
		FROM clients
		ORDER BY last_connected DESC
		LIMIT %s
	`, limit))

	if err != nil {
		logrus.Errorf("Failed to query clients: %v", err)
		http.Error(w, fmt.Sprintf("Failed to query clients: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var c Client
		var activeSQL sql.NullBool
		err := rows.Scan(&c.ID, &c.Type, &c.IP, &c.FirstConnected, &c.LastConnected, &c.Count, &activeSQL, &c.DataSent, &c.DataReceived, &c.Username)
		if err != nil {
			logrus.Errorf("Failed to scan row: %v", err)
			http.Error(w, fmt.Sprintf("Failed to scan row: %v", err), http.StatusInternalServerError)
			return
		}
		if activeSQL.Valid {
			c.Active = &activeSQL.Bool
		} else {
			c.Active = nil
		}
		clients = append(clients, c)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

func basicAuthMiddleware(next http.HandlerFunc, config *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Basic ") {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		payload, _ := base64.StdEncoding.DecodeString(authHeader[6:])
		pair := strings.SplitN(string(payload), ":", 2)

		if len(pair) != 2 || subtle.ConstantTimeCompare([]byte(pair[0]), []byte(config.Username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pair[1]), []byte(config.Password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func startWebServer(addr string, config *Config) error {
	go checkInactiveClients()

	http.Handle("/clients", http.HandlerFunc(basicAuthMiddleware(getClients, config)))
	logrus.Infof("Starting web server on %s", addr)
	return http.ListenAndServe(addr, nil)
}
