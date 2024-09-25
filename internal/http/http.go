package http

import (
	"encoding/json"
	"net/http"

	"github.com/AlchemillaHQ/simple-turn/internal/config"
	"github.com/AlchemillaHQ/simple-turn/internal/db"
	"github.com/AlchemillaHQ/simple-turn/internal/db/models"
	"github.com/sirupsen/logrus"
)

func getClients(w http.ResponseWriter, r *http.Request) {
	var clients []models.Client
	result := db.DB.Order("last_connected desc").Limit(100).Find(&clients)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

func StartWebServer(addr string, cfg *config.Config) error {
	http.HandleFunc("/clients", basicAuthMiddleware(getClients, cfg))
	logrus.Infof("Starting web server on %s", addr)
	return http.ListenAndServe(addr, nil)
}
