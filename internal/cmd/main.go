package main

import (
	"github.com/AlchemillaHQ/simple-turn/internal/config"
	"github.com/AlchemillaHQ/simple-turn/internal/db"
	"github.com/AlchemillaHQ/simple-turn/internal/http"
	"github.com/AlchemillaHQ/simple-turn/internal/turn"
	"github.com/AlchemillaHQ/simple-turn/internal/utils"
	"github.com/sirupsen/logrus"
)

func main() {
	utils.PrintAsciiArt()

	cfg, err := config.LoadConfig("config.json")
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	if err := db.InitDB(); err != nil {
		logrus.Fatalf("Failed to initialize database: %v", err)
	}

	go func() {
		if err := http.StartWebServer(cfg.WebAddr, cfg); err != nil {
			logrus.Errorf("Failed to start web server: %v", err)
		}
	}()

	if err := turn.StartTurnServer(cfg); err != nil {
		logrus.Fatalf("Failed to start TURN server: %v", err)
	}

	select {}
}
