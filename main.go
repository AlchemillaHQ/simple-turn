package main

import (
	"flag"
	"log"
	"os"

	"github.com/sirupsen/logrus"
)

func main() {
	AsciiArt()

	configFile := flag.String("config", "config.json", "Path to configuration file")
	realm := flag.String("realm", "example.stunserver.com", "Realm for the TURN/STUN server")
	ipv4Bind := flag.String("ipv4", "0.0.0.0:3478", "IPv4 address and port to bind to")
	ipv6Bind := flag.String("ipv6", "[::]:3478", "IPv6 address and port to bind to")
	logLevel := flag.String("loglevel", "info", "Log level (debug, info, warn, error)")
	authEndpoint := flag.String("auth-endpoint", "", "URL to the authentication endpoint")
	webAddr := flag.String("web-addr", ":8080", "Address for the web server")

	version := flag.Bool("version", false, "Print version and exit")
	flag.BoolVar(version, "v", false, "Print version and exit (shorthand)")

	flag.Parse()

	if *version {
		logrus.Printf("simple-turn version v%s", Version)
		os.Exit(0)
	}

	config, err := LoadConfig(*configFile)
	if err != nil {
		log.Printf("Failed to load configuration file: %v", err)
		log.Println("Continuing with default and CLI-provided values")
		config = &Config{}
	}

	if *realm != "example.stunserver.com" {
		config.Realm = *realm
	}

	if *ipv4Bind != "0.0.0.0:3478" {
		config.IPv4Bind = *ipv4Bind
	}

	if *ipv6Bind != "[::]:3478" {
		config.IPv6Bind = *ipv6Bind
	}

	if *authEndpoint != "" {
		config.AuthEndpoint = *authEndpoint
	}

	if *logLevel != "info" {
		config.LogLevel = *logLevel
	}

	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}

	logrus.SetLevel(level)
	logrus.Infof("Configuration: %+v", config)

	err = initDB()
	if err != nil {
		logrus.Errorf("Failed to initialize database: %v", err)
		os.Exit(1)
	}

	go func() {
		err := startWebServer(*webAddr)
		if err != nil {
			logrus.Errorf("Failed to start web server: %v", err)
		}
	}()

	err = StartServer(config)
	if err != nil {
		logrus.Errorf("Failed to start STUN server: %v", err)
		os.Exit(1)
	}

	select {}
}
