package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/common-nighthawk/go-figure"
)

const Version = "0.0.1"

type Config struct {
	Realm        string `json:"realm"`
	IPv4Bind     string `json:"ipv4_bind"`
	IPv6Bind     string `json:"ipv6_bind"`
	LogLevel     string `json:"log_level"`
	AuthEndpoint string `json:"auth_endpoint"`
	WebAddr      string `json:"web_addr"`
	Username     string `json:"username"`
	Password     string `json:"password"`
}

func LoadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func AsciiArt() {
	figure.NewFigure("SimpleTurn", "doom", true).Print()
	fmt.Println("\t\t\t\t\t\tVersion: ", Version)
}
