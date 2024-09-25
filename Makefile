# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=simple-turn
VERSION=1.0.0
MAIN_PATH=./internal/cmd/main.go

all: test build

build:
	$(GOBUILD) -o $(BINARY_NAME) -v -ldflags "-X main.Version=$(VERSION)" $(MAIN_PATH)

test:
	$(GOTEST) -v ./...

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME) $(BINARY_NAME)_linux $(BINARY_NAME).exe $(BINARY_NAME)_mac

run: build
	./$(BINARY_NAME)

deps:
	go mod download

# Cross compilation
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)_linux -v -ldflags "-X main.Version=$(VERSION)" $(MAIN_PATH)

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME).exe -v -ldflags "-X main.Version=$(VERSION)" $(MAIN_PATH)

build-mac:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)_mac -v -ldflags "-X main.Version=$(VERSION)" $(MAIN_PATH)

.PHONY: all build test clean run deps build-linux build-windows build-mac
