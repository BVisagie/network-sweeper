.PHONY: test build cross clean run oui

# Strip leading v from tags (v0.1.0 → 0.1.0) so the UI can prefix a single "v".
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
VERSION := $(patsubst v%,%,$(VERSION))
LDFLAGS := -X github.com/BVisagie/network-sweeper/internal/version.Version=$(VERSION)

test:
	go test ./...
	bash -n scripts/install.sh

build:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/network-sweeper ./cmd/networksweeper

run:
	go run ./cmd/networksweeper -no-browser

cross:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/network-sweeper-linux-amd64 ./cmd/networksweeper
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/network-sweeper-linux-arm64 ./cmd/networksweeper
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/network-sweeper-windows-amd64.exe ./cmd/networksweeper
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/network-sweeper-darwin-amd64 ./cmd/networksweeper
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/network-sweeper-darwin-arm64 ./cmd/networksweeper
	cd dist && sha256sum network-sweeper-* > SHA256SUMS || shasum -a 256 network-sweeper-* > SHA256SUMS

# Refresh the embedded IEEE MAC vendor registry (internal/oui/ieee.csv).
oui:
	go run ./internal/oui/gen

clean:
	rm -rf bin dist
