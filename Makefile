MODULE  := github.com/grd-platform/grd-siem-agent
BINARY  := grd-siem-agent
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

PLATFORMS := linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64

.PHONY: build run test clean build-all checksums

## build: Build for current platform
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/grd-siem-agent

## run: Build and run with example config
run: build
	./bin/$(BINARY) run --config configs/config.example.yaml

## test: Run all tests
test:
	go test -v -race -count=1 ./...

## lint: Run linter (requires golangci-lint)
lint:
	golangci-lint run ./...

## build-all: Cross-compile for all target platforms
build-all:
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "Building $$os/$$arch..."; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -ldflags "$(LDFLAGS)" \
			-o bin/$(BINARY)-$$os-$$arch$$ext \
			./cmd/grd-siem-agent; \
	done
	@echo "Done. Binaries:"
	@ls -lh bin/

## checksums: Generate SHA256 checksums for all binaries
checksums: build-all
	cd bin && sha256sum grd-siem-agent-* > checksums.txt
	@cat bin/checksums.txt

## clean: Remove build artifacts
clean:
	rm -rf bin/ coverage.out

## validate: Validate example config
validate: build
	./bin/$(BINARY) validate --config configs/config.example.yaml

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
