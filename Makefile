# seatguard — build & test
# Single static binary per target (CGO disabled).

BIN     := seatguard
PKG     := ./cmd/seatguard
DIST    := dist
LDFLAGS := -s -w
GOFLAGS := -trimpath
export CGO_ENABLED = 0

.PHONY: all build linux darwin windows test harness vet fmt clean

all: linux darwin windows

build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN) $(PKG)

linux:
	GOOS=linux   GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-linux-amd64   $(PKG)

darwin:
	GOOS=darwin  GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-darwin-arm64  $(PKG)

windows:
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-windows-amd64.exe $(PKG)

# Fast unit tests (core package).
test:
	go test ./core/...

vet:
	go vet ./...

fmt:
	gofmt -w .

# Full §6 acceptance suite (runs against the host OS backend).
harness:
	go run ./cmd/harness

clean:
	rm -rf $(DIST)
