TARGET = myra-ranges
BINDIR = ./bin/
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS = -s -w -X main.version=$(VERSION)

all: build

build: $(BINDIR)
	go build -ldflags="$(LDFLAGS)" -o $(BINDIR)$(TARGET) .

$(BINDIR):
	mkdir -p $(BINDIR)

# cross-compile, e.g. for a Raspberry Pi
linux-arm64: $(BINDIR)
	GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BINDIR)$(TARGET)-linux-arm64 .

test:
	go test ./...

clean:
	rm -rf $(BINDIR)

.PHONY: all build linux-arm64 test clean
