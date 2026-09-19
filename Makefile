TARGET = myra-ranges
BINDIR = ./bin/

all: build

build: $(BINDIR)
	go build -ldflags="-s -w" -o $(BINDIR)$(TARGET) .

$(BINDIR):
	mkdir -p $(BINDIR)

# cross-compile for the Pi gateway (server .111, aarch64)
linux-arm64: $(BINDIR)
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BINDIR)$(TARGET)-linux-arm64 .

test:
	go test ./...

clean:
	rm -rf $(BINDIR)

.PHONY: all build linux-arm64 test clean
