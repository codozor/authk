BINARY_NAME=authk
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE := $(shell date -I)

LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: all build clean install

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/authk

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/authk

clean:
	go clean
	rm -f $(BINARY_NAME)
