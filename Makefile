BINARY_NAME=authk
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE := $(shell date -I)

LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: all build clean install integration keycloak-up keycloak-down

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/authk

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/authk

clean:
	go clean
	rm -f $(BINARY_NAME)

# Integration tests against a real Keycloak (see test/integration)
CONTAINER ?= $(shell command -v docker >/dev/null 2>&1 && echo docker || echo podman)
KEYCLOAK_IMAGE := quay.io/keycloak/keycloak:26.4
KEYCLOAK_PORT ?= 18080

keycloak-up:
	$(CONTAINER) run -d --name authk-keycloak -p $(KEYCLOAK_PORT):8080 \
		-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
		-v $(CURDIR)/test/integration/realm.json:/opt/keycloak/data/import/realm.json:ro,Z \
		$(KEYCLOAK_IMAGE) start-dev --import-realm
	timeout 180 sh -c 'until curl -sf http://localhost:$(KEYCLOAK_PORT)/realms/authk-test/.well-known/openid-configuration >/dev/null; do sleep 2; done'

keycloak-down:
	$(CONTAINER) rm -f authk-keycloak

integration:
	AUTHK_KEYCLOAK_URL=http://localhost:$(KEYCLOAK_PORT) go test -tags integration -count=1 -v ./test/integration/
