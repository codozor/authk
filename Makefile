BINARY_NAME=authk
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE := $(shell date -I)

LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: all build clean install integration integration-k8s keycloak-up keycloak-down k3s-up k3s-down

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

# Keycloak tests, and Kubernetes tests when k3s-up was run
integration:
	AUTHK_KEYCLOAK_URL=http://localhost:$(KEYCLOAK_PORT) AUTHK_KUBECONFIG=$(wildcard $(K3S_KUBECONFIG)) go test -tags integration -count=1 -v ./test/integration/

# Kubernetes integration tests against the API server of a k3s (no kubelet: rootless
# containers cannot run one, and TokenRequest only needs the API server)
K3S_IMAGE := docker.io/rancher/k3s:v1.31.4-k3s1
K3S_PORT ?= 16443
K3S_KUBECONFIG ?= $(CURDIR)/test/integration/.kubeconfig

k3s-up:
	$(CONTAINER) run -d --name authk-k3s --privileged -p $(K3S_PORT):6443 $(K3S_IMAGE) \
		server --disable-agent --disable=traefik,metrics-server,servicelb,local-storage,coredns
	timeout 180 sh -c 'until $(CONTAINER) exec authk-k3s kubectl get --raw /readyz >/dev/null 2>&1; do sleep 2; done'
	$(CONTAINER) exec authk-k3s cat /etc/rancher/k3s/k3s.yaml | sed 's#127.0.0.1:6443#127.0.0.1:$(K3S_PORT)#' > $(K3S_KUBECONFIG)

k3s-down:
	$(CONTAINER) rm -f authk-k3s
	rm -f $(K3S_KUBECONFIG)

integration-k8s:
	AUTHK_KUBECONFIG=$(K3S_KUBECONFIG) go test -tags integration -count=1 -v -run Kubernetes ./test/integration/
