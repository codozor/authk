package main

import (
	"errors"
	"testing"

	"github.com/codozor/authk/internal/config"
)

// A Kubernetes profile is accepted by the config, but cannot get tokens yet: every
// command needing a session fails with a clear error, before any network access.
func TestNewSession_KubernetesNotImplemented(t *testing.T) {
	p := &config.Profile{Name: "sa", Provider: config.ProviderKubernetes, ServiceAccount: "client"}
	if _, err := newSession(p); !errors.Is(err, errProviderNotImplemented) {
		t.Errorf("newSession() error = %v, want errProviderNotImplemented", err)
	}
}

func TestKubernetesColumns(t *testing.T) {
	tests := []struct {
		profile              config.Profile
		wantClient, wantFrom string
	}{
		{config.Profile{ServiceAccount: "client"}, "client", "current context"},
		{config.Profile{ServiceAccount: "client", Namespace: "ns", Context: "kind-dev"}, "ns/client", "context kind-dev"},
	}
	for _, tt := range tests {
		flow, client, from := kubernetesColumns(&tt.profile)
		if flow != "kubernetes" || client != tt.wantClient || from != tt.wantFrom {
			t.Errorf("kubernetesColumns(%+v) = %q, %q, %q", tt.profile, flow, client, from)
		}
	}
}
