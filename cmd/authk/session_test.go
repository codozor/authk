package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codozor/authk/internal/config"
)

// A Kubernetes profile gets its tokens from the Kubernetes client, with no login and
// nothing stored. Building the session needs no network.
func TestNewSession_Kubernetes(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "config")
	content := "apiVersion: v1\nkind: Config\ncurrent-context: dev\n" +
		"clusters: [{name: c, cluster: {server: \"https://127.0.0.1:6443\"}}]\n" +
		"users: [{name: u, user: {token: t}}]\n" +
		"contexts: [{name: dev, context: {cluster: c, user: u, namespace: team-a}}]\n"
	if err := os.WriteFile(kubeconfig, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &config.Profile{Name: "sa", Provider: config.ProviderKubernetes, Kubeconfig: kubeconfig, ServiceAccount: "client"}
	s, err := newSession(p)
	if err != nil {
		t.Fatalf("newSession() error = %v", err)
	}
	if s.kube == nil || s.Client != nil || s.keeper != nil || s.Interactive() {
		t.Errorf("unexpected session %+v", s)
	}
	if s.kube.ServiceAccount() != "team-a/client" {
		t.Errorf("service account = %s", s.kube.ServiceAccount())
	}

	// A broken kubeconfig fails with the profile name
	p.Kubeconfig = filepath.Join(t.TempDir(), "nope")
	if _, err := newSession(p); err == nil || !strings.Contains(err.Error(), "profile sa") {
		t.Errorf("newSession() with a missing kubeconfig: %v", err)
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
