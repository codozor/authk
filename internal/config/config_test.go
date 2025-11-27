package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Targets(t *testing.T) {
	content := `
package config

oidc: {
	issuerUrl: "https://example.com"
	clientId: "client"
	clientSecret: "secret"
}

targets: [
	{ file: ".env.1", key: "KEY1" },
	{ file: ".env.2", key: "KEY2" }
]
`
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "authk.cue")
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := Load(configFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg.Targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(cfg.Targets))
	}

	if cfg.Targets[0].File != ".env.1" || cfg.Targets[0].Key != "KEY1" {
		t.Errorf("unexpected target 0: %+v", cfg.Targets[0])
	}
	if cfg.Targets[1].File != ".env.2" || cfg.Targets[1].Key != "KEY2" {
		t.Errorf("unexpected target 1: %+v", cfg.Targets[1])
	}
}
