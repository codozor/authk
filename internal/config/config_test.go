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
	if err := os.WriteFile(configFile, []byte(content), 0o644); err != nil {
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

func TestLoad_Vals(t *testing.T) {
	// Set env var for testing
	expectedSecret := "super-secret-value"
	os.Setenv("TEST_OIDC_SECRET", expectedSecret)
	defer os.Unsetenv("TEST_OIDC_SECRET")

	content := `
package config

oidc: {
	issuerUrl: "https://example.com"
	clientId: "client"
	clientSecret: "ref+echo://super-secret-value"
}

user: {
	password: "ref+echo://super-secret-value"
}
`
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "authk_vals.cue")
	if err := os.WriteFile(configFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := Load(configFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.OIDC.ClientSecret != expectedSecret {
		t.Errorf("expected OIDC clientSecret %q, got %q", expectedSecret, cfg.OIDC.ClientSecret)
	}

	if cfg.User.Password != expectedSecret {
		t.Errorf("expected User password %q, got %q", expectedSecret, cfg.User.Password)
	}
}

func TestLoad_IDTokenKey(t *testing.T) {
	content := `
package config

oidc: {
	issuerUrl: "https://example.com"
	clientId: "client"
	clientSecret: "secret"
}

tokenKey: "MY_TOKEN"
idTokenKey: "MY_ID_TOKEN"

targets: [
	{ file: ".env.1", key: "KEY1", type: "access_token" },
	{ file: ".env.1", key: "ID1", type: "id_token" },
	{ file: ".env.2", key: "KEY2" }
]
`
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "authk_id_token.cue")
	if err := os.WriteFile(configFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := Load(configFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TokenKey != "MY_TOKEN" {
		t.Errorf("expected TokenKey 'MY_TOKEN', got %q", cfg.TokenKey)
	}
	if cfg.IDTokenKey != "MY_ID_TOKEN" {
		t.Errorf("expected IDTokenKey 'MY_ID_TOKEN', got %q", cfg.IDTokenKey)
	}

	if len(cfg.Targets) != 3 {
		t.Errorf("expected 3 targets, got %d", len(cfg.Targets))
	}

	if cfg.Targets[0].Type != "access_token" {
		t.Errorf("expected target 0 Type 'access_token', got %q", cfg.Targets[0].Type)
	}
	if cfg.Targets[1].Type != "id_token" {
		t.Errorf("expected target 1 Type 'id_token', got %q", cfg.Targets[1].Type)
	}
	if cfg.Targets[1].Key != "ID1" {
		t.Errorf("expected target 1 Key 'ID1', got %q", cfg.Targets[1].Key)
	}
	if cfg.Targets[2].Type != "access_token" {
		t.Errorf("expected target 2 Type 'access_token' (default), got %q", cfg.Targets[2].Type)
	}
}
