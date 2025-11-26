package config

import (
	_ "embed"
	"fmt"
	"os"

	"cuelang.org/go/cue/cuecontext"
)

//go:embed schema.cue
var schemaContent []byte

type Config struct {
	OIDC     OIDCConfig `json:"oidc"`
	User     UserConfig `json:"user"`
	TokenKey string     `json:"tokenKey"`
}

type OIDCConfig struct {
	IssuerURL    string   `json:"issuerUrl"`
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	Scopes       []string `json:"scopes"`
	AuthMethod   string   `json:"authMethod"`
}

type UserConfig struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func Load(path string) (*Config, error) {
	ctx := cuecontext.New()

	// Load schema
	schema := ctx.CompileBytes(schemaContent)
	if schema.Err() != nil {
		return nil, fmt.Errorf("failed to compile schema: %w", schema.Err())
	}

	// Read config file
	configBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Compile config
	val := ctx.CompileBytes(configBytes)
	if val.Err() != nil {
		return nil, fmt.Errorf("failed to compile config file: %w", val.Err())
	}

	// Unify with schema
	unified := schema.Unify(val)
	if err := unified.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Decode into struct
	var cfg Config
	if err := unified.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	return &cfg, nil
}
