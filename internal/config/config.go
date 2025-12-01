package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"cuelang.org/go/cue/cuecontext"
	"github.com/helmfile/vals"
	_ "github.com/helmfile/vals/pkg/providers/file"
	_ "github.com/helmfile/vals/pkg/providers/k8s"
	_ "github.com/helmfile/vals/pkg/providers/sops"
)

//go:embed schema.cue
var schemaContent []byte

type Config struct {
	OIDC     OIDCConfig `json:"oidc"`
	User     UserConfig `json:"user"`
	TokenKey string     `json:"tokenKey"`
	Targets  []Target   `json:"targets,omitempty"`
}

type Target struct {
	File string `json:"file"`
	Key  string `json:"key"`
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

	// Decode into map for processing
	var configMap map[string]interface{}
	if err := unified.Decode(&configMap); err != nil {
		return nil, fmt.Errorf("failed to decode config to map: %w", err)
	}

	// Manual expansion of ref+env:// since vals env provider is problematic
	if err := processEnvRefs(configMap); err != nil {
		return nil, fmt.Errorf("failed to process env refs: %w", err)
	}

	// Process with vals
	runtime, err := vals.New(vals.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize vals runtime: %w", err)
	}
	processedMap, err := runtime.Eval(configMap)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate secrets with vals: %w", err)
	}

	// Decode into struct via JSON to ensure type safety
	configJSON, err := json.Marshal(processedMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal processed config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	return &cfg, nil
}

func processEnvRefs(v interface{}) error {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if str, ok := val.(string); ok {
				if strings.HasPrefix(str, "ref+env://") {
					varName := strings.TrimPrefix(str, "ref+env://")
					t[k] = os.Getenv(varName)
				}
			} else {
				if err := processEnvRefs(val); err != nil {
					return err
				}
			}
		}
	case []interface{}:
		for i, val := range t {
			if str, ok := val.(string); ok {
				if strings.HasPrefix(str, "ref+env://") {
					varName := strings.TrimPrefix(str, "ref+env://")
					t[i] = os.Getenv(varName)
				}
			} else {
				if err := processEnvRefs(val); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
