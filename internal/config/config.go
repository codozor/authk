// Package config loads authk configuration files (CUE).
//
// Version 2 files hold named profiles. Version 1 files (no version field) are
// converted in memory into a single profile named "default".
package config

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"github.com/helmfile/vals"
	_ "github.com/helmfile/vals/pkg/providers/file"
	_ "github.com/helmfile/vals/pkg/providers/k8s"
	_ "github.com/helmfile/vals/pkg/providers/sops"
)

//go:embed schema_v1.cue
var schemaV1 []byte

//go:embed schema_v2.cue
var schemaV2 []byte

// CurrentVersion is the configuration format written by "authk config migrate".
const CurrentVersion = 2

// DefaultProfileName is the profile created from a version 1 file.
const DefaultProfileName = "default"

// Flow types.
const (
	FlowClientCredentials = "client_credentials"
	FlowPassword          = "password"
	FlowDeviceCode        = "device_code"
)

// Client authentication methods (clientAuth).
const (
	AuthBasic = "basic"
	AuthPost  = "post"
	AuthNone  = "none"
)

// Target types.
const (
	TargetAccessToken = "access_token"
	TargetIDToken     = "id_token"
)

// Config is a loaded configuration file. Secrets are not resolved: use Profile.
type Config struct {
	Version        int                `json:"version"`
	DefaultProfile string             `json:"defaultProfile,omitempty"`
	Profiles       map[string]Profile `json:"profiles"`

	path          string // file it was loaded from
	sourceVersion int    // version of the file on disk (1 for converted files)
}

// Profile is one identity: an OIDC client, how to get its tokens and where to write them.
type Profile struct {
	Name         string   `json:"-"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret,omitempty"`
	ClientAuth   string   `json:"clientAuth"`
	Flow         string   `json:"flow"`
	Username     string   `json:"username,omitempty"` // password flow
	Password     string   `json:"password,omitempty"` // password flow
	Scopes       []string `json:"scopes"`
	Targets      []Target `json:"targets,omitempty"`
}

// Public reports whether the client has no secret (Keycloak "Client authentication: Off").
func (p *Profile) Public() bool {
	return p.ClientAuth == AuthNone || p.ClientSecret == ""
}

// Target is a key of a file to update with a token. An empty File means the .env
// file found from the current directory, or given with --env.
type Target struct {
	File string `json:"file,omitempty"`
	Key  string `json:"key"`
	Type string `json:"type"`
}

// HasFileTargets reports whether a target writes to a fixed file (with file set).
func (p *Profile) HasFileTargets() bool {
	for _, t := range p.Targets {
		if t.File != "" {
			return true
		}
	}
	return false
}

// UsesEnvFile reports whether a target writes to the .env file found from the
// current directory (or --env).
func (p *Profile) UsesEnvFile() bool {
	for _, t := range p.Targets {
		if t.File == "" {
			return true
		}
	}
	return false
}

// Path returns the file the config was loaded from.
func (c *Config) Path() string { return c.path }

// SourceVersion returns the version of the file on disk (1 for a converted v1 file).
func (c *Config) SourceVersion() int { return c.sourceVersion }

// Load reads a configuration file, version 1 or 2, and validates its structure.
// Secrets (ref+...) are not resolved: they are resolved per profile by Profile.
func Load(path string) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	ctx := cuecontext.New()
	val := ctx.CompileBytes(content, cue.Filename(path))
	if val.Err() != nil {
		return nil, fmt.Errorf("failed to compile config file: %w", val.Err())
	}

	version := 1
	if v := val.LookupPath(cue.ParsePath("version")); v.Exists() {
		n, err := v.Int64()
		if err != nil {
			return nil, fmt.Errorf("invalid config version: %w", err)
		}
		version = int(n)
	}

	var cfg *Config
	switch version {
	case 1:
		var raw v1Config
		if err := decode(ctx, schemaV1, val, &raw); err != nil {
			return nil, err
		}
		cfg = raw.convert()
	case 2:
		cfg = &Config{}
		if err := decode(ctx, schemaV2, val, cfg); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported config version %d (this authk supports 1 and 2)", version)
	}

	cfg.path = path
	cfg.sourceVersion = version
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// decode validates val against schema and decodes it into out.
func decode(ctx *cue.Context, schema []byte, val cue.Value, out any) error {
	s := ctx.CompileBytes(schema)
	if s.Err() != nil {
		return fmt.Errorf("failed to compile schema: %w", s.Err())
	}
	unified := s.Unify(val)
	if err := unified.Validate(cue.Concrete(true)); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}
	if err := unified.Decode(out); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}
	return nil
}

func (c *Config) validate() error {
	if len(c.Profiles) == 0 {
		return errors.New("config validation failed: no profile defined")
	}
	if c.DefaultProfile != "" {
		if _, ok := c.Profiles[c.DefaultProfile]; !ok {
			return fmt.Errorf("config validation failed: defaultProfile %q is not defined", c.DefaultProfile)
		}
	}
	return nil
}

// ProfileNames returns the profile names, sorted.
func (c *Config) ProfileNames() []string {
	names := make([]string, 0, len(c.Profiles))
	for name := range c.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ProfileName returns the profile to use: name if given, otherwise defaultProfile,
// otherwise the only profile.
func (c *Config) ProfileName(name string) (string, error) {
	switch {
	case name != "":
		if _, ok := c.Profiles[name]; !ok {
			return "", fmt.Errorf("profile %q not found in %s (profiles: %s)",
				name, c.path, strings.Join(c.ProfileNames(), ", "))
		}
		return name, nil
	case c.DefaultProfile != "":
		return c.DefaultProfile, nil
	case len(c.Profiles) == 1:
		return c.ProfileNames()[0], nil
	}
	return "", fmt.Errorf("%s defines several profiles (%s): use --profile or set defaultProfile",
		c.path, strings.Join(c.ProfileNames(), ", "))
}

// Profile returns the profile to use (see ProfileName), with its secrets resolved
// and its target files made absolute (relative to the config file directory).
func (c *Config) Profile(name string) (*Profile, error) {
	name, err := c.ProfileName(name)
	if err != nil {
		return nil, err
	}
	p := c.Profiles[name]

	if err := resolveSecrets(&p); err != nil {
		return nil, err
	}
	p.Name = name
	if err := p.resolveTargetPaths(c.path); err != nil {
		return nil, err
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	return &p, nil
}

// validate checks what the schema cannot: values that come from secrets, and
// combinations of fields.
func (p *Profile) validate() error {
	if p.Issuer == "" {
		return errors.New("issuer is empty")
	}
	if p.ClientID == "" {
		return errors.New("clientId is empty")
	}
	switch p.Flow {
	case FlowClientCredentials:
		if p.Public() {
			return errors.New("the client_credentials flow requires a client secret (public client)")
		}
	case FlowPassword:
		if p.Username == "" || p.Password == "" {
			return errors.New("the password flow requires a username and a password")
		}
	}
	return nil
}

// resolveSecrets replaces ref+env://, ref+file://, ref+sops:// and ref+k8s:// values.
func resolveSecrets(p *Profile) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	// Manual expansion of ref+env:// since vals env provider is problematic
	if err := processEnvRefs(m); err != nil {
		return fmt.Errorf("failed to process env refs: %w", err)
	}
	runtime, err := vals.New(vals.Options{})
	if err != nil {
		return fmt.Errorf("failed to initialize vals runtime: %w", err)
	}
	resolved, err := runtime.Eval(m)
	if err != nil {
		return fmt.Errorf("failed to evaluate secrets with vals: %w", err)
	}

	data, err = json.Marshal(resolved)
	if err != nil {
		return fmt.Errorf("failed to marshal processed config: %w", err)
	}
	var out Profile
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}
	*p = out
	return nil
}

// resolveTargetPaths makes relative target files relative to the config file directory,
// so that running authk from a subdirectory updates the same files.
func (p *Profile) resolveTargetPaths(configPath string) error {
	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("failed to resolve config path: %w", err)
	}
	baseDir := filepath.Dir(absConfig)
	for i, t := range p.Targets {
		if t.File == "" {
			continue // the .env file found at runtime
		}
		if filepath.IsAbs(t.File) {
			p.Targets[i].File = filepath.Clean(t.File)
		} else {
			p.Targets[i].File = filepath.Join(baseDir, t.File)
		}
	}
	return nil
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
