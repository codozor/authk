package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeConfig writes content to authk.cue in a new directory and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authk.cue")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	return path
}

func mustProfile(t *testing.T, path, name string) *Profile {
	t.Helper()
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	p, err := cfg.Profile(name)
	if err != nil {
		t.Fatalf("Profile(%q) error = %v", name, err)
	}
	return p
}

// --- Version 1 files are converted into a "default" profile ---

func TestLoadV1_ClientCredentials(t *testing.T) {
	path := writeConfig(t, `
package config

oidc: {
	issuerUrl: "https://example.com"
	clientId: "client"
	clientSecret: "secret"
	authMethod: "post"
}

tokenKey: "MY_TOKEN"
idTokenKey: "MY_ID_TOKEN"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.SourceVersion() != 1 || cfg.Version != CurrentVersion {
		t.Errorf("versions: source %d, converted %d", cfg.SourceVersion(), cfg.Version)
	}
	if names := cfg.ProfileNames(); !reflect.DeepEqual(names, []string{DefaultProfileName}) {
		t.Fatalf("profiles = %v", names)
	}

	p := mustProfile(t, path, "")
	want := Profile{
		Name:      DefaultProfileName,
		IssuerURL: "https://example.com",
		ClientID:  "client",
		Client:    Client{Method: MethodClientSecretPost, Secret: "secret"},
		Flow:      Flow{Type: FlowClientCredentials},
		Scopes:    []string{"openid", "profile", "email"},
		EnvKeys:   EnvKeys{AccessToken: "MY_TOKEN", IDToken: "MY_ID_TOKEN"},
	}
	if !reflect.DeepEqual(*p, want) {
		t.Errorf("profile =\n%+v\nwant\n%+v", *p, want)
	}
}

func TestLoadV1_PasswordWithSecrets(t *testing.T) {
	t.Setenv("TEST_AUTHK_USER", "alice")
	path := writeConfig(t, `
package config

oidc: {
	issuerUrl: "https://example.com"
	clientId: "client"
	clientSecret: "ref+echo://super-secret-value"
}

user: {
	username: "ref+env://TEST_AUTHK_USER"
	password: "ref+echo://super-secret-value"
}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// Load keeps references unresolved
	if raw := cfg.Profiles[DefaultProfileName]; raw.Flow.Username != "ref+env://TEST_AUTHK_USER" {
		t.Errorf("Load() must not resolve secrets, got username %q", raw.Flow.Username)
	}

	p := mustProfile(t, path, "")
	if p.Flow != (Flow{Type: FlowPassword, Username: "alice", Password: "super-secret-value"}) {
		t.Errorf("flow = %+v", p.Flow)
	}
	if p.Client.Secret != "super-secret-value" {
		t.Errorf("client secret = %q", p.Client.Secret)
	}
}

func TestLoadV1_PublicClient(t *testing.T) {
	withUser := writeConfig(t, `
package config

oidc: {
	issuerUrl: "https://example.com"
	clientId: "public-client"
	authMethod: "none"
}
user: { username: "u", password: "p" }
`)
	p := mustProfile(t, withUser, "")
	if !p.Client.Public() || p.Client.Method != MethodNone || p.Flow.Type != FlowPassword {
		t.Errorf("unexpected profile %+v", p)
	}

	// Version 1 failed at runtime in this case; it now fails when selecting the profile
	withoutUser := writeConfig(t, `
package config

oidc: {
	issuerUrl: "https://example.com"
	clientId: "public-client"
}
`)
	cfg, err := Load(withoutUser)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if _, err := cfg.Profile(""); err == nil || !strings.Contains(err.Error(), "requires a client secret") {
		t.Errorf("expected a client secret error, got %v", err)
	}
}

func TestLoadV1_Targets(t *testing.T) {
	path := writeConfig(t, `
package config

oidc: {
	issuerUrl: "https://example.com"
	clientId: "client"
	clientSecret: "secret"
}

targets: [
	{ file: ".env.1", key: "KEY1", type: "access_token" },
	{ file: ".env.1", key: "ID1", type: "id_token" },
	{ file: ".env.2", key: "KEY2" }
]
`)
	dir := filepath.Dir(path)
	p := mustProfile(t, path, "")
	want := []Target{
		{File: filepath.Join(dir, ".env.1"), Key: "KEY1", Type: TargetAccessToken},
		{File: filepath.Join(dir, ".env.1"), Key: "ID1", Type: TargetIDToken},
		{File: filepath.Join(dir, ".env.2"), Key: "KEY2", Type: TargetAccessToken},
	}
	if !reflect.DeepEqual(p.Targets, want) {
		t.Errorf("targets =\n%+v\nwant\n%+v", p.Targets, want)
	}
}

func TestProfile_TargetPaths(t *testing.T) {
	absTarget := filepath.Join(t.TempDir(), "abs.env")
	path := writeConfig(t, `
package config

version: 2
profiles: dev: {
	issuerUrl: "https://example.com"
	clientId: "client"
	client: secret: "s"
	flow: type: "client_credentials"
	targets: [
		{ file: "apps/front/.env", key: "A" },
		{ file: "`+filepath.ToSlash(absTarget)+`", key: "B" },
	]
}
`)
	// Load from another working directory: paths must not depend on it
	t.Chdir(t.TempDir())

	p := mustProfile(t, path, "dev")
	if want := filepath.Join(filepath.Dir(path), "apps", "front", ".env"); p.Targets[0].File != want {
		t.Errorf("relative target = %s, want %s", p.Targets[0].File, want)
	}
	if p.Targets[1].File != filepath.FromSlash(absTarget) {
		t.Errorf("absolute target = %s, want %s", p.Targets[1].File, absTarget)
	}
}

// --- Version 2 ---

const v2Profiles = `
package config

version: 2

profiles: dev: {
	issuerUrl: "https://kc.example.com/realms/dev"
	clientId:  "authk"
	client: { method: "client_secret_post", secret: "dev-secret" }
	flow: type: "client_credentials"
	scopes: ["openid"]
}

profiles: prod: {
	issuerUrl: "https://kc.example.com/realms/prod"
	clientId:  "authk"
	client: secret: "ref+file:///nonexistent/authk-test-secret"
	flow: { type: "password", username: "u", password: "p" }
}

profiles: tv: {
	issuerUrl: "https://kc.example.com/realms/dev"
	clientId:  "tv"
	client: method: "none"
	flow: type: "device_code"
}
`

func TestLoadV2_Profiles(t *testing.T) {
	path := writeConfig(t, v2Profiles)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.ProfileNames(); !reflect.DeepEqual(got, []string{"dev", "prod", "tv"}) {
		t.Errorf("profiles = %v", got)
	}

	dev, err := cfg.Profile("dev")
	if err != nil {
		t.Fatalf("Profile(dev) error = %v", err)
	}
	if dev.Client != (Client{Method: MethodClientSecretPost, Secret: "dev-secret"}) ||
		!reflect.DeepEqual(dev.Scopes, []string{"openid"}) || dev.EnvKeys.AccessToken != "TOKEN" {
		t.Errorf("unexpected dev profile %+v", dev)
	}

	// Default method, and a device_code profile is accepted by the config
	tv, err := cfg.Profile("tv")
	if err != nil {
		t.Fatalf("Profile(tv) error = %v", err)
	}
	if tv.Flow.Type != FlowDeviceCode || !tv.Client.Public() {
		t.Errorf("unexpected tv profile %+v", tv)
	}

	// Secrets are resolved only for the selected profile: prod's broken reference
	// did not prevent using dev, but fails when prod is selected
	if _, err := cfg.Profile("prod"); err == nil || !strings.Contains(err.Error(), "secrets") {
		t.Errorf("expected a secret resolution error for prod, got %v", err)
	}
}

func TestProfileName(t *testing.T) {
	several, err := Load(writeConfig(t, v2Profiles))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := several.ProfileName(""); err == nil || !strings.Contains(err.Error(), "--profile") {
		t.Errorf("several profiles without default must ask for --profile, got %v", err)
	}
	if _, err := several.ProfileName("staging"); err == nil || !strings.Contains(err.Error(), "dev, prod, tv") {
		t.Errorf("an unknown profile must list the profiles, got %v", err)
	}

	withDefault, err := Load(writeConfig(t, v2Profiles+"\ndefaultProfile: \"prod\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if name, err := withDefault.ProfileName(""); err != nil || name != "prod" {
		t.Errorf("ProfileName() = %q, %v; want prod", name, err)
	}
	if name, err := withDefault.ProfileName("dev"); err != nil || name != "dev" {
		t.Errorf("ProfileName(dev) = %q, %v", name, err)
	}
}

func TestLoadV2_Invalid(t *testing.T) {
	profile := func(body string) string {
		return "package config\nversion: 2\nprofiles: p: {\n" +
			"issuerUrl: \"https://x\"\nclientId: \"c\"\n" + body + "\n}\n"
	}
	tests := map[string]string{
		"no profile":              "package config\nversion: 2\nprofiles: {}\n",
		"unknown default profile": profile(`flow: type: "client_credentials"`) + `defaultProfile: "nope"` + "\n",
		"missing flow":            profile(``),
		"unknown flow":            profile(`flow: type: "implicit"`),
		"password without user":   profile(`flow: { type: "password", password: "p" }`),
		"field of another flow":   profile(`flow: { type: "client_credentials", username: "u" }`),
		"typo in a field":         profile(`flow: type: "client_credentials"` + "\nscope: [\"openid\"]"),
		"unknown client method":   profile(`flow: type: "client_credentials"` + "\nclient: method: \"basic\""),
		"unsupported version":     "package config\nversion: 3\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, content)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// --- Render (authk config migrate) ---

func TestRender_RoundTrip(t *testing.T) {
	v1 := writeConfig(t, `
package config

// a comment that is lost
oidc: {
	issuerUrl: "https://example.com"
	clientId: "client"
	clientSecret: "ref+env://AUTHK_TEST_SECRET"
	authMethod: "basic"
}
user: { username: "u", password: "ref+sops://secrets.yaml#/password" }
idTokenKey: "ID"
`)
	cfg, err := Load(v1)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	text := string(out)
	for _, want := range []string{
		"version: 2",
		"profiles: default: {",
		`secret: "ref+env://AUTHK_TEST_SECRET"`,
		`password: "ref+sops://secrets.yaml#/password"`,
		`type:     "password"`,
		`idToken:     "ID"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered config misses %q:\n%s", want, text)
		}
	}

	// The rendered file loads back to the same config
	again, err := Load(writeConfig(t, text))
	if err != nil {
		t.Fatalf("Load(rendered) error = %v\n%s", err, text)
	}
	if again.SourceVersion() != 2 || !reflect.DeepEqual(again.Profiles, cfg.Profiles) {
		t.Errorf("round trip changed the config:\n%+v\n%+v", again.Profiles, cfg.Profiles)
	}
}

func TestRender_V2RoundTrip(t *testing.T) {
	cfg, err := Load(writeConfig(t, v2Profiles+"\ndefaultProfile: \"dev\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(cfg)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Load(writeConfig(t, string(out)))
	if err != nil {
		t.Fatalf("Load(rendered) error = %v\n%s", err, out)
	}
	if again.DefaultProfile != "dev" || !reflect.DeepEqual(again.Profiles, cfg.Profiles) {
		t.Errorf("round trip changed the config:\n%s", out)
	}
}

func TestRender_QuotesOnlyWhenNeeded(t *testing.T) {
	path := writeConfig(t, "package config\nversion: 2\n"+
		"profiles: \"my-team\": {issuerUrl: \"https://x\", clientId: \"c\", client: secret: \"s\", flow: type: \"client_credentials\"}\n"+
		"profiles: dev2: {issuerUrl: \"https://x\", clientId: \"c\", client: secret: \"s\", flow: type: \"client_credentials\"}\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`profiles: "my-team": {`, "profiles: dev2: {"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("rendered config misses %q:\n%s", want, out)
		}
	}
	if _, err := Load(writeConfig(t, string(out))); err != nil {
		t.Errorf("rendered config does not load: %v", err)
	}
}
