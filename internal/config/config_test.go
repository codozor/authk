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
		Name:         DefaultProfileName,
		Issuer:       "https://example.com",
		ClientID:     "client",
		ClientSecret: "secret",
		ClientAuth:   AuthPost,
		Flow:         FlowClientCredentials,
		Scopes:       []string{"openid", "profile", "email"},
		// tokenKey and idTokenKey become targets writing the .env file found at runtime
		Targets: []Target{
			{Key: "MY_TOKEN", Type: TargetAccessToken},
			{Key: "MY_ID_TOKEN", Type: TargetIDToken},
		},
	}
	if !reflect.DeepEqual(*p, want) {
		t.Errorf("profile =\n%+v\nwant\n%+v", *p, want)
	}
	if !p.UsesEnvFile() {
		t.Error("a converted v1 profile without targets must use the .env file")
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
	if raw := cfg.Profiles[DefaultProfileName]; raw.Username != "ref+env://TEST_AUTHK_USER" {
		t.Errorf("Load() must not resolve secrets, got username %q", raw.Username)
	}

	p := mustProfile(t, path, "")
	if p.Flow != FlowPassword || p.Username != "alice" || p.Password != "super-secret-value" {
		t.Errorf("unexpected credentials: flow %s, %q / %q", p.Flow, p.Username, p.Password)
	}
	if p.ClientSecret != "super-secret-value" {
		t.Errorf("client secret = %q", p.ClientSecret)
	}
	// Default tokenKey
	if !reflect.DeepEqual(p.Targets, []Target{{Key: "TOKEN", Type: TargetAccessToken}}) {
		t.Errorf("targets = %+v", p.Targets)
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
	if !p.Public() || p.ClientAuth != AuthNone || p.Flow != FlowPassword {
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

func TestProfile_PublicClientWithSecret(t *testing.T) {
	// Version 2: contradictory settings are rejected
	v2 := writeConfig(t, "package config\nversion: 2\nprofiles: p: {\n"+
		"issuer: \"https://x\"\nclientId: \"c\"\nclientSecret: \"s\"\nclientAuth: \"none\"\nflow: \"device_code\"\n}\n")
	cfg, err := Load(v2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Profile("p"); err == nil || !strings.Contains(err.Error(), "remove clientAuth") {
		t.Errorf("Profile() error = %v, want a clientAuth/clientSecret conflict", err)
	}

	// Version 1 ignored the secret: converted configs keep working
	v1 := writeConfig(t, `
package config

oidc: {
	issuerUrl: "https://example.com"
	clientId: "public-client"
	clientSecret: "ignored"
	authMethod: "none"
}
user: { username: "u", password: "p" }
`)
	if p := mustProfile(t, v1, ""); p.ClientSecret != "" || !p.Public() {
		t.Errorf("unexpected profile %+v", p)
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

tokenKey: "IGNORED_WITH_TARGETS"
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

// --- Version 2 ---

const v2Profiles = `
package config

version: 2

profiles: dev: {
	issuer:       "https://kc.example.com/realms/dev"
	clientId:     "authk"
	clientSecret: "dev-secret"
	clientAuth:   "post"
	flow:         "client_credentials"
	scopes: ["openid"]
	targets: [{key: "TOKEN"}]
}

profiles: prod: {
	issuer:       "https://kc.example.com/realms/prod"
	clientId:     "authk"
	clientSecret: "ref+file:///nonexistent/authk-test-secret"
	flow:         "password"
	username:     "u"
	password:     "p"
}

profiles: tv: {
	issuer:   "https://kc.example.com/realms/dev"
	clientId: "tv"
	flow:     "device_code"
}

profiles: web: {
	issuer:       "https://kc.example.com/realms/dev"
	clientId:     "web"
	clientAuth:   "none"
	flow:         "authorization_code"
	redirectPort: 8765
}
`

func TestLoadV2_Profiles(t *testing.T) {
	path := writeConfig(t, v2Profiles)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.ProfileNames(); !reflect.DeepEqual(got, []string{"dev", "prod", "tv", "web"}) {
		t.Errorf("profiles = %v", got)
	}

	dev, err := cfg.Profile("dev")
	if err != nil {
		t.Fatalf("Profile(dev) error = %v", err)
	}
	want := Profile{
		Name: "dev", Issuer: "https://kc.example.com/realms/dev", ClientID: "authk",
		ClientSecret: "dev-secret", ClientAuth: AuthPost, Flow: FlowClientCredentials,
		Scopes:  []string{"openid"},
		Targets: []Target{{Key: "TOKEN", Type: TargetAccessToken}},
	}
	if !reflect.DeepEqual(*dev, want) {
		t.Errorf("dev =\n%+v\nwant\n%+v", *dev, want)
	}

	// No secret: public client; no targets: nothing written
	tv, err := cfg.Profile("tv")
	if err != nil {
		t.Fatalf("Profile(tv) error = %v", err)
	}
	if tv.Flow != FlowDeviceCode || !tv.Public() || tv.ClientAuth != AuthBasic || len(tv.Targets) != 0 || tv.UsesEnvFile() {
		t.Errorf("unexpected tv profile %+v", tv)
	}

	// Secrets are resolved only for the selected profile: prod's broken reference
	// did not prevent using dev, but fails when prod is selected
	if _, err := cfg.Profile("prod"); err == nil || !strings.Contains(err.Error(), "secrets") {
		t.Errorf("expected a secret resolution error for prod, got %v", err)
	}
	web, err := cfg.Profile("web")
	if err != nil || web.Flow != FlowAuthorizationCode || web.RedirectPort != 8765 || !web.Public() {
		t.Errorf("web profile = %+v, %v", web, err)
	}
}

func TestProfile_TargetPaths(t *testing.T) {
	absTarget := filepath.Join(t.TempDir(), "abs.env")
	path := writeConfig(t, `
package config

version: 2
profiles: dev: {
	issuer: "https://example.com"
	clientId: "client"
	clientSecret: "s"
	flow: "client_credentials"
	targets: [
		{ file: "apps/front/.env", key: "A" },
		{ file: "`+filepath.ToSlash(absTarget)+`", key: "B" },
		{ key: "C" },
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
	if p.Targets[2].File != "" || !p.UsesEnvFile() {
		t.Errorf("a target without file must stay without file, got %q", p.Targets[2].File)
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
			"issuer: \"https://x\"\nclientId: \"c\"\nclientSecret: \"s\"\n" + body + "\n}\n"
	}
	tests := map[string]string{
		"no profile":                     "package config\nversion: 2\nprofiles: {}\n",
		"unknown default profile":        profile(`flow: "client_credentials"`) + `defaultProfile: "nope"` + "\n",
		"missing flow":                   profile(``),
		"unknown flow":                   profile(`flow: "implicit"`),
		"password without username":      profile(`flow: "password"` + "\npassword: \"p\""),
		"username with another flow":     profile(`flow: "client_credentials"` + "\nusername: \"u\""),
		"redirectPort with another flow": profile(`flow: "device_code"` + "\nredirectPort: 8765"),
		"redirectPort out of range":      profile(`flow: "authorization_code"` + "\nredirectPort: 70000"),
		"typo in a field":                profile(`flow: "client_credentials"` + "\nscope: [\"openid\"]"),
		"unknown clientAuth":             profile(`flow: "client_credentials"` + "\nclientAuth: \"client_secret_basic\""),
		"target without key":             profile(`flow: "client_credentials"` + "\ntargets: [{file: \".env\"}]"),
		"v1 field in a version 2 file":   profile(`flow: "client_credentials"` + "\nissuerUrl: \"https://x\""),
		"unsupported version":            "package config\nversion: 3\n",
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
		`clientSecret: "ref+env://AUTHK_TEST_SECRET"`,
		`password:     "ref+sops://secrets.yaml#/password"`,
		`flow:         "password"`,
		`{key: "TOKEN"}`,
		`{key: "ID", type: "id_token"}`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered config misses %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"clientAuth", "scopes"} { // defaults are omitted
		if strings.Contains(text, unwanted) {
			t.Errorf("rendered config should omit the default %s:\n%s", unwanted, text)
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
		"profiles: \"my-team\": {issuer: \"https://x\", clientId: \"c\", clientSecret: \"s\", flow: \"client_credentials\"}\n"+
		"profiles: dev2: {issuer: \"https://x\", clientId: \"c\", clientSecret: \"s\", flow: \"client_credentials\"}\n"+
		"profiles: \"if\": {issuer: \"https://x\", clientId: \"c\", clientSecret: \"s\", flow: \"client_credentials\"}\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`profiles: "my-team": {`, "profiles: dev2: {", `profiles: "if": {`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("rendered config misses %q:\n%s", want, out)
		}
	}
	if _, err := Load(writeConfig(t, string(out))); err != nil {
		t.Errorf("rendered config does not load: %v", err)
	}
}
