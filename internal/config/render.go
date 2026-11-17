package config

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"cuelang.org/go/cue/format"
)

// Render returns the config as a version 2 CUE file. Secret references (ref+...) are
// written as loaded: Render must be called on a config from Load, not on a resolved
// profile. Comments of the original file are not kept.
func Render(c *Config) ([]byte, error) {
	var b strings.Builder
	b.WriteString("package config\n\n")
	fmt.Fprintf(&b, "version: %d\n", CurrentVersion)
	if c.DefaultProfile != "" {
		fmt.Fprintf(&b, "defaultProfile: %s\n", quote(c.DefaultProfile))
	}

	for _, name := range c.ProfileNames() {
		p := c.Profiles[name]
		fmt.Fprintf(&b, "\nprofiles: %s: {\n", label(name))
		if p.Kubernetes() {
			renderKubernetes(&b, &p)
		} else {
			renderOIDC(&b, &p)
		}

		if len(p.Targets) > 0 {
			b.WriteString("targets: [\n")
			for _, t := range p.Targets {
				b.WriteString("{")
				if t.File != "" {
					fmt.Fprintf(&b, "file: %s, ", quote(t.File))
				}
				fmt.Fprintf(&b, "key: %s", quote(t.Key))
				if t.Type != "" && t.Type != TargetAccessToken {
					fmt.Fprintf(&b, ", type: %s", quote(t.Type))
				}
				b.WriteString("},\n")
			}
			b.WriteString("]\n")
		}
		b.WriteString("}\n")
	}

	out, err := format.Source([]byte(b.String()))
	if err != nil {
		return nil, fmt.Errorf("failed to format config: %w", err)
	}
	return out, nil
}

func renderOIDC(b *strings.Builder, p *Profile) {
	fmt.Fprintf(b, "issuer: %s\n", quote(p.Issuer))
	fmt.Fprintf(b, "clientId: %s\n", quote(p.ClientID))
	if p.ClientSecret != "" {
		fmt.Fprintf(b, "clientSecret: %s\n", quote(p.ClientSecret))
	}
	if p.ClientAuth != "" && p.ClientAuth != AuthBasic {
		fmt.Fprintf(b, "clientAuth: %s\n", quote(p.ClientAuth))
	}

	fmt.Fprintf(b, "flow: %s\n", quote(p.Flow))
	if p.Flow == FlowPassword {
		fmt.Fprintf(b, "username: %s\n", quote(p.Username))
		fmt.Fprintf(b, "password: %s\n", quote(p.Password))
	}
	if p.Flow == FlowAuthorizationCode && p.RedirectPort != 0 {
		fmt.Fprintf(b, "redirectPort: %d\n", p.RedirectPort)
	}
	if p.TokenStore != "" && p.TokenStore != StoreAuto {
		fmt.Fprintf(b, "tokenStore: %s\n", quote(p.TokenStore))
	}

	if !slices.Equal(p.Scopes, defaultScopes) {
		fmt.Fprintf(b, "scopes: %s\n", quoteList(p.Scopes))
	}
}

func renderKubernetes(b *strings.Builder, p *Profile) {
	fmt.Fprintf(b, "provider: %s\n", quote(ProviderKubernetes))
	for _, f := range []struct{ name, value string }{
		{"kubeconfig", p.Kubeconfig},
		{"context", p.Context},
		{"namespace", p.Namespace},
		{"serviceAccount", p.ServiceAccount},
	} {
		if f.value != "" {
			fmt.Fprintf(b, "%s: %s\n", f.name, quote(f.value))
		}
	}
	if len(p.Audiences) > 0 {
		fmt.Fprintf(b, "audiences: %s\n", quoteList(p.Audiences))
	}
	if p.Duration != "" {
		fmt.Fprintf(b, "duration: %s\n", quote(p.Duration))
	}
}

// quoteList returns values as a CUE list of strings.
func quoteList(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, quote(v))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// defaultScopes are the scopes of the schema default, omitted when rendering.
var defaultScopes = []string{"openid", "profile", "email"}

// identifier matches names usable as CUE labels without quotes.
var identifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// label returns name as a CUE label, quoted only when needed.
func label(name string) string {
	keywords := []string{"package", "import", "for", "in", "if", "let", "true", "false", "null"}
	if identifier.MatchString(name) && !slices.Contains(keywords, name) {
		return name
	}
	return quote(name)
}

// quote returns s as a CUE string literal (JSON string syntax is valid CUE).
func quote(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}
