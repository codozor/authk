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
		fmt.Fprintf(&b, "issuerUrl: %s\n", quote(p.IssuerURL))
		fmt.Fprintf(&b, "clientId: %s\n", quote(p.ClientID))

		b.WriteString("client: {\n")
		fmt.Fprintf(&b, "method: %s\n", quote(p.Client.Method))
		if p.Client.Secret != "" {
			fmt.Fprintf(&b, "secret: %s\n", quote(p.Client.Secret))
		}
		b.WriteString("}\n")

		b.WriteString("flow: {\n")
		fmt.Fprintf(&b, "type: %s\n", quote(p.Flow.Type))
		if p.Flow.Type == FlowPassword {
			fmt.Fprintf(&b, "username: %s\n", quote(p.Flow.Username))
			fmt.Fprintf(&b, "password: %s\n", quote(p.Flow.Password))
		}
		b.WriteString("}\n")

		quoted := make([]string, 0, len(p.Scopes))
		for _, s := range p.Scopes {
			quoted = append(quoted, quote(s))
		}
		fmt.Fprintf(&b, "scopes: [%s]\n", strings.Join(quoted, ", "))

		if len(p.Targets) > 0 {
			b.WriteString("targets: [\n")
			for _, t := range p.Targets {
				fmt.Fprintf(&b, "{file: %s, key: %s, type: %s},\n", quote(t.File), quote(t.Key), quote(t.Type))
			}
			b.WriteString("]\n")
		} else if !slices.Contains([]EnvKeys{{}, {AccessToken: "TOKEN"}}, p.EnvKeys) {
			// envKeys are only used without targets; omit the default
			b.WriteString("envKeys: {\n")
			fmt.Fprintf(&b, "accessToken: %s\n", quote(p.EnvKeys.AccessToken))
			if p.EnvKeys.IDToken != "" {
				fmt.Fprintf(&b, "idToken: %s\n", quote(p.EnvKeys.IDToken))
			}
			b.WriteString("}\n")
		}
		b.WriteString("}\n")
	}

	out, err := format.Source([]byte(b.String()))
	if err != nil {
		return nil, fmt.Errorf("failed to format config: %w", err)
	}
	return out, nil
}

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
