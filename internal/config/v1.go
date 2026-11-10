package config

// v1Config is the version 1 format: a single client, with the flow inferred from the
// presence of user credentials.
type v1Config struct {
	OIDC struct {
		IssuerURL    string   `json:"issuerUrl"`
		ClientID     string   `json:"clientId"`
		ClientSecret string   `json:"clientSecret"`
		Scopes       []string `json:"scopes"`
		AuthMethod   string   `json:"authMethod"`
	} `json:"oidc"`
	User struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"user"`
	TokenKey   string   `json:"tokenKey"`
	IDTokenKey string   `json:"idTokenKey"`
	Targets    []Target `json:"targets"`
}

// convert returns the equivalent version 2 config, with a single "default" profile.
// Values are copied unresolved: secrets references (ref+...) are kept as is.
func (v *v1Config) convert() *Config {
	p := Profile{
		Issuer:       v.OIDC.IssuerURL,
		ClientID:     v.OIDC.ClientID,
		ClientSecret: v.OIDC.ClientSecret,
		ClientAuth:   AuthBasic,
		Flow:         FlowClientCredentials,
		Scopes:       v.OIDC.Scopes,
		Targets:      v.Targets,
	}
	switch v.OIDC.AuthMethod {
	case "post":
		p.ClientAuth = AuthPost
	case "none":
		// Version 1 ignored the secret of a public client, with a warning
		p.ClientAuth = AuthNone
		p.ClientSecret = ""
	}

	// Version 1 used the password flow when user credentials were configured
	if v.User.Username != "" && v.User.Password != "" {
		p.Flow = FlowPassword
		p.Username = v.User.Username
		p.Password = v.User.Password
	}

	// Without targets, version 1 wrote tokenKey (and idTokenKey) to the .env file
	// found from the current directory: targets without file do the same.
	if len(p.Targets) == 0 {
		p.Targets = []Target{{Key: v.TokenKey, Type: TargetAccessToken}}
		if v.IDTokenKey != "" {
			p.Targets = append(p.Targets, Target{Key: v.IDTokenKey, Type: TargetIDToken})
		}
	}

	return &Config{
		Version:  CurrentVersion,
		Profiles: map[string]Profile{DefaultProfileName: p},
	}
}
