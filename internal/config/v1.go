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
	method := MethodClientSecretBasic
	switch v.OIDC.AuthMethod {
	case "post":
		method = MethodClientSecretPost
	case "none":
		method = MethodNone
	}

	// Version 1 used the password flow when user credentials were configured
	flow := Flow{Type: FlowClientCredentials}
	if v.User.Username != "" && v.User.Password != "" {
		flow = Flow{Type: FlowPassword, Username: v.User.Username, Password: v.User.Password}
	}

	return &Config{
		Version: CurrentVersion,
		Profiles: map[string]Profile{
			DefaultProfileName: {
				IssuerURL: v.OIDC.IssuerURL,
				ClientID:  v.OIDC.ClientID,
				Client:    Client{Method: method, Secret: v.OIDC.ClientSecret},
				Flow:      flow,
				Scopes:    v.OIDC.Scopes,
				EnvKeys:   EnvKeys{AccessToken: v.TokenKey, IDToken: v.IDTokenKey},
				Targets:   v.Targets,
			},
		},
	}
}
