package config

#Config: {
	oidc: {
		issuerUrl:    string
		clientId:     string
		clientSecret: string
		scopes:       [...string] | *["openid", "profile", "email"]
		authMethod:   "basic" | "post" | *"basic"
		redirectUrl?: string
	}
	user: {
		username?: string
		password?: string
	}
	tokenKey: string | *"TOKEN"
}
