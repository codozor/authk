package config

oidc: {
	issuerUrl:    string
	clientId:     string
	clientSecret: string
	scopes:       [...string] | *["openid", "profile", "email"]
	authMethod:   "basic" | "post" | *"basic"
}
user: {
	username?: string
	password?: string
}
tokenKey: string | *"TOKEN"

targets?: [...{
	file: string
	key:  string
}]
