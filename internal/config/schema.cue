package config

oidc: {
	issuerUrl:    string
	clientId:     string
	clientSecret: string | *""
	scopes:       [...string] | *["openid", "profile", "email"]
	authMethod:   "basic" | "post" | "none" | *"basic"
	audience?:    string
}
user: {
	username?: string
	password?: string
}
tokenKey: string | *"TOKEN"
idTokenKey?: string

targets?: [...{
	file: string
	key:  string
	type: "access_token" | "id_token" | *"access_token"
}]
