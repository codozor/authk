package config

version: 2

// Profile used when --profile is not given and the file has several profiles
defaultProfile?: string

profiles: [string]: #Profile

#Profile: {
	issuer:   string
	clientId: string
	// Absent for a public client (Keycloak "Client authentication: Off")
	clientSecret?: string
	// How the client secret is sent: HTTP Basic header, or request body
	clientAuth: *"basic" | "post" | "none"

	flow: "client_credentials" | "password" | "device_code" | "authorization_code"
	if flow == "password" {
		username: string
		password: string
	}
	if flow == "authorization_code" {
		// Port of the local redirect URI http://127.0.0.1:<port>/callback.
		// Absent: a free port is chosen at each login.
		redirectPort?: int & >0 & <65536
	}

	scopes: [...string] | *["openid", "profile", "email"]

	// Files to write the tokens to. Without targets, nothing is written: tokens
	// are only available through "authk get" (and the agent).
	targets?: [...#Target]
}

#Target: {
	// Without file: the .env file found from the current directory, or --env
	file?: string
	key:   string
	type:  *"access_token" | "id_token"
}
