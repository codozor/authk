package config

version: 2

// Profile used when --profile is not given and the file has several profiles
defaultProfile?: string

profiles: [string]: #Profile

#Profile: {
	issuerUrl: string
	clientId:  string
	client:    #Client
	flow:      #ClientCredentials | #Password | #DeviceCode
	scopes:    [...string] | *["openid", "profile", "email"]
	// Keys written to the --env file when the profile has no targets
	envKeys:  #EnvKeys
	targets?: [...#Target]
}

#Client: {
	method: *"client_secret_basic" | "client_secret_post" | "none"
	// Empty for a public client
	secret: string | *""
}

#ClientCredentials: {
	type: "client_credentials"
}

#Password: {
	type:     "password"
	username: string
	password: string
}

#DeviceCode: {
	type: "device_code"
}

#EnvKeys: {
	accessToken: string | *"TOKEN"
	idToken:     string | *""
}

#Target: {
	file: string
	key:  string
	type: *"access_token" | "id_token"
}
