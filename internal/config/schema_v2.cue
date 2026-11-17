package config

version: 2

// Profile used when --profile is not given and the file has several profiles
defaultProfile?: string

profiles: [string]: #Profile

#Profile: {
	// Where the tokens come from: an OIDC provider, or the Kubernetes API (a
	// service account token)
	provider: *"oidc" | "kubernetes"

	if provider == "oidc" {
		#OIDC
	}
	if provider == "kubernetes" {
		#Kubernetes
	}

	// Files to write the tokens to. Without targets, nothing is written: tokens
	// are only available through "authk get" (and the agent).
	targets?: [...#Target]
}

#Target: {
	// "env": a KEY="token" line in a .env file. "raw": a file holding only the
	// token, like the service account token mounted in a pod.
	format: *"env" | "raw"
	if format == "env" {
		// Without file: the .env file found from the current directory, or --env
		file?: string
		key:   string
	}
	if format == "raw" {
		file: string
	}
	type: *"access_token" | "id_token"
}

#OIDC: {
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
	if flow == "device_code" || flow == "authorization_code" {
		// Where the refresh token is kept between runs, to avoid logging in again:
		// the OS keyring, a private file, or nowhere. "auto": the keyring when
		// available, the file otherwise.
		tokenStore: *"auto" | "keyring" | "file" | "none"
	}

	scopes: [...string] | *["openid", "profile", "email"]
}

// A service account token, asked to the Kubernetes API (TokenRequest, like
// "kubectl create token")
#Kubernetes: {
	// Kubeconfig file. Absent: $KUBECONFIG, then ~/.kube/config
	kubeconfig?: string
	// Kubeconfig context. Absent: the current context
	context?: string
	// Namespace of the service account. Absent: the namespace of the context
	namespace?: string
	serviceAccount: string
	// Audiences of the token. Absent: the audience of the API server
	audiences?: [...string]
	// Requested validity, a Go duration ("1h", "30m"), at least 10m. The API
	// server may grant less. Absent: the API server default
	duration?: string
}
