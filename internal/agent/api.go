package agent

import "time"

// Token types served by the agent, matching config target types.
const (
	TypeAccessToken = "access_token"
	TypeIDToken     = "id_token"
)

// TokenResponse is returned by GET /v1/token.
type TokenResponse struct {
	Type   string    `json:"type"`
	Token  string    `json:"token"`
	Expiry time.Time `json:"expiry,omitzero"`
}

// Status is returned by GET /v1/status and POST /v1/refresh.
type Status struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	LogFile         string    `json:"logFile,omitempty"`
	PID             int       `json:"pid"`
	ConfigPath      string    `json:"configPath"`
	Profile         string    `json:"profile"`
	Issuer          string    `json:"issuer"`
	ClientID        string    `json:"clientId"`
	Targets         []string  `json:"targets"`
	TargetFiles     []string  `json:"targetFiles"`
	StartedAt       time.Time `json:"startedAt"`
	Ready           bool      `json:"ready"` // the agent has a token
	Expiry          time.Time `json:"expiry,omitzero"`
	HasRefreshToken bool      `json:"hasRefreshToken"`
	HasIDToken      bool      `json:"hasIdToken"`
	LastRenewal     time.Time `json:"lastRenewal"`
	LastError       string    `json:"lastError,omitempty"`

	// Interactive flows (device_code, authorization_code)
	LoginRequired bool         `json:"loginRequired,omitempty"` // a login is needed to get or renew the token
	Login         *LoginPrompt `json:"login,omitempty"`         // pending login
	TokenStore    string       `json:"tokenStore,omitempty"`    // where the refresh token is stored
	// When the refresh token expires (refresh_expires_in, Keycloak): a login is needed
	// after it. Zero when unknown or when it does not expire (offline token).
	SessionExpiry time.Time `json:"sessionExpiry,omitzero"`
}

// loginCompleteRequest is the body of POST /v1/login/complete.
type loginCompleteRequest struct {
	URL string `json:"url"`
}

// codeLoginRequired marks an error response caused by ErrLoginRequired.
const codeLoginRequired = "login_required"

type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}
