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
	LogFile         string    `json:"logFile,omitempty"`
	PID             int       `json:"pid"`
	ConfigPath      string    `json:"configPath"`
	Profile         string    `json:"profile"`
	Issuer          string    `json:"issuer"`
	ClientID        string    `json:"clientId"`
	Targets         []string  `json:"targets"`
	TargetFiles     []string  `json:"targetFiles"`
	StartedAt       time.Time `json:"startedAt"`
	Expiry          time.Time `json:"expiry,omitzero"`
	HasRefreshToken bool      `json:"hasRefreshToken"`
	HasIDToken      bool      `json:"hasIdToken"`
	LastRenewal     time.Time `json:"lastRenewal"`
	LastError       string    `json:"lastError,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}
