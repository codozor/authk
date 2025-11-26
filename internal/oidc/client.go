package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/codozor/authk/internal/config"
	"github.com/rs/zerolog/log"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type Client struct {
	cfg        *config.Config
	httpClient *http.Client
	endpoints  *providerEndpoints
}

type providerEndpoints struct {
	TokenEndpoint string `json:"token_endpoint"`
}

func NewClient(cfg *config.Config) (*Client, error) {
	c := &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	if err := c.discoverEndpoints(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Client) discoverEndpoints() error {
	wellKnownURL := strings.TrimRight(c.cfg.OIDC.IssuerURL, "/") + "/.well-known/openid-configuration"
	resp, err := c.httpClient.Get(wellKnownURL)
	if err != nil {
		return fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery request failed with status: %d", resp.StatusCode)
	}

	var endpoints providerEndpoints
	if err := json.NewDecoder(resp.Body).Decode(&endpoints); err != nil {
		return fmt.Errorf("failed to decode discovery document: %w", err)
	}

	c.endpoints = &endpoints
	return nil
}

func (c *Client) RefreshToken(refreshToken string) (*TokenResponse, error) {
	log.Info().Msg("Refreshing token...")

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	return c.makeTokenRequest(data)
}

func (c *Client) GetToken(username, password string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("scope", strings.Join(c.cfg.OIDC.Scopes, " "))

	// Use config credentials if provided, otherwise fallback to args or client credentials
	user := username
	pass := password
	if user == "" {
		user = c.cfg.User.Username
	}
	if pass == "" {
		pass = c.cfg.User.Password
	}

	if user != "" && pass != "" {
		log.Info().Str("grant_type", "password").Msg("Using Resource Owner Password Credentials flow")
		data.Set("grant_type", "password")
		data.Set("username", user)
		data.Set("password", pass)
	} else {
		log.Info().Str("grant_type", "client_credentials").Msg("Using Client Credentials flow")
		data.Set("grant_type", "client_credentials")
	}

	return c.makeTokenRequest(data)
}

func (c *Client) makeTokenRequest(data url.Values) (*TokenResponse, error) {
	// Handle Auth Method
	if c.cfg.OIDC.AuthMethod == "post" {
		data.Set("client_id", c.cfg.OIDC.ClientID)
		data.Set("client_secret", c.cfg.OIDC.ClientSecret)
	} else {
		// Default to basic
		// RFC 6749 says client_id in body is NOT RECOMMENDED for Basic Auth,
		// but we'll leave it out to be strict.
		// If the user wants it in body, they should use "post" or we'd need a "basic_with_body" option.
		// For now, let's stick to strict Basic Auth.
	}

	if c.cfg.OIDC.RedirectURL != "" {
		data.Set("redirect_uri", c.cfg.OIDC.RedirectURL)
	}

	log.Debug().
		Str("endpoint", c.endpoints.TokenEndpoint).
		Str("auth_method", c.cfg.OIDC.AuthMethod).
		Str("grant_type", data.Get("grant_type")).
		Msg("Making token request")

	req, err := http.NewRequest("POST", c.endpoints.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if c.cfg.OIDC.AuthMethod != "post" {
		req.SetBasicAuth(c.cfg.OIDC.ClientID, c.cfg.OIDC.ClientSecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Try to read body for error details
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		log.Debug().Interface("error_response", errResp).Msg("Token request failed")
		return nil, fmt.Errorf("token request returned status %d: %v", resp.StatusCode, errResp)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}
