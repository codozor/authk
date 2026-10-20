package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/codozor/authk/internal/config"
	"github.com/rs/zerolog/log"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type Client struct {
	cfg          *config.Config
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	httpClient   *http.Client
	public       bool
}

func NewClient(cfg *config.Config) (*Client, error) {
	ctx := context.Background()

	// Use custom HTTP client with timeout
	httpClient := &http.Client{Timeout: 30 * time.Second}
	ctx = oidc.ClientContext(ctx, httpClient)

	provider, err := oidc.NewProvider(ctx, cfg.OIDC.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider: %w", err)
	}

	// Determine AuthStyle based on AuthMethod
	var authStyle oauth2.AuthStyle
	public := false
	switch cfg.OIDC.AuthMethod {
	case "none":
		public = true
	case "client_secret_post", "post":
		authStyle = oauth2.AuthStyleInParams
	case "client_secret_basic", "basic", "": // Default to basic if not specified
		authStyle = oauth2.AuthStyleInHeader
	default:
		return nil, fmt.Errorf("unsupported auth method: %s", cfg.OIDC.AuthMethod)
	}

	// A client without secret is a public client (e.g. Keycloak "Client authentication: Off"):
	// client_id is sent in the request body and no client_secret is sent.
	if cfg.OIDC.ClientSecret == "" {
		public = true
	}
	if public {
		authStyle = oauth2.AuthStyleInParams
		if cfg.OIDC.ClientSecret != "" {
			log.Warn().Msg("authMethod is \"none\": ignoring configured clientSecret")
		}
	}

	clientSecret := cfg.OIDC.ClientSecret
	if public {
		clientSecret = ""
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   provider.Endpoint().AuthURL,
			TokenURL:  provider.Endpoint().TokenURL,
			AuthStyle: authStyle, // Set AuthStyle here
		},
		Scopes: cfg.OIDC.Scopes,
	}

	return &Client{
		cfg:          cfg,
		provider:     provider,
		oauth2Config: oauth2Config,
		httpClient:   httpClient,
		public:       public,
	}, nil
}

func (c *Client) GetToken(username, password string) (*oauth2.Token, error) {
	ctx := context.Background()

	// Use config credentials if provided, otherwise fallback to args or client credentials
	user := username
	pass := password
	if user == "" {
		user = c.cfg.User.Username
	}
	if pass == "" {
		pass = c.cfg.User.Password
	}

	var token *oauth2.Token
	var err error

	if user != "" && pass != "" {
		log.Info().Str("grant_type", "password").Msg("Using Resource Owner Password Credentials flow")
		if c.cfg.OIDC.Audience != "" {
			// oauth2.Config.PasswordCredentialsToken does not accept extra parameters
			token, err = c.passwordCredentialsToken(ctx, user, pass)
		} else {
			token, err = c.oauth2Config.PasswordCredentialsToken(ctx, user, pass)
		}
	} else if c.public {
		return nil, fmt.Errorf("public client (no client secret) requires username and password: client_credentials flow is not available")
	} else {
		log.Info().Str("grant_type", "client_credentials").Msg("Using Client Credentials flow")
		// For client credentials, we need to create a clientcredentials.Config
		ccConfig := clientcredentials.Config{
			ClientID:     c.oauth2Config.ClientID,
			ClientSecret: c.oauth2Config.ClientSecret,
			TokenURL:     c.oauth2Config.Endpoint.TokenURL,
			Scopes:       c.oauth2Config.Scopes,
			AuthStyle:    c.oauth2Config.Endpoint.AuthStyle,
		}
		if c.cfg.OIDC.Audience != "" {
			ccConfig.EndpointParams = url.Values{"audience": {c.cfg.OIDC.Audience}}
		}
		// The clientcredentials.Config should use the http client set in the context
		token, err = ccConfig.Token(ctx)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	// Validate ID Token if present
	if idTokenRaw, ok := token.Extra("id_token").(string); ok && idTokenRaw != "" {
		verifier := c.provider.Verifier(&oidc.Config{ClientID: c.cfg.OIDC.ClientID})
		idToken, err := verifier.Verify(ctx, idTokenRaw)
		if err != nil {
			log.Warn().Err(err).Msg("failed to verify ID token")
		} else {
			log.Debug().
				Str("issuer", idToken.Issuer).
				Str("subject", idToken.Subject).
				Msg("ID Token validated successfully")
		}
	} else {
		log.Debug().Msg("No ID Token found or provided in response")
	}

	return token, nil
}

// RefreshToken refreshes an expired token using the oauth2 library.
// It takes the existing *oauth2.Token which must contain a valid RefreshToken.
func (c *Client) RefreshToken(oldToken *oauth2.Token) (*oauth2.Token, error) {
	ctx := context.Background()

	tokenSource := c.oauth2Config.TokenSource(ctx, oldToken)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	return newToken, nil
}

// passwordCredentialsToken performs the Resource Owner Password Credentials grant
// with the configured audience, which oauth2.Config.PasswordCredentialsToken cannot send.
func (c *Client) passwordCredentialsToken(ctx context.Context, username, password string) (*oauth2.Token, error) {
	v := url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
		"audience":   {c.cfg.OIDC.Audience},
	}
	if len(c.oauth2Config.Scopes) > 0 {
		v.Set("scope", strings.Join(c.oauth2Config.Scopes, " "))
	}
	if c.oauth2Config.Endpoint.AuthStyle == oauth2.AuthStyleInParams {
		v.Set("client_id", c.oauth2Config.ClientID)
		if c.oauth2Config.ClientSecret != "" {
			v.Set("client_secret", c.oauth2Config.ClientSecret)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.oauth2Config.Endpoint.TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.oauth2Config.Endpoint.AuthStyle == oauth2.AuthStyleInHeader {
		// RFC 6749 section 2.3.1: credentials are form-urlencoded before Basic encoding
		req.SetBasicAuth(url.QueryEscape(c.oauth2Config.ClientID), url.QueryEscape(c.oauth2Config.ClientSecret))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		retrieveErr := &oauth2.RetrieveError{Response: resp, Body: body}
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
			ErrorURI         string `json:"error_uri"`
		}
		if json.Unmarshal(body, &errResp) == nil {
			retrieveErr.ErrorCode = errResp.Error
			retrieveErr.ErrorDescription = errResp.ErrorDescription
			retrieveErr.ErrorURI = errResp.ErrorURI
		}
		return nil, retrieveErr
	}

	var tokenResp struct {
		AccessToken  string      `json:"access_token"`
		TokenType    string      `json:"token_type"`
		RefreshToken string      `json:"refresh_token"`
		ExpiresIn    json.Number `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("server response missing access_token")
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	token := &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
	}
	if expiresIn, err := tokenResp.ExpiresIn.Int64(); err == nil && expiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
		token.ExpiresIn = expiresIn
	}
	return token.WithExtra(raw), nil
}
