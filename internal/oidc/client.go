package oidc

import (
	"context"
	"fmt"
	"net/http"
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
		token, err = c.oauth2Config.PasswordCredentialsToken(ctx, user, pass)
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
