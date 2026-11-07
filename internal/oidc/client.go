package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/codozor/authk/internal/config"
	"github.com/rs/zerolog/log"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// ErrNoRefreshToken is returned by RefreshToken when the token has no refresh token
// (e.g. client_credentials flow): the caller must re-authenticate instead.
var ErrNoRefreshToken = errors.New("no refresh token available")

// ErrFlowNotSupported is returned by GetToken for a flow this version cannot run yet.
var ErrFlowNotSupported = errors.New("flow not supported yet")

type Client struct {
	profile      *config.Profile
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	httpClient   *http.Client
}

// NewClient discovers the OIDC provider of the profile. The profile must come from
// config.Config.Profile (secrets resolved).
func NewClient(p *config.Profile) (*Client, error) {
	// Use custom HTTP client with timeout, for discovery and for every token request
	httpClient := &http.Client{Timeout: 30 * time.Second}
	ctx := oidc.ClientContext(context.Background(), httpClient)

	provider, err := oidc.NewProvider(ctx, p.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider: %w", err)
	}

	var authStyle oauth2.AuthStyle
	switch p.Client.Method {
	case config.MethodNone:
	case config.MethodClientSecretPost:
		authStyle = oauth2.AuthStyleInParams
	case config.MethodClientSecretBasic, "":
		authStyle = oauth2.AuthStyleInHeader
	default:
		return nil, fmt.Errorf("unsupported client authentication method: %s", p.Client.Method)
	}

	// A public client (e.g. Keycloak "Client authentication: Off") sends client_id in
	// the request body and no client_secret.
	clientSecret := p.Client.Secret
	if p.Client.Public() {
		authStyle = oauth2.AuthStyleInParams
		if clientSecret != "" {
			log.Warn().Msg("client method is \"none\": ignoring configured client secret")
		}
		clientSecret = ""
	}

	oauth2Config := &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:       provider.Endpoint().AuthURL,
			TokenURL:      provider.Endpoint().TokenURL,
			DeviceAuthURL: provider.Endpoint().DeviceAuthURL,
			AuthStyle:     authStyle,
		},
		Scopes: p.Scopes,
	}

	return &Client{
		profile:      p,
		provider:     provider,
		oauth2Config: oauth2Config,
		httpClient:   httpClient,
	}, nil
}

// withHTTPClient makes oauth2 and go-oidc use the client's HTTP client (and its timeout)
// instead of http.DefaultClient.
func (c *Client) withHTTPClient(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, c.httpClient)
}

// GetToken runs the flow of the profile to get a new token.
func (c *Client) GetToken(ctx context.Context) (*oauth2.Token, error) {
	ctx = c.withHTTPClient(ctx)

	var token *oauth2.Token
	var err error

	switch flow := c.profile.Flow; flow.Type {
	case config.FlowPassword:
		log.Info().Str("grant_type", "password").Msg("Using Resource Owner Password Credentials flow")
		token, err = c.oauth2Config.PasswordCredentialsToken(ctx, flow.Username, flow.Password)
	case config.FlowClientCredentials:
		if c.profile.Client.Public() {
			return nil, errors.New("public client (no client secret): the client_credentials flow is not available")
		}
		log.Info().Str("grant_type", "client_credentials").Msg("Using Client Credentials flow")
		ccConfig := clientcredentials.Config{
			ClientID:     c.oauth2Config.ClientID,
			ClientSecret: c.oauth2Config.ClientSecret,
			TokenURL:     c.oauth2Config.Endpoint.TokenURL,
			Scopes:       c.oauth2Config.Scopes,
			AuthStyle:    c.oauth2Config.Endpoint.AuthStyle,
		}
		token, err = ccConfig.Token(ctx)
	default:
		return nil, fmt.Errorf("%w: %s", ErrFlowNotSupported, flow.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	// Validate ID Token if present
	if idTokenRaw, ok := token.Extra("id_token").(string); ok && idTokenRaw != "" {
		verifier := c.provider.Verifier(&oidc.Config{ClientID: c.profile.ClientID})
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

// RefreshToken always performs a refresh_token grant, even if oldToken is still valid.
// It returns ErrNoRefreshToken if oldToken has no refresh token.
func (c *Client) RefreshToken(ctx context.Context, oldToken *oauth2.Token) (*oauth2.Token, error) {
	if oldToken == nil || oldToken.RefreshToken == "" {
		return nil, ErrNoRefreshToken
	}
	ctx = c.withHTTPClient(ctx)

	// oauth2.Config.TokenSource returns the token unchanged while it is still valid.
	// Passing only the refresh token makes it invalid, which forces the refresh grant.
	tokenSource := c.oauth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: oldToken.RefreshToken})
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	return newToken, nil
}
