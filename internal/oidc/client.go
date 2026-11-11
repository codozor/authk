package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
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

	// OnDeviceLogin is called by GetToken with what the user must do to log in, for
	// the device_code flow. It must show it to the user.
	OnDeviceLogin func(DeviceLogin)
}

// DeviceLogin is a pending device_code login: the user must open VerificationURI and
// enter UserCode (or open VerificationURIComplete, which contains the code) before Expiry.
type DeviceLogin struct {
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	Expiry                  time.Time

	client *Client
	auth   *oauth2.DeviceAuthResponse
}

// NewClient discovers the OIDC provider of the profile. The profile must come from
// config.Config.Profile (secrets resolved).
func NewClient(p *config.Profile) (*Client, error) {
	// Use custom HTTP client with timeout, for discovery and for every token request
	httpClient := &http.Client{Timeout: 30 * time.Second}
	ctx := oidc.ClientContext(context.Background(), httpClient)

	provider, err := oidc.NewProvider(ctx, p.Issuer)
	if err != nil {
		return nil, discoveryError(p.Issuer, err)
	}

	var authStyle oauth2.AuthStyle
	switch p.ClientAuth {
	case config.AuthNone:
	case config.AuthPost:
		authStyle = oauth2.AuthStyleInParams
	case config.AuthBasic, "":
		authStyle = oauth2.AuthStyleInHeader
	default:
		return nil, fmt.Errorf("unsupported clientAuth: %s", p.ClientAuth)
	}

	// A public client (e.g. Keycloak "Client authentication: Off") sends client_id in
	// the request body and no client_secret.
	// config.Profile rejects clientAuth "none" with a clientSecret.
	clientSecret := p.ClientSecret
	if p.Public() {
		authStyle = oauth2.AuthStyleInParams
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

// Interactive reports whether the flow of the profile needs the user to log in.
func (c *Client) Interactive() bool {
	return c.profile.Flow == config.FlowDeviceCode
}

// GetToken runs the flow of the profile to get a new token. For the device_code flow,
// it calls OnDeviceLogin and waits until the user logs in.
func (c *Client) GetToken(ctx context.Context) (*oauth2.Token, error) {
	if c.profile.Flow == config.FlowDeviceCode {
		if c.OnDeviceLogin == nil {
			return nil, errors.New("the device_code flow needs a way to show the login code")
		}
		login, err := c.StartDeviceLogin(ctx)
		if err != nil {
			return nil, err
		}
		c.OnDeviceLogin(*login)
		return login.Wait(ctx)
	}
	ctx = c.withHTTPClient(ctx)

	var token *oauth2.Token
	var err error

	switch p := c.profile; p.Flow {
	case config.FlowPassword:
		log.Info().Str("grant_type", "password").Msg("Using Resource Owner Password Credentials flow")
		token, err = c.oauth2Config.PasswordCredentialsToken(ctx, p.Username, p.Password)
	case config.FlowClientCredentials:
		if p.Public() {
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
		return nil, fmt.Errorf("%w: %s", ErrFlowNotSupported, p.Flow)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	c.verifyIDToken(ctx, token)
	return token, nil
}

// StartDeviceLogin starts a device_code login (RFC 8628): the returned login tells what
// the user must do, and its Wait method waits until they did.
func (c *Client) StartDeviceLogin(ctx context.Context) (*DeviceLogin, error) {
	if c.oauth2Config.Endpoint.DeviceAuthURL == "" {
		return nil, errors.New("the provider does not support the device_code flow (no device_authorization_endpoint)")
	}
	ctx = c.withHTTPClient(ctx)

	// oauth2 does not authenticate the client on the device endpoint: a confidential
	// client sends its secret in the body, which Keycloak and Authentik accept.
	var opts []oauth2.AuthCodeOption
	if secret := c.oauth2Config.ClientSecret; secret != "" {
		opts = append(opts, oauth2.SetAuthURLParam("client_secret", secret))
	}
	log.Info().Str("grant_type", "device_code").Msg("Using Device Authorization flow")
	auth, err := c.oauth2Config.DeviceAuth(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to start device login: %w", err)
	}
	return &DeviceLogin{
		UserCode:                auth.UserCode,
		VerificationURI:         auth.VerificationURI,
		VerificationURIComplete: auth.VerificationURIComplete,
		Expiry:                  auth.Expiry,
		client:                  c,
		auth:                    auth,
	}, nil
}

// Wait polls the provider until the user logged in, refused, or the code expired.
func (l *DeviceLogin) Wait(ctx context.Context) (*oauth2.Token, error) {
	c := l.client
	ctx = c.withHTTPClient(ctx)
	token, err := c.oauth2Config.DeviceAccessToken(ctx, l.auth)
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) {
			switch re.ErrorCode {
			case "expired_token":
				return nil, errors.New("device login failed: the code expired before the user logged in")
			case "access_denied":
				return nil, errors.New("device login failed: the user refused the access")
			case "invalid_client":
				// The device endpoint often only checks client_id: a secret missing or
				// wrong only shows here
				if c.oauth2Config.ClientSecret == "" {
					return nil, fmt.Errorf("device login failed: %w (the client is probably confidential: "+
						"set clientSecret, or make the client public in the provider)", err)
				}
				return nil, fmt.Errorf("device login failed: %w (check clientSecret and clientAuth)", err)
			}
		}
		if errors.Is(err, context.DeadlineExceeded) && !l.Expiry.IsZero() && !time.Now().Before(l.Expiry) {
			return nil, errors.New("device login failed: the code expired before the user logged in")
		}
		return nil, fmt.Errorf("device login failed: %w", err)
	}
	if token.RefreshToken == "" {
		log.Warn().Msg("No refresh token: you will have to log in again when the token expires " +
			"(add the offline_access scope to get one)")
	}
	c.verifyIDToken(ctx, token)
	return token, nil
}

// verifyIDToken checks the ID Token of token, if any, and only logs the result.
func (c *Client) verifyIDToken(ctx context.Context, token *oauth2.Token) {
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

// discoveryError makes a discovery failure readable: go-oidc includes the whole response
// body, often an HTML error page.
func discoveryError(issuer string, err error) error {
	msg := err.Error()
	if i := strings.Index(msg, "\n"); i >= 0 {
		msg = msg[:i]
	}
	msg = strings.TrimSuffix(strings.TrimSpace(msg), ":")
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	url := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	hint := ""
	if strings.HasPrefix(msg, "404") {
		hint = "; check the issuer (Keycloak: https://<host>/realms/<realm>, " +
			"Authentik: https://<host>/application/o/<application slug>/)"
	}
	return fmt.Errorf("failed to discover OIDC provider at %s: %s%s", url, msg, hint)
}
