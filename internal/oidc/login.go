package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/codozor/authk/internal/config"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

// Login is a pending interactive login: the user must open URL (and enter UserCode for
// the device_code flow) before Expiry. Wait returns the token once they did.
type Login struct {
	URL         string    // verification URI (device_code) or authorization URL (authorization_code)
	UserCode    string    // device_code only
	CompleteURL string    // device_code only: verification URI containing the code
	Expiry      time.Time // zero if unknown

	// Browser is set when the provider redirects the browser to a local callback
	// (authorization_code): Complete then accepts the URL the browser ended on, for a
	// browser that cannot reach the callback (another machine without port forwarding).
	Browser bool

	wait     func(context.Context) (*oauth2.Token, error)
	complete func(redirectURL string) error
}

// Wait waits until the user logged in, refused, or the login expired.
func (l *Login) Wait(ctx context.Context) (*oauth2.Token, error) {
	return l.wait(ctx)
}

// Complete finishes a browser login with the URL the browser was redirected to.
func (l *Login) Complete(redirectURL string) error {
	if l.complete == nil {
		return errors.New("this login does not take a redirect URL")
	}
	return l.complete(redirectURL)
}

// StartLogin starts the login of an interactive flow.
func (c *Client) StartLogin(ctx context.Context) (*Login, error) {
	switch c.profile.Flow {
	case config.FlowDeviceCode:
		return c.startDeviceLogin(ctx)
	case config.FlowAuthorizationCode:
		return c.startBrowserLogin(ctx)
	}
	return nil, fmt.Errorf("the %s flow does not need a login", c.profile.Flow)
}

// loginError explains the token errors of an interactive login.
func (c *Client) loginError(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		switch re.ErrorCode {
		case "expired_token":
			return errors.New("login failed: the code expired before the user logged in")
		case "access_denied":
			return errors.New("login failed: the user refused the access")
		case "invalid_client":
			// The device and authorization endpoints often only check client_id: a
			// secret missing or wrong only shows on the token endpoint
			if c.oauth2Config.ClientSecret == "" {
				return fmt.Errorf("login failed: %w (the client is probably confidential: "+
					"set clientSecret, or make the client public in the provider)", err)
			}
			return fmt.Errorf("login failed: %w (check clientSecret and clientAuth)", err)
		}
	}
	return fmt.Errorf("login failed: %w", err)
}

// loggedIn finishes a successful interactive login.
func (c *Client) loggedIn(ctx context.Context, token *oauth2.Token) *oauth2.Token {
	if token.RefreshToken == "" {
		log.Warn().Msg("No refresh token: you will have to log in again when the token expires " +
			"(add the offline_access scope to get one)")
	}
	c.verifyIDToken(ctx, token)
	return token
}

// startDeviceLogin starts a device_code login (RFC 8628).
func (c *Client) startDeviceLogin(ctx context.Context) (*Login, error) {
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

	wait := func(ctx context.Context) (*oauth2.Token, error) {
		ctx = c.withHTTPClient(ctx)
		token, err := c.oauth2Config.DeviceAccessToken(ctx, auth)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && !auth.Expiry.IsZero() && !time.Now().Before(auth.Expiry) {
				return nil, errors.New("login failed: the code expired before the user logged in")
			}
			return nil, c.loginError(err)
		}
		return c.loggedIn(ctx, token), nil
	}
	return &Login{
		URL:         auth.VerificationURI,
		UserCode:    auth.UserCode,
		CompleteURL: auth.VerificationURIComplete,
		Expiry:      auth.Expiry,
		wait:        wait,
	}, nil
}
