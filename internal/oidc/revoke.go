package oidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

// ErrRevocationNotSupported is returned by Revoke when the provider has no
// revocation_endpoint.
var ErrRevocationNotSupported = errors.New("the provider does not support token revocation (no revocation_endpoint)")

// Revoke revokes a refresh token at the provider (RFC 7009). Keycloak and Authentik
// then end the session it belongs to.
func (c *Client) Revoke(ctx context.Context, refreshToken string) error {
	var claims struct {
		RevocationEndpoint string `json:"revocation_endpoint"`
	}
	if err := c.provider.Claims(&claims); err != nil || claims.RevocationEndpoint == "" {
		return ErrRevocationNotSupported
	}

	form := url.Values{"token": {refreshToken}, "token_type_hint": {"refresh_token"}}
	cfg := c.oauth2Config
	basic := cfg.ClientSecret != "" && cfg.Endpoint.AuthStyle == oauth2.AuthStyleInHeader
	if !basic {
		// Public client, or secret in the body (clientAuth "post")
		form.Set("client_id", cfg.ClientID)
		if cfg.ClientSecret != "" {
			form.Set("client_secret", cfg.ClientSecret)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, claims.RevocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth(url.QueryEscape(cfg.ClientID), url.QueryEscape(cfg.ClientSecret))
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to revoke the token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	// RFC 7009: 200 even when the token was already invalid
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to revoke the token: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
