package oidc

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

// browserLoginTimeout bounds a browser login: the provider gives no expiry.
const browserLoginTimeout = 5 * time.Minute

// callbackPath is the path of the local redirect URI.
const callbackPath = "/callback"

// callbackResult is the outcome of the redirect to the local callback.
type callbackResult struct {
	code string
	err  error
}

// startBrowserLogin starts an authorization_code login with PKCE (RFC 7636): it serves
// the redirect URI http://127.0.0.1:<port>/callback until the login ends.
func (c *Client) startBrowserLogin(context.Context) (*Login, error) {
	if c.oauth2Config.Endpoint.AuthURL == "" {
		return nil, errors.New("the provider has no authorization_endpoint")
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", c.profile.RedirectPort))
	if err != nil {
		return nil, fmt.Errorf("failed to listen for the login redirect: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	cfg := *c.oauth2Config
	cfg.RedirectURL = fmt.Sprintf("http://127.0.0.1:%d%s", port, callbackPath)

	state := oauth2.GenerateVerifier() // random, unguessable
	verifier := oauth2.GenerateVerifier()
	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

	results := make(chan callbackResult, 1)
	// deliver checks a redirect and passes its outcome to wait (the first one only).
	deliver := func(q url.Values) error {
		if q.Get("state") != state {
			return errors.New("this redirect does not belong to the pending login (state mismatch)")
		}
		var res callbackResult
		switch {
		case q.Get("error") != "":
			res.err = fmt.Errorf("login failed: %s", strings.TrimSpace(q.Get("error")+" "+q.Get("error_description")))
		case q.Get("code") == "":
			res.err = errors.New("login failed: no code in the redirect")
		default:
			res.code = q.Get("code")
		}
		select {
		case results <- res:
		default: // already delivered
		}
		return res.err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+callbackPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := deliver(r.URL.Query()); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, callbackPage, "authk: login failed", html.EscapeString(err.Error()))
			return
		}
		_, _ = fmt.Fprintf(w, callbackPage, "authk: logged in", "You can close this window and go back to the terminal.")
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	log.Info().Str("grant_type", "authorization_code").Str("redirect_uri", cfg.RedirectURL).
		Msg("Using Authorization Code flow with PKCE")
	expiry := time.Now().Add(browserLoginTimeout)

	wait := func(ctx context.Context) (*oauth2.Token, error) {
		defer func() { _ = srv.Close() }()
		ctx, cancel := context.WithDeadline(ctx, expiry)
		defer cancel()

		var res callbackResult
		select {
		case res = <-results:
		case <-ctx.Done():
			if !time.Now().Before(expiry) {
				return nil, fmt.Errorf("login failed: nobody logged in within %s", browserLoginTimeout)
			}
			return nil, ctx.Err()
		}
		if res.err != nil {
			return nil, res.err
		}
		token, err := cfg.Exchange(c.withHTTPClient(ctx), res.code, oauth2.VerifierOption(verifier))
		if err != nil {
			return nil, c.loginError(err)
		}
		return c.loggedIn(ctx, token), nil
	}
	complete := func(redirectURL string) error {
		u, err := url.Parse(strings.TrimSpace(redirectURL))
		if err != nil {
			return fmt.Errorf("invalid URL: %w", err)
		}
		return deliver(u.Query())
	}

	return &Login{
		URL:      authURL,
		Expiry:   expiry,
		Browser:  true,
		wait:     wait,
		complete: complete,
	}, nil
}

const callbackPage = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>%[1]s</title></head>
<body style="font-family: sans-serif; margin: 3em; text-align: center">
<h2>%[1]s</h2><p>%[2]s</p></body></html>
`
