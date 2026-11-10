// Package agent keeps an OIDC token valid and serves it to other authk commands
// over a local socket.
package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

// TokenClient is the part of oidc.Client used by the refresher.
type TokenClient interface {
	GetToken(ctx context.Context) (*oauth2.Token, error)
	RefreshToken(ctx context.Context, oldToken *oauth2.Token) (*oauth2.Token, error)
}

// ErrLoginRequired is returned when the token cannot be renewed without the user, for
// an interactive flow (device_code): there is no token yet, or the session expired.
var ErrLoginRequired = errors.New("login required")

// LoginPrompt tells the user how to log in.
type LoginPrompt struct {
	URL         string    `json:"url"`
	Code        string    `json:"code"`
	CompleteURL string    `json:"completeUrl,omitempty"` // URL containing the code
	Expiry      time.Time `json:"expiry,omitzero"`
}

// LoginFunc starts an interactive login: it returns what the user must do and a
// function waiting until they did.
type LoginFunc func(ctx context.Context) (LoginPrompt, func(context.Context) (*oauth2.Token, error), error)

// Refresher owns the current token and renews it before it expires.
// It is the only component allowed to renew: with refresh token rotation (Keycloak
// "Revoke Refresh Token"), two concurrent renewals would invalidate each other.
type Refresher struct {
	client  TokenClient
	onToken func(*oauth2.Token) // called with every new token, under renewMu

	RefreshBuffer time.Duration // renew this long before expiry (at most half the token lifetime)
	MinDelay      time.Duration // never schedule a renewal sooner than this
	RetryDelay    time.Duration // first delay after a failed renewal, doubled up to MaxRetryDelay
	MaxRetryDelay time.Duration
	CheckInterval time.Duration // the wall clock is checked at least this often

	renewMu sync.Mutex // serializes renewals

	login LoginFunc // set for interactive flows (SetLogin)

	mu            sync.Mutex // guards the fields below
	token         *oauth2.Token
	lastRenewal   time.Time
	lastErr       error
	loginRequired bool
	pending       *Login

	wake chan struct{} // tells run to reschedule after an on-demand renewal
}

// Login is an interactive login started by StartLogin, waiting for the user.
type Login struct {
	Prompt LoginPrompt

	ready chan struct{} // closed when Prompt is set, or the start failed
	done  chan struct{} // closed when the login ends
	err   error         // set before done is closed
}

// Done is closed when the login ends.
func (l *Login) Done() <-chan struct{} { return l.done }

// Err returns why the login failed, once Done is closed.
func (l *Login) Err() error { return l.err }

// NewRefresher returns a refresher for token (nil for an interactive flow before the
// first login, see SetLogin). onToken is called with every new token.
func NewRefresher(client TokenClient, token *oauth2.Token, onToken func(*oauth2.Token)) *Refresher {
	if onToken == nil {
		onToken = func(*oauth2.Token) {}
	}
	var lastRenewal time.Time
	if token != nil {
		lastRenewal = time.Now()
	}
	return &Refresher{
		client:        client,
		onToken:       onToken,
		RefreshBuffer: 60 * time.Second,
		MinDelay:      10 * time.Second,
		RetryDelay:    10 * time.Second,
		MaxRetryDelay: 60 * time.Second,
		CheckInterval: 30 * time.Second,
		token:         token,
		lastRenewal:   lastRenewal,
		wake:          make(chan struct{}, 1),
	}
}

// SetLogin makes the flow interactive: the refresher then never authenticates by itself.
// When the token cannot be refreshed, it reports ErrLoginRequired until StartLogin
// succeeds. It must be called before Run.
func (r *Refresher) SetLogin(login LoginFunc) {
	r.login = login
	r.mu.Lock()
	r.loginRequired = r.token == nil
	r.mu.Unlock()
}

// Current returns the current token, nil before the first login. It must not be modified.
func (r *Refresher) Current() *oauth2.Token {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.token
}

// State is a snapshot of the refresher, for status reporting.
type State struct {
	Token         *oauth2.Token
	LastRenewal   time.Time
	LastErr       error
	LoginRequired bool
	Login         *LoginPrompt // pending login, if any
}

// State returns a snapshot of the refresher.
func (r *Refresher) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := State{Token: r.token, LastRenewal: r.lastRenewal, LastErr: r.lastErr, LoginRequired: r.loginRequired}
	if l := r.pending; l != nil {
		select {
		case <-l.ready:
			prompt := l.Prompt
			st.Login = &prompt
		default:
		}
	}
	return st
}

// StartLogin starts an interactive login, or returns the pending one. The login goes on
// in the background with lifetime, the agent lifetime context, while ctx only bounds the
// wait for the prompt.
func (r *Refresher) StartLogin(ctx, lifetime context.Context) (*Login, error) {
	if r.login == nil {
		return nil, errors.New("the flow of this profile does not need a login")
	}
	r.mu.Lock()
	if l := r.pending; l != nil {
		r.mu.Unlock()
		select {
		case <-l.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case <-l.done:
			if l.err != nil {
				return nil, l.err
			}
		default:
		}
		return l, nil
	}
	l := &Login{ready: make(chan struct{}), done: make(chan struct{})}
	r.pending = l
	r.mu.Unlock()

	prompt, wait, err := r.login(lifetime)
	if err != nil {
		l.err = err
		r.mu.Lock()
		r.pending = nil
		r.lastErr = err
		r.mu.Unlock()
		close(l.ready)
		close(l.done)
		return nil, err
	}
	l.Prompt = prompt
	close(l.ready)
	log.Info().Str("url", prompt.URL).Str("code", prompt.Code).Time("expires", prompt.Expiry).Msg("Waiting for the user to log in")

	go func() {
		token, err := wait(lifetime)
		if err == nil {
			r.setToken(token)
			log.Info().Msg("Logged in")
		} else if lifetime.Err() == nil {
			log.Error().Err(err).Msg("Login failed")
		}
		r.mu.Lock()
		l.err = err
		r.pending = nil
		if err != nil {
			r.lastErr = err
		}
		r.mu.Unlock()
		close(l.done)
	}()
	return l, nil
}

// setToken installs a token obtained by a login, like a renewal.
func (r *Refresher) setToken(token *oauth2.Token) {
	r.renewMu.Lock()
	defer r.renewMu.Unlock()
	r.mu.Lock()
	r.token = token
	r.lastRenewal = time.Now()
	r.lastErr = nil
	r.loginRequired = false
	r.mu.Unlock()
	r.onToken(token)
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Renew renews the token unless it already changed since the caller read seen:
// concurrent callers that saw the same token trigger a single renewal.
// Pass nil to always renew.
func (r *Refresher) Renew(ctx context.Context, seen *oauth2.Token) (*oauth2.Token, error) {
	r.renewMu.Lock()
	defer r.renewMu.Unlock()

	current := r.Current()
	if seen != nil && current != seen {
		return current, nil
	}

	newToken, err := r.renew(ctx, current)

	r.mu.Lock()
	r.lastErr = err
	if err == nil {
		r.token = newToken
		r.lastRenewal = time.Now()
		r.loginRequired = false
	} else if errors.Is(err, ErrLoginRequired) {
		r.loginRequired = true
	}
	r.mu.Unlock()

	if err != nil {
		return nil, err
	}
	r.onToken(newToken)

	// Reschedule the loop from the new token (non-blocking: one pending wake is enough)
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return newToken, nil
}

// Run renews the token before it expires and returns nil when ctx is cancelled.
func (r *Refresher) Run(ctx context.Context) error {
	retryDelay := r.RetryDelay
	token := r.Current()
	next, ok := r.nextRefresh(token)
	waitingLogin := token == nil
	for {
		switch {
		case waitingLogin:
			// Interactive flow: nothing to do until a login
		case !ok:
			log.Warn().Msg("Token has no expiry: it will not be refreshed")
		default:
			log.Info().Time("refresh_at", next).Msg("Waiting for token refresh")
		}

		switch r.waitUntil(ctx, next, ok) {
		case waitCancelled:
			return nil
		case waitWoken:
			// Renewed on demand or logged in: reschedule from the new token
			retryDelay = r.RetryDelay
			waitingLogin = false
			token = r.Current()
			next, ok = r.nextRefresh(token)
			continue
		}

		if _, err := r.Renew(ctx, token); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, ErrLoginRequired) {
				// Retrying cannot help: wait for a login
				log.Error().Err(err).Msg("Cannot renew the token: run \"authk agent login\"")
				next, ok, waitingLogin = time.Time{}, false, true
				continue
			}
			log.Error().Err(err).Dur("retry_in", retryDelay).Msg("Failed to renew token")
			next, ok = time.Now().Round(0).Add(retryDelay), true
			retryDelay = min(retryDelay*2, r.MaxRetryDelay)
			continue
		}

		// Our own renewal also queued a wake: drop it
		select {
		case <-r.wake:
		default:
		}
		retryDelay = r.RetryDelay
		token = r.Current() // ours, or a newer one renewed on demand meanwhile
		next, ok = r.nextRefresh(token)
	}
}

// nextRefresh returns when token must be renewed, or false if it never expires.
func (r *Refresher) nextRefresh(token *oauth2.Token) (time.Time, bool) {
	if token == nil || token.Expiry.IsZero() {
		return time.Time{}, false
	}
	// Round(0) strips the monotonic clock reading: comparisons then use the wall clock,
	// which keeps running while the machine is suspended (the monotonic clock does not).
	expiry := token.Expiry.Round(0)
	now := time.Now().Round(0)

	buffer := min(r.RefreshBuffer, expiry.Sub(now)/2)
	at := expiry.Add(-buffer)
	if earliest := now.Add(r.MinDelay); at.Before(earliest) {
		at = earliest
	}
	return at, true
}

type waitResult int

const (
	waitReached waitResult = iota
	waitWoken
	waitCancelled
)

// waitUntil blocks until the wall clock reaches at, a renewal happened elsewhere, or ctx
// is cancelled. With scheduled false, it only waits for a wake or a cancellation.
// It wakes up at least every CheckInterval, so a suspend does not delay the renewal.
func (r *Refresher) waitUntil(ctx context.Context, at time.Time, scheduled bool) waitResult {
	for {
		var tick <-chan time.Time
		var timer *time.Timer
		if scheduled {
			remaining := at.Sub(time.Now().Round(0))
			if remaining <= 0 {
				return waitReached
			}
			timer = time.NewTimer(min(remaining, r.CheckInterval))
			tick = timer.C
		}
		select {
		case <-ctx.Done():
			stopTimer(timer)
			return waitCancelled
		case <-r.wake:
			stopTimer(timer)
			return waitWoken
		case <-tick:
		}
	}
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

// renew uses the refresh token when there is one, and falls back to a full authentication,
// except for an interactive flow, which then needs a login.
func (r *Refresher) renew(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	if r.login != nil {
		if token == nil || token.RefreshToken == "" {
			return nil, ErrLoginRequired
		}
		newToken, err := r.client.RefreshToken(ctx, token)
		if err != nil && sessionExpired(err) {
			return nil, fmt.Errorf("%w: %w", ErrLoginRequired, err)
		}
		return newToken, err
	}
	if token.RefreshToken != "" {
		newToken, err := r.client.RefreshToken(ctx, token)
		if err == nil {
			log.Debug().Msg("Token refreshed with refresh token")
			return newToken, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
		log.Warn().Err(err).Msg("Failed to refresh token, attempting full re-authentication")
	}
	return r.client.GetToken(ctx)
}

// sessionExpired reports whether a refresh failed because the refresh token is no longer
// valid (session expired or revoked), rather than for a transient reason.
func sessionExpired(err error) bool {
	var re *oauth2.RetrieveError
	return errors.As(err, &re) && re.ErrorCode == "invalid_grant"
}
