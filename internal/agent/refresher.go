// Package agent keeps an OIDC token valid and serves it to other authk commands
// over a local socket.
package agent

import (
	"context"
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

	mu          sync.Mutex // guards the fields below
	token       *oauth2.Token
	lastRenewal time.Time
	lastErr     error

	wake chan struct{} // tells run to reschedule after an on-demand renewal
}

// NewRefresher returns a refresher for token. onToken is called with every renewed token.
func NewRefresher(client TokenClient, token *oauth2.Token, onToken func(*oauth2.Token)) *Refresher {
	if onToken == nil {
		onToken = func(*oauth2.Token) {}
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
		lastRenewal:   time.Now(),
		wake:          make(chan struct{}, 1),
	}
}

// Current returns the current token. It must not be modified.
func (r *Refresher) Current() *oauth2.Token {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.token
}

// State is a snapshot of the refresher, for status reporting.
type State struct {
	Token       *oauth2.Token
	LastRenewal time.Time
	LastErr     error
}

// State returns a snapshot of the refresher.
func (r *Refresher) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return State{Token: r.token, LastRenewal: r.lastRenewal, LastErr: r.lastErr}
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
	for {
		if !ok {
			log.Warn().Msg("Token has no expiry: it will not be refreshed")
		} else {
			log.Info().Time("refresh_at", next).Msg("Waiting for token refresh")
		}

		switch r.waitUntil(ctx, next, ok) {
		case waitCancelled:
			return nil
		case waitWoken:
			// Renewed on demand: reschedule from the new token
			retryDelay = r.RetryDelay
			token = r.Current()
			next, ok = r.nextRefresh(token)
			continue
		}

		if _, err := r.Renew(ctx, token); err != nil {
			if ctx.Err() != nil {
				return nil
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
	if token.Expiry.IsZero() {
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

// renew uses the refresh token when there is one, and falls back to a full authentication.
func (r *Refresher) renew(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
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
