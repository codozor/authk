package main

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

// tokenClient is the part of oidc.Client used by the refresh loop.
type tokenClient interface {
	GetToken(ctx context.Context, username, password string) (*oauth2.Token, error)
	RefreshToken(ctx context.Context, oldToken *oauth2.Token) (*oauth2.Token, error)
}

// refresher keeps a token valid until its context is cancelled.
type refresher struct {
	client  tokenClient
	onToken func(*oauth2.Token) // called with every new token

	refreshBuffer time.Duration // renew this long before expiry (at most half the token lifetime)
	minDelay      time.Duration // never schedule a renewal sooner than this
	retryDelay    time.Duration // first delay after a failed renewal, doubled up to maxRetryDelay
	maxRetryDelay time.Duration
	checkInterval time.Duration // the wall clock is checked at least this often
}

func newRefresher(client tokenClient, onToken func(*oauth2.Token)) *refresher {
	return &refresher{
		client:        client,
		onToken:       onToken,
		refreshBuffer: 60 * time.Second,
		minDelay:      10 * time.Second,
		retryDelay:    10 * time.Second,
		maxRetryDelay: 60 * time.Second,
		checkInterval: 30 * time.Second,
	}
}

// run renews token before it expires and returns nil when ctx is cancelled.
func (r *refresher) run(ctx context.Context, token *oauth2.Token) error {
	retryDelay := r.retryDelay
	next, ok := r.nextRefresh(token)
	for {
		if !ok {
			log.Warn().Msg("Token has no expiry: it will not be refreshed")
			<-ctx.Done()
			return nil
		}

		log.Info().Time("refresh_at", next).Msg("Waiting for token refresh")
		if !r.waitUntil(ctx, next) {
			return nil
		}

		newToken, err := r.renew(ctx, token)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Error().Err(err).Dur("retry_in", retryDelay).Msg("Failed to renew token")
			next = time.Now().Round(0).Add(retryDelay)
			retryDelay = min(retryDelay*2, r.maxRetryDelay)
			continue
		}

		retryDelay = r.retryDelay
		token = newToken
		r.onToken(token)
		next, ok = r.nextRefresh(token)
	}
}

// nextRefresh returns when token must be renewed, or false if it never expires.
func (r *refresher) nextRefresh(token *oauth2.Token) (time.Time, bool) {
	if token.Expiry.IsZero() {
		return time.Time{}, false
	}
	// Round(0) strips the monotonic clock reading: comparisons then use the wall clock,
	// which keeps running while the machine is suspended (the monotonic clock does not).
	expiry := token.Expiry.Round(0)
	now := time.Now().Round(0)

	buffer := min(r.refreshBuffer, expiry.Sub(now)/2)
	at := expiry.Add(-buffer)
	if earliest := now.Add(r.minDelay); at.Before(earliest) {
		at = earliest
	}
	return at, true
}

// waitUntil blocks until the wall clock reaches at (true) or ctx is cancelled (false).
// It wakes up at least every checkInterval, so a suspend does not delay the renewal.
func (r *refresher) waitUntil(ctx context.Context, at time.Time) bool {
	for {
		remaining := at.Sub(time.Now().Round(0))
		if remaining <= 0 {
			return true
		}
		timer := time.NewTimer(min(remaining, r.checkInterval))
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}

// renew uses the refresh token when there is one, and falls back to a full authentication.
func (r *refresher) renew(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
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
	return r.client.GetToken(ctx, "", "")
}
