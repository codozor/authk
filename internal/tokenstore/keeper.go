package tokenstore

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

// RefreshFunc refreshes a token with its refresh token (oidc.Client.RefreshToken).
type RefreshFunc func(ctx context.Context, old *oauth2.Token) (*oauth2.Token, error)

// Keeper keeps the refresh token of one profile in a backend. Every process using the
// profile (agents, authk get) goes through it: with refresh token rotation, a refresh
// token can only be used once, so refreshes are serialized by a lock and each one
// starts from the newest refresh token, stored by whichever process refreshed last.
//
// A nil Keeper stores nothing: Refresh only refreshes.
type Keeper struct {
	backend  Backend
	key      string
	lockPath string // empty: no lock (the directory is not writable)

	mu   sync.Mutex
	seen string // refresh token last read from or written to the backend
}

// NewKeeper returns a keeper storing the session key in backend, nil if backend is nil.
func NewKeeper(backend Backend, key string) *Keeper {
	if backend == nil {
		return nil
	}
	k := &Keeper{backend: backend, key: key}
	if dir, err := Dir(); err != nil {
		log.Warn().Err(err).Msg("No lock for the stored refresh token")
	} else if err := ensurePrivateDir(dir); err != nil {
		log.Warn().Err(err).Msg("No lock for the stored refresh token")
	} else {
		k.lockPath = filepath.Join(dir, key+".lock")
	}
	return k
}

// Backend returns the name of the backend, "none" for a nil Keeper.
func (k *Keeper) Backend() string {
	if k == nil {
		return "none"
	}
	return k.backend.Name()
}

// Refresh refreshes current, nil when the process has no token yet. It uses the stored
// refresh token instead when another process stored a newer one, or when current has
// none, and stores the new refresh token. When the refresh token is rejected, the
// stored one is deleted (if it is the one used).
func (k *Keeper) Refresh(ctx context.Context, current *oauth2.Token, refresh RefreshFunc) (*oauth2.Token, error) {
	if k == nil {
		return refresh(ctx, current)
	}
	release := k.lock(ctx)
	if release == nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	defer release()

	used := current
	stored := k.load()
	if stored != nil {
		k.mu.Lock()
		newer := stored.RefreshToken != k.seen
		k.seen = stored.RefreshToken
		k.mu.Unlock()
		if current == nil || current.RefreshToken == "" || newer {
			log.Debug().Str("store", k.backend.Name()).Msg("Using the stored refresh token")
			used = &oauth2.Token{RefreshToken: stored.RefreshToken}
		}
	}

	token, err := refresh(ctx, used)
	if err != nil {
		if InvalidGrant(err) && stored != nil && used != nil && used.RefreshToken == stored.RefreshToken {
			k.delete()
		}
		return nil, err
	}
	k.save(token)
	return token, nil
}

// Save stores the refresh token of token, after a login. Failures are only logged:
// the token is valid, only the next run will have to log in.
func (k *Keeper) Save(ctx context.Context, token *oauth2.Token) {
	if k == nil || token == nil {
		return
	}
	release := k.lock(ctx)
	if release == nil && ctx.Err() != nil {
		return
	}
	defer release()
	k.save(token)
}

// lock takes the lock of the key, or returns a no-op when there is no lock. It returns
// nil only when ctx is done.
func (k *Keeper) lock(ctx context.Context) func() {
	if k.lockPath == "" {
		return func() {}
	}
	release, err := lockFile(ctx, k.lockPath)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		log.Warn().Err(err).Msg("Using the stored refresh token without lock")
		return func() {}
	}
	return release
}

// load returns the stored entry, nil if there is none or it is unusable.
func (k *Keeper) load() *Entry {
	e, err := k.backend.Load(k.key)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil
	case err != nil:
		log.Warn().Err(err).Str("store", k.backend.Name()).Msg("Failed to read the stored refresh token")
		return nil
	case e.Expired():
		log.Debug().Time("expired", e.RefreshExpiry).Msg("The stored refresh token expired")
		k.delete()
		return nil
	}
	return e
}

func (k *Keeper) save(token *oauth2.Token) {
	if token.RefreshToken == "" {
		return
	}
	e := &Entry{RefreshToken: token.RefreshToken, RefreshExpiry: RefreshExpiry(token, time.Now())}
	if err := k.backend.Save(k.key, e); err != nil {
		log.Warn().Err(err).Str("store", k.backend.Name()).Msg("Failed to store the refresh token: the next run will have to log in")
		return
	}
	k.mu.Lock()
	k.seen = e.RefreshToken
	k.mu.Unlock()
	log.Debug().Str("store", k.backend.Name()).Msg("Refresh token stored")
}

func (k *Keeper) delete() {
	if err := k.backend.Delete(k.key); err != nil {
		log.Warn().Err(err).Str("store", k.backend.Name()).Msg("Failed to delete the stored refresh token")
	}
}

// InvalidGrant reports whether a refresh failed because the refresh token is no longer
// valid (session expired or revoked), rather than for a transient reason.
func InvalidGrant(err error) bool {
	var re *oauth2.RetrieveError
	return errors.As(err, &re) && re.ErrorCode == "invalid_grant"
}

// RefreshExpiry returns when the refresh token of token expires, from the
// refresh_expires_in field (Keycloak) of a response received at receivedAt. It is
// zero when unknown, or when the refresh token does not expire (offline token: 0).
func RefreshExpiry(token *oauth2.Token, receivedAt time.Time) time.Time {
	if token == nil {
		return time.Time{}
	}
	var seconds float64
	switch v := token.Extra("refresh_expires_in").(type) {
	case float64:
		seconds = v
	case int64:
		seconds = float64(v)
	case int:
		seconds = float64(v)
	case json.Number:
		seconds, _ = v.Float64()
	case string:
		seconds, _ = strconv.ParseFloat(v, 64)
	}
	if seconds <= 0 {
		return time.Time{}
	}
	return receivedAt.Add(time.Duration(seconds * float64(time.Second)))
}
