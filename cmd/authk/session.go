package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/codozor/authk/internal/agent"
	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/oidc"
	"github.com/codozor/authk/internal/tokenstore"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

// session is the OIDC client of a profile with its stored refresh token (interactive
// flows): it logs in only when the stored session cannot be refreshed.
type session struct {
	*oidc.Client
	keeper *tokenstore.Keeper // nil: nothing stored
}

// newSession returns the session of a profile.
func newSession(p *config.Profile) (*session, error) {
	client, err := newOIDCClient(p)
	if err != nil {
		return nil, err
	}
	s := &session{Client: client}
	if !client.Interactive() {
		return s, nil
	}
	backend, err := tokenstore.Open(p.TokenStore)
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", p.Name, err)
	}
	configPath, err := agent.CanonicalPath(cfgFile)
	if err != nil {
		return nil, err
	}
	s.keeper = tokenstore.NewKeeper(backend, tokenstore.Key(p, configPath))
	log.Debug().Str("store", s.keeper.Backend()).Msg("Refresh token store")
	return s, nil
}

// RefreshToken refreshes old, or the stored session when old is nil or older.
func (s *session) RefreshToken(ctx context.Context, old *oauth2.Token) (*oauth2.Token, error) {
	return s.keeper.Refresh(ctx, old, s.Client.RefreshToken)
}

// GetToken returns a new token. For an interactive flow, it first refreshes the stored
// session, and logs in only if there is none or it expired.
func (s *session) GetToken(ctx context.Context) (*oauth2.Token, error) {
	if !s.Interactive() {
		return s.Client.GetToken(ctx)
	}
	token, err := s.restore(ctx)
	if err != nil || token != nil {
		return token, err
	}
	if token, err = s.Client.GetToken(ctx); err != nil {
		return nil, err
	}
	s.keeper.Save(ctx, token)
	return token, nil
}

// restore refreshes the stored session of an interactive flow. It returns a nil token
// when a login is needed.
func (s *session) restore(ctx context.Context) (*oauth2.Token, error) {
	if s.keeper == nil {
		return nil, nil
	}
	token, err := s.RefreshToken(ctx, nil)
	switch {
	case err == nil:
		log.Info().Str("store", s.keeper.Backend()).Msg("Session restored from the stored refresh token")
		return token, nil
	case errors.Is(err, oidc.ErrNoRefreshToken):
		return nil, nil
	case tokenstore.InvalidGrant(err):
		log.Info().Err(err).Msg("The stored session expired: login required")
		return nil, nil
	}
	return nil, fmt.Errorf("failed to refresh the stored session: %w", err)
}

// login adapts the interactive login for the agent refresher, storing the new session.
func (s *session) login() agent.LoginFunc {
	start := agentLogin(s.Client)
	return func(ctx context.Context) (*agent.LoginSession, error) {
		ls, err := start(ctx)
		if err != nil {
			return nil, err
		}
		wait := ls.Wait
		ls.Wait = func(ctx context.Context) (*oauth2.Token, error) {
			token, err := wait(ctx)
			if err == nil {
				s.keeper.Save(ctx, token)
			}
			return token, err
		}
		return ls, nil
	}
}
