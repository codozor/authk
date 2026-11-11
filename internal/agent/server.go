package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/codozor/authk/internal/tokenstore"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

// ErrAlreadyRunning is returned by Listen when another agent listens on the socket,
// i.e. already serves the same config (and .env file).
var ErrAlreadyRunning = errors.New("an agent is already running for this config and .env file")

// renewTimeout bounds an on-demand renewal (the OIDC HTTP client times out after 30s).
const renewTimeout = 35 * time.Second

// Info describes what the agent serves, for status reporting.
type Info struct {
	ID          string
	Name        string
	LogFile     string
	ConfigPath  string
	Profile     string
	Issuer      string
	ClientID    string
	Targets     []string
	TargetFiles []string
	TokenStore  string // where the refresh token is stored (interactive flows)
}

type server struct {
	ctx       context.Context // lifetime of the agent, used for renewals
	refresher *Refresher
	info      Info
	startedAt time.Time
	stop      func()
}

// Serve answers requests on ln (see Listen) until ctx is cancelled. stop is called when
// a client asks the agent to stop (POST /v1/stop); it should cancel ctx.
func Serve(ctx context.Context, ln net.Listener, r *Refresher, info Info, stop func()) error {
	s := &server{ctx: ctx, refresher: r, info: info, startedAt: time.Now(), stop: stop}
	srv := &http.Server{Handler: s.routes(), ReadHeaderTimeout: 5 * time.Second}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info().Str("socket", ln.Addr().String()).Str("id", info.ID).Msg("Agent listening")
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("agent server failed: %w", err)
	}
	return nil
}

// Listen creates the agent socket, replacing a stale one left by an agent that crashed.
// It returns ErrAlreadyRunning if another agent listens on it.
func Listen(socket string) (net.Listener, error) {
	if err := ensurePrivateDir(filepath.Dir(socket)); err != nil {
		return nil, err
	}
	if _, err := os.Stat(socket); err == nil {
		conn, err := net.DialTimeout("unix", socket, time.Second)
		if err == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w (socket %s)", ErrAlreadyRunning, socket)
		}
		if err := os.Remove(socket); err != nil {
			return nil, fmt.Errorf("failed to remove stale socket: %w", err)
		}
	}

	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", socket, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(socket, 0o600); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("failed to set socket permissions: %w", err)
		}
	}
	return ln, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/token", s.handleToken)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("POST /v1/refresh", s.handleRefresh)
	mux.HandleFunc("POST /v1/stop", s.handleStop)
	mux.HandleFunc("POST /v1/login", s.handleLogin)
	mux.HandleFunc("POST /v1/login/complete", s.handleLoginComplete)
	return mux
}

// handleToken serves the current token. With min_ttl, a token expiring sooner is renewed first.
func (s *server) handleToken(w http.ResponseWriter, req *http.Request) {
	typ := req.URL.Query().Get("type")
	if typ == "" {
		typ = TypeAccessToken
	}
	if typ != TypeAccessToken && typ != TypeIDToken {
		writeError(w, http.StatusBadRequest, fmt.Errorf("unknown token type %q", typ))
		return
	}
	var minTTL time.Duration
	if v := req.URL.Query().Get("min_ttl"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid min_ttl %q", v))
			return
		}
		minTTL = d
	}

	token := s.refresher.Current()
	if token == nil {
		s.writeLoginRequired(w, ErrLoginRequired)
		return
	}
	if expiresWithin(token, minTTL) {
		renewed, err := s.renew(token)
		if errors.Is(err, ErrLoginRequired) {
			s.writeLoginRequired(w, err)
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("failed to renew token: %w", err))
			return
		}
		token = renewed
	}
	if expiresWithin(token, 0) {
		writeError(w, http.StatusServiceUnavailable, errors.New("token is expired and could not be renewed"))
		return
	}

	resp := TokenResponse{Type: typ, Expiry: token.Expiry}
	if typ == TypeIDToken {
		idToken, ok := token.Extra("id_token").(string)
		if !ok || idToken == "" {
			writeJSON(w, http.StatusNotFound, errorResponse{Error: ErrNoIDToken.Error(), Code: codeNoIDToken})
			return
		}
		resp.Token = idToken
	} else {
		resp.Token = token.AccessToken
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.status())
}

func (s *server) handleRefresh(w http.ResponseWriter, _ *http.Request) {
	_, err := s.renew(nil)
	if errors.Is(err, ErrLoginRequired) {
		s.writeLoginRequired(w, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("failed to renew token: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, s.status())
}

// handleLogin starts an interactive login (or returns the pending one) and returns its
// prompt at once: the client then follows the login through the status.
func (s *server) handleLogin(w http.ResponseWriter, req *http.Request) {
	l, err := s.refresher.StartLogin(req.Context(), s.ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("failed to start login: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, l.Prompt)
}

// handleLoginComplete finishes the pending browser login with the redirect URL pasted
// by the user.
func (s *server) handleLoginComplete(w http.ResponseWriter, req *http.Request) {
	var body loginCompleteRequest
	if err := json.NewDecoder(io.LimitReader(req.Body, 64<<10)).Decode(&body); err != nil || body.URL == "" {
		writeError(w, http.StatusBadRequest, errors.New("expected {\"url\": \"<redirect URL>\"}"))
		return
	}
	if err := s.refresher.CompleteLogin(body.URL); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.status())
}

// writeLoginRequired tells the client that the user must log in, and how.
func (s *server) writeLoginRequired(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusServiceUnavailable, errorResponse{
		Error: fmt.Sprintf("%v: run \"authk agent login %s\"", err, s.info.Name),
		Code:  codeLoginRequired,
	})
}

func (s *server) handleStop(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusAccepted)
	log.Info().Msg("Stop requested by a client")
	go s.stop()
}

// renew renews on demand with the agent lifetime context, not the request one: a client
// disconnecting must not abort a renewal that may already have consumed the refresh token.
func (s *server) renew(seen *oauth2.Token) (*oauth2.Token, error) {
	ctx, cancel := context.WithTimeout(s.ctx, renewTimeout)
	defer cancel()
	return s.refresher.Renew(ctx, seen)
}

func (s *server) status() Status {
	state := s.refresher.State()
	st := Status{
		ID:            s.info.ID,
		Name:          s.info.Name,
		LogFile:       s.info.LogFile,
		PID:           os.Getpid(),
		ConfigPath:    s.info.ConfigPath,
		Profile:       s.info.Profile,
		Issuer:        s.info.Issuer,
		ClientID:      s.info.ClientID,
		Targets:       s.info.Targets,
		TargetFiles:   s.info.TargetFiles,
		StartedAt:     s.startedAt,
		LastRenewal:   state.LastRenewal,
		LoginRequired: state.LoginRequired,
		Login:         state.Login,
		TokenStore:    s.info.TokenStore,
	}
	if state.Token != nil {
		st.Ready = true
		st.Expiry = state.Token.Expiry
		st.HasRefreshToken = state.Token.RefreshToken != ""
		idToken, _ := state.Token.Extra("id_token").(string)
		st.HasIDToken = idToken != ""
		st.SessionExpiry = tokenstore.RefreshExpiry(state.Token, state.LastRenewal)
	}
	if state.LastErr != nil {
		st.LastError = state.LastErr.Error()
	}
	return st
}

// expiresWithin reports whether token expires in less than d. A token without expiry never does.
func expiresWithin(token *oauth2.Token, d time.Duration) bool {
	if token.Expiry.IsZero() {
		return false
	}
	return time.Until(token.Expiry.Round(0)) < d
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, errorResponse{Error: err.Error()})
}
