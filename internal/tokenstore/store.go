// Package tokenstore keeps the refresh token of an interactive flow between runs, in
// the OS keyring or in a private file, so that the user does not log in again.
package tokenstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/codozor/authk/internal/config"
	"github.com/rs/zerolog/log"
)

// ErrNotFound is returned by Backend.Load when nothing is stored for the key.
var ErrNotFound = errors.New("no stored refresh token")

// Entry is what is stored for a profile.
type Entry struct {
	RefreshToken  string    `json:"refreshToken"`
	RefreshExpiry time.Time `json:"refreshExpiry,omitzero"` // zero: unknown or none
}

// Expired reports whether the refresh token is known to be expired.
func (e *Entry) Expired() bool {
	return !e.RefreshExpiry.IsZero() && !time.Now().Before(e.RefreshExpiry)
}

// Backend stores entries by key.
type Backend interface {
	Name() string
	Load(key string) (*Entry, error) // ErrNotFound if nothing is stored
	Save(key string, e *Entry) error
	Delete(key string) error // nil if nothing is stored
}

// Open returns the backend of a tokenStore value, nil for "none". "auto" is the
// keyring when it is available, the file otherwise.
func Open(kind string) (Backend, error) {
	switch kind {
	case config.StoreNone:
		return nil, nil
	case config.StoreFile:
		return newFileBackend()
	case config.StoreKeyring:
		k := newKeyringBackend()
		if err := k.probe(); err != nil {
			return nil, fmt.Errorf("the OS keyring is not available (use tokenStore \"file\" or \"auto\"): %w", err)
		}
		return k, nil
	case config.StoreAuto, "":
		k := newKeyringBackend()
		err := k.probe()
		if err == nil {
			return k, nil
		}
		// A machine without desktop session (SSH, container) usually has no keyring
		log.Debug().Err(err).Msg("OS keyring not available, storing the refresh token in a file")
		return newFileBackend()
	}
	return nil, fmt.Errorf("unknown tokenStore %q", kind)
}

// Key identifies the session of a profile: the provider, the client and the scopes
// (a token for other scopes must not be reused), and the config file and profile.
// configPath must be canonical.
func Key(p *config.Profile, configPath string) string {
	scopes := slices.Clone(p.Scopes)
	slices.Sort(scopes)
	parts := []string{p.Issuer, p.ClientID, strings.Join(scopes, " "), configPath, p.Name}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])[:16]
}

// Dir returns the per-user directory of the token files and locks: $XDG_STATE_HOME/authk,
// ~/.local/state/authk on Unix, the local application data on Windows and macOS.
func Dir() (string, error) {
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "authk"), nil
	}
	switch runtime.GOOS {
	case "windows":
		dir, err := os.UserCacheDir() // %LocalAppData%: not roaming
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "authk"), nil
	case "darwin":
		dir, err := os.UserConfigDir() // ~/Library/Application Support
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "authk"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "authk"), nil
}

func encode(e *Entry) (string, error) {
	data, err := json.Marshal(e)
	return string(data), err
}

func decode(s string) (*Entry, error) {
	var e Entry
	if err := json.Unmarshal([]byte(s), &e); err != nil {
		return nil, fmt.Errorf("invalid stored token: %w", err)
	}
	if e.RefreshToken == "" {
		return nil, errors.New("invalid stored token: no refresh token")
	}
	return &e, nil
}
