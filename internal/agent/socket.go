package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// SocketEnv overrides the socket path, like SSH_AUTH_SOCK for ssh-agent.
const SocketEnv = "AUTHK_SOCK"

// Dir returns the per-user directory holding agent sockets and registry entries.
// Unix socket paths are limited to about 100 bytes, so it must stay short.
func Dir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "authk")
	}
	if runtime.GOOS == "windows" {
		if dir, err := os.UserCacheDir(); err == nil {
			return filepath.Join(dir, "authk")
		}
	}
	return filepath.Join(os.TempDir(), "authk-"+strconv.Itoa(os.Getuid()))
}

// CanonicalPath returns an absolute path with symlinks resolved when possible, so that
// the same file always gives the same agent ID.
func CanonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path %s: %w", path, err)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	return abs, nil
}

// ID identifies an agent by what it serves: the config file, plus the .env file when
// the config has no targets (envFile is empty otherwise), plus a custom socket path
// (AUTHK_SOCK). Paths must be canonical.
func ID(configPath, envFile, customSocket string) string {
	id := shortHash(configPath)
	if envFile == "" && customSocket == "" {
		return id
	}
	return id + "-" + shortHash(envFile+"\x00"+customSocket)
}

// SocketFor returns the socket path of the agent id: AUTHK_SOCK if set, otherwise a
// socket in Dir().
func SocketFor(id string) string {
	if p := os.Getenv(SocketEnv); p != "" {
		return p
	}
	return filepath.Join(Dir(), id+".sock")
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}

// ensurePrivateDir creates dir, private to the user, and checks that nobody else can use it.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	// In a shared directory like /tmp, another user could have created it first
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("directory %s is accessible by other users (mode %o)", dir, perm)
	}
	if !ownedByCurrentUser(info) {
		return fmt.Errorf("directory %s is not owned by the current user", dir)
	}
	return nil
}
