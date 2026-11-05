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

// SocketPath returns the socket of the agent serving configPath.
// One agent runs per config file: the name is derived from its absolute path.
func SocketPath(configPath string) (string, error) {
	if p := os.Getenv(SocketEnv); p != "" {
		return p, nil
	}

	abs, err := filepath.Abs(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve config path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(socketDir(), hex.EncodeToString(sum[:])[:16]+".sock"), nil
}

// socketDir returns a per-user directory for sockets. Unix socket paths are limited to
// about 100 bytes, so it must stay short.
func socketDir() string {
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

// ensureSocketDir creates the socket directory, private to the user.
func ensureSocketDir(socket string) error {
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
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
		return fmt.Errorf("socket directory %s is accessible by other users (mode %o)", dir, perm)
	}
	if !ownedByCurrentUser(info) {
		return fmt.Errorf("socket directory %s is not owned by the current user", dir)
	}
	return nil
}
