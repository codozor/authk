package tokenstore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// fileBackend stores each entry in a file readable only by the user, like the tokens
// written to .env files.
type fileBackend struct {
	dir string
}

func newFileBackend() (*fileBackend, error) {
	dir, err := Dir()
	if err != nil {
		return nil, fmt.Errorf("failed to find the token directory: %w", err)
	}
	return &fileBackend{dir: filepath.Join(dir, "tokens")}, nil
}

func (*fileBackend) Name() string { return "file" }

func (f *fileBackend) path(key string) string {
	return filepath.Join(f.dir, key+".json")
}

func (f *fileBackend) Load(key string) (*Entry, error) {
	data, err := os.ReadFile(f.path(key))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return decode(string(data))
}

// Save writes the entry atomically: a crash never leaves a truncated file.
func (f *fileBackend) Save(key string, e *Entry) error {
	if err := ensurePrivateDir(f.dir); err != nil {
		return err
	}
	s, err := encode(e)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(f.dir, key+".*.tmp") // created with mode 0600
	if err != nil {
		return fmt.Errorf("failed to write the token file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(s); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write the token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to write the token file: %w", err)
	}
	if err := os.Rename(tmp.Name(), f.path(key)); err != nil {
		return fmt.Errorf("failed to write the token file: %w", err)
	}
	return nil
}

func (f *fileBackend) Delete(key string) error {
	if err := os.Remove(f.path(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
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
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("directory %s is accessible by other users (mode %o): run chmod 700 on it", dir, perm)
	}
	return nil
}
