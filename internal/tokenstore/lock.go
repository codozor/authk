package tokenstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

// errLocked is returned by tryLock when another process holds the lock.
var errLocked = errors.New("locked")

// lockPollInterval is how often a held lock is retried.
const lockPollInterval = 50 * time.Millisecond

// lockFile takes an exclusive lock on path, waiting until it is free or ctx is done.
// The lock is released by the returned function, or when the process exits.
func lockFile(ctx context.Context, path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}
	for {
		err := tryLock(f)
		if err == nil {
			return func() {
				_ = unlock(f)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, errLocked) {
			_ = f.Close()
			return nil, fmt.Errorf("failed to lock %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(lockPollInterval):
		}
	}
}
