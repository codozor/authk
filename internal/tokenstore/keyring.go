package tokenstore

import (
	"errors"
	"fmt"
	"time"

	"github.com/zalando/go-keyring"
)

// keyringService is the service name of the entries in the OS keyring.
const keyringService = "authk"

// keyringTimeout bounds every keyring call: a locked keyring may wait for a password
// prompt that nobody sees (detached agent, SSH session).
var keyringTimeout = 10 * time.Second

// keyringBackend stores entries in the OS keyring: Secret Service (GNOME Keyring,
// KWallet) on Linux, Keychain on macOS, Credential Manager on Windows.
type keyringBackend struct {
	kr keyring.Keyring
}

// systemKeyring calls the package functions of go-keyring, which use the OS keyring.
type systemKeyring struct{}

func (systemKeyring) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}
func (systemKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (systemKeyring) Delete(service, user string) error        { return keyring.Delete(service, user) }
func (systemKeyring) DeleteAll(service string) error           { return keyring.DeleteAll(service) }

func newKeyringBackend() *keyringBackend {
	return &keyringBackend{kr: systemKeyring{}}
}

func (*keyringBackend) Name() string { return "keyring" }

// probe checks that the keyring answers.
func (k *keyringBackend) probe() error {
	_, err := withTimeout(func() (string, error) { return k.kr.Get(keyringService, "probe") })
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}

func (k *keyringBackend) Load(key string) (*Entry, error) {
	s, err := withTimeout(func() (string, error) { return k.kr.Get(keyringService, key) })
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read the keyring: %w", err)
	}
	return decode(s)
}

func (k *keyringBackend) Save(key string, e *Entry) error {
	s, err := encode(e)
	if err != nil {
		return err
	}
	if _, err := withTimeout(func() (string, error) { return "", k.kr.Set(keyringService, key, s) }); err != nil {
		return fmt.Errorf("failed to write the keyring: %w", err)
	}
	return nil
}

func (k *keyringBackend) Delete(key string) error {
	_, err := withTimeout(func() (string, error) { return "", k.kr.Delete(keyringService, key) })
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("failed to delete from the keyring: %w", err)
	}
	return nil
}

// withTimeout runs f, giving up after keyringTimeout (f then keeps running in the
// background: keyring calls cannot be cancelled).
func withTimeout(f func() (string, error)) (string, error) {
	type result struct {
		s   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := f()
		ch <- result{s, err}
	}()
	timer := time.NewTimer(keyringTimeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.s, r.err
	case <-timer.C:
		return "", fmt.Errorf("the keyring did not answer within %s (locked?)", keyringTimeout)
	}
}
