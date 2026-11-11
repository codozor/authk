package tokenstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/codozor/authk/internal/config"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

// memBackend is an in-memory backend.
type memBackend struct {
	mu      sync.Mutex
	entries map[string]Entry
	saveErr error
}

func newMem() *memBackend { return &memBackend{entries: map[string]Entry{}} }

func (*memBackend) Name() string { return "mem" }

func (m *memBackend) Load(key string) (*Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok {
		return nil, ErrNotFound
	}
	return &e, nil
}

func (m *memBackend) Save(key string, e *Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.entries[key] = *e
	return nil
}

func (m *memBackend) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
	return nil
}

func (m *memBackend) stored(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.entries[key].RefreshToken
}

// provider simulates refresh token rotation: each refresh token works once.
type provider struct {
	mu    sync.Mutex
	valid map[string]bool
	n     int
	used  []string
}

func newProvider(valid ...string) *provider {
	p := &provider{valid: map[string]bool{}}
	for _, rt := range valid {
		p.valid[rt] = true
	}
	return p
}

func (p *provider) refresh(_ context.Context, old *oauth2.Token) (*oauth2.Token, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if old == nil || old.RefreshToken == "" {
		return nil, errNoRT
	}
	p.used = append(p.used, old.RefreshToken)
	if !p.valid[old.RefreshToken] {
		return nil, &oauth2.RetrieveError{ErrorCode: "invalid_grant"}
	}
	delete(p.valid, old.RefreshToken)
	p.n++
	rt := "rt" + string(rune('0'+p.n))
	p.valid[rt] = true
	return &oauth2.Token{AccessToken: "at", RefreshToken: rt}, nil
}

var errNoRT = errors.New("no refresh token")

func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
}

func TestKeeper_RestoresAndRotates(t *testing.T) {
	isolate(t)
	mem := newMem()
	p := newProvider("rt0")
	_ = mem.Save("k", &Entry{RefreshToken: "rt0"})

	k := NewKeeper(mem, "k")
	token, err := k.Refresh(context.Background(), nil, p.refresh)
	if err != nil {
		t.Fatal(err)
	}
	if token.RefreshToken != "rt1" || mem.stored("k") != "rt1" {
		t.Fatalf("got %q, stored %q, want rt1", token.RefreshToken, mem.stored("k"))
	}

	// The next refresh uses the current token (the stored one is the same)
	token, err = k.Refresh(context.Background(), token, p.refresh)
	if err != nil {
		t.Fatal(err)
	}
	if token.RefreshToken != "rt2" || mem.stored("k") != "rt2" {
		t.Fatalf("got %q, stored %q, want rt2", token.RefreshToken, mem.stored("k"))
	}
}

func TestKeeper_UsesNewerTokenOfAnotherProcess(t *testing.T) {
	isolate(t)
	mem := newMem()
	p := newProvider("rt0")
	_ = mem.Save("k", &Entry{RefreshToken: "rt0"})

	agentKeeper := NewKeeper(mem, "k")
	agentToken, err := agentKeeper.Refresh(context.Background(), nil, p.refresh)
	if err != nil {
		t.Fatal(err)
	}

	// Another process (authk get --direct) refreshes in between: rt1 is used up
	other := NewKeeper(mem, "k")
	if _, err := other.Refresh(context.Background(), nil, p.refresh); err != nil {
		t.Fatal(err)
	}

	// The agent must use the stored rt2, not its own rt1
	token, err := agentKeeper.Refresh(context.Background(), agentToken, p.refresh)
	if err != nil {
		t.Fatalf("refresh after another process: %v (used %v)", err, p.used)
	}
	if token.RefreshToken != "rt3" {
		t.Fatalf("got %q, want rt3", token.RefreshToken)
	}
}

func TestKeeper_KeepsOwnTokenWhenSaveFailed(t *testing.T) {
	isolate(t)
	mem := newMem()
	p := newProvider("rt0")
	_ = mem.Save("k", &Entry{RefreshToken: "rt0"})

	k := NewKeeper(mem, "k")
	token, err := k.Refresh(context.Background(), nil, p.refresh)
	if err != nil {
		t.Fatal(err)
	}
	mem.saveErr = errors.New("keyring locked")
	if token, err = k.Refresh(context.Background(), token, p.refresh); err != nil {
		t.Fatal(err)
	}
	// rt1 stays stored, but rt2 (in memory) is the valid one
	if token, err = k.Refresh(context.Background(), token, p.refresh); err != nil {
		t.Fatalf("stale stored token used: %v (used %v)", err, p.used)
	}
	if token.RefreshToken != "rt3" {
		t.Fatalf("got %q, want rt3", token.RefreshToken)
	}
}

func TestKeeper_InvalidGrantDeletesStoredToken(t *testing.T) {
	isolate(t)
	mem := newMem()
	_ = mem.Save("k", &Entry{RefreshToken: "revoked"})

	k := NewKeeper(mem, "k")
	_, err := k.Refresh(context.Background(), nil, newProvider().refresh)
	if !InvalidGrant(err) {
		t.Fatalf("expected invalid_grant, got %v", err)
	}
	if _, err := mem.Load("k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the rejected token is still stored: %v", err)
	}
}

func TestKeeper_ExpiredStoredToken(t *testing.T) {
	isolate(t)
	mem := newMem()
	_ = mem.Save("k", &Entry{RefreshToken: "rt0", RefreshExpiry: time.Now().Add(-time.Minute)})
	p := newProvider("rt0")

	_, err := NewKeeper(mem, "k").Refresh(context.Background(), nil, p.refresh)
	if !errors.Is(err, errNoRT) {
		t.Fatalf("expected no refresh token, got %v", err)
	}
	if len(p.used) != 0 {
		t.Fatalf("an expired token was sent: %v", p.used)
	}
	if _, err := mem.Load("k"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the expired token is still stored")
	}
}

func TestKeeper_SaveAfterLogin(t *testing.T) {
	isolate(t)
	mem := newMem()
	k := NewKeeper(mem, "k")
	token := &oauth2.Token{AccessToken: "at", RefreshToken: "rt"}
	token = token.WithExtra(map[string]any{"refresh_expires_in": float64(1800)})
	if err := k.Save(context.Background(), token); err != nil {
		t.Fatal(err)
	}

	e, err := mem.Load("k")
	if err != nil {
		t.Fatal(err)
	}
	if e.RefreshToken != "rt" {
		t.Fatalf("stored %q", e.RefreshToken)
	}
	if d := time.Until(e.RefreshExpiry); d < 29*time.Minute || d > 30*time.Minute {
		t.Fatalf("refresh expiry in %s, want 30m", d)
	}

	// No refresh token: nothing stored, the previous one is kept
	if err := k.Save(context.Background(), &oauth2.Token{AccessToken: "at"}); err != nil {
		t.Fatal(err)
	}
	if mem.stored("k") != "rt" {
		t.Fatal("a token without refresh token replaced the stored one")
	}
}

func TestKeeper_Nil(t *testing.T) {
	var k *Keeper
	p := newProvider("rt0")
	token, err := k.Refresh(context.Background(), &oauth2.Token{RefreshToken: "rt0"}, p.refresh)
	if err != nil || token.RefreshToken != "rt1" {
		t.Fatalf("got %v, %v", token, err)
	}
	if err := k.Save(context.Background(), token); err != nil { // no-op
		t.Fatal(err)
	}
	if k.Backend() != "none" {
		t.Fatalf("backend %q", k.Backend())
	}
	if NewKeeper(nil, "k") != nil {
		t.Fatal("NewKeeper(nil) must return nil")
	}
}

// Concurrent refreshes through separate keepers (separate processes) must never use
// the same refresh token twice.
func TestKeeper_ConcurrentRefreshesAreSerialized(t *testing.T) {
	isolate(t)
	mem := newMem()
	p := newProvider("rt0")
	_ = mem.Save("k", &Entry{RefreshToken: "rt0"})

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := NewKeeper(mem, "k").Refresh(context.Background(), nil, p.refresh)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("refresh failed: %v (used %v)", err, p.used)
		}
	}
}

func TestRefreshExpiry(t *testing.T) {
	at := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		extra any
		want  time.Time
	}{
		{"seconds", float64(600), at.Add(10 * time.Minute)},
		{"offline token", float64(0), time.Time{}},
		{"string", "60", at.Add(time.Minute)},
		{"absent", nil, time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &oauth2.Token{AccessToken: "at"}
			if tt.extra != nil {
				token = token.WithExtra(map[string]any{"refresh_expires_in": tt.extra})
			}
			if got := RefreshExpiry(token, at); !got.Equal(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
	if !RefreshExpiry(nil, at).IsZero() {
		t.Fatal("nil token")
	}
}

func TestFileBackend(t *testing.T) {
	isolate(t)
	f, err := newFileBackend()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Load("k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	want := Entry{RefreshToken: "rt", RefreshExpiry: time.Now().Add(time.Hour).Round(time.Second)}
	if err := f.Save("k", &want); err != nil {
		t.Fatal(err)
	}
	got, err := f.Load("k")
	if err != nil {
		t.Fatal(err)
	}
	if got.RefreshToken != want.RefreshToken || !got.RefreshExpiry.Equal(want.RefreshExpiry) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(f.path("k"))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("token file mode %o, want 600", perm)
		}
		dir, _ := os.Stat(filepath.Dir(f.path("k")))
		if perm := dir.Mode().Perm(); perm != 0o700 {
			t.Fatalf("token dir mode %o, want 700", perm)
		}
	}
	if err := f.Delete("k"); err != nil {
		t.Fatal(err)
	}
	if err := f.Delete("k"); err != nil {
		t.Fatalf("deleting a missing entry: %v", err)
	}
	if _, err := f.Load("k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestFileBackend_CorruptFile(t *testing.T) {
	isolate(t)
	f, _ := newFileBackend()
	if err := ensurePrivateDir(f.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path("k"), []byte("{oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Load("k"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a decode error, got %v", err)
	}
}

func TestKeyringBackend(t *testing.T) {
	keyring.MockInit()
	k := &keyringBackend{kr: systemKeyring{}}
	if err := k.probe(); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Load("k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := k.Save("k", &Entry{RefreshToken: "rt"}); err != nil {
		t.Fatal(err)
	}
	e, err := k.Load("k")
	if err != nil || e.RefreshToken != "rt" {
		t.Fatalf("got %v, %v", e, err)
	}
	if err := k.Delete("k"); err != nil {
		t.Fatal(err)
	}
	if err := k.Delete("k"); err != nil {
		t.Fatalf("deleting a missing entry: %v", err)
	}
}

// slowKeyring never answers, like a locked keyring waiting for a password prompt.
type slowKeyring struct{ systemKeyring }

func (slowKeyring) Get(string, string) (string, error) {
	time.Sleep(time.Hour)
	return "", nil
}

func TestKeyringBackend_Timeout(t *testing.T) {
	old := keyringTimeout
	keyringTimeout = 50 * time.Millisecond
	t.Cleanup(func() { keyringTimeout = old })

	k := &keyringBackend{kr: slowKeyring{}}
	if err := k.probe(); err == nil {
		t.Fatal("expected a timeout")
	}
}

func TestOpen(t *testing.T) {
	isolate(t)
	keyring.MockInit()
	tests := map[string]string{
		config.StoreAuto:    "keyring",
		"":                  "keyring",
		config.StoreKeyring: "keyring",
		config.StoreFile:    "file",
	}
	for kind, want := range tests {
		b, err := Open(kind)
		if err != nil {
			t.Fatalf("%q: %v", kind, err)
		}
		if b.Name() != want {
			t.Fatalf("%q: got %s, want %s", kind, b.Name(), want)
		}
	}
	if b, err := Open(config.StoreNone); b != nil || err != nil {
		t.Fatalf("none: got %v, %v", b, err)
	}

	keyring.MockInitWithError(errors.New("no secret service"))
	if b, err := Open(config.StoreAuto); err != nil || b.Name() != "file" {
		t.Fatalf("auto without keyring: got %v, %v", b, err)
	}
	if _, err := Open(config.StoreKeyring); err == nil {
		t.Fatal("keyring without keyring: expected an error")
	}
	if _, err := Open("bogus"); err == nil {
		t.Fatal("expected an error for an unknown store")
	}
}

func TestKey(t *testing.T) {
	base := config.Profile{Name: "me", Issuer: "https://idp", ClientID: "cli", Scopes: []string{"openid", "email"}}
	key := Key(&base, "/etc/authk.cue")

	reordered := base
	reordered.Scopes = []string{"email", "openid"}
	if Key(&reordered, "/etc/authk.cue") != key {
		t.Fatal("the scope order must not change the key")
	}
	for name, p := range map[string]config.Profile{
		"issuer":  {Name: "me", Issuer: "https://other", ClientID: "cli", Scopes: base.Scopes},
		"client":  {Name: "me", Issuer: "https://idp", ClientID: "other", Scopes: base.Scopes},
		"scopes":  {Name: "me", Issuer: "https://idp", ClientID: "cli", Scopes: []string{"openid", "offline_access"}},
		"profile": {Name: "other", Issuer: "https://idp", ClientID: "cli", Scopes: base.Scopes},
	} {
		if Key(&p, "/etc/authk.cue") == key {
			t.Errorf("another %s must give another key", name)
		}
	}
	if Key(&base, "/other/authk.cue") == key {
		t.Error("another config file must give another key")
	}
}

func TestKeeper_Forget(t *testing.T) {
	isolate(t)
	mem := newMem()
	k := NewKeeper(mem, "k")
	if rt, err := k.Forget(context.Background()); rt != "" || err != nil {
		t.Fatalf("nothing stored: got %q, %v", rt, err)
	}
	_ = mem.Save("k", &Entry{RefreshToken: "rt0", RefreshExpiry: time.Now().Add(-time.Minute)})
	rt, err := k.Forget(context.Background())
	if rt != "rt0" || err != nil {
		t.Fatalf("got %q, %v; want the stored token, even expired", rt, err)
	}
	if _, err := mem.Load("k"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the session is still stored")
	}
	var nilKeeper *Keeper
	if rt, err := nilKeeper.Forget(context.Background()); rt != "" || err != nil {
		t.Fatalf("nil keeper: got %q, %v", rt, err)
	}
}
