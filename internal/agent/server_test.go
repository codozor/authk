package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// shortSocket returns a socket path short enough for the ~100 bytes limit.
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ak")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "a.sock")
}

// serveOn listens on socket and serves r until ctx is cancelled.
func serveOn(ctx context.Context, socket string, r *Refresher, info Info, stop func()) error {
	ln, err := Listen(socket)
	if err != nil {
		return err
	}
	return Serve(ctx, ln, r, info, stop)
}

// startAgent serves r on a new socket until the test ends.
func startAgent(t *testing.T, r *Refresher) (*Client, *atomic.Bool) {
	t.Helper()
	socket := shortSocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := &atomic.Bool{}
	done := make(chan error, 1)
	go func() {
		done <- serveOn(ctx, socket, r, Info{ConfigPath: "/x/authk.cue", Issuer: "https://idp", ClientID: "cli"}, func() {
			stopped.Store(true)
			cancel()
		})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve() error = %v", err)
		}
	})

	client := NewClient(socket)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := client.Status(context.Background()); err == nil {
			return client, stopped
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func tokenWithID(access, id string, lifetime time.Duration) *oauth2.Token {
	tok := &oauth2.Token{AccessToken: access, RefreshToken: "rt", Expiry: time.Now().Add(lifetime)}
	if id != "" {
		tok = tok.WithExtra(map[string]interface{}{"id_token": id})
	}
	return tok
}

func TestServer_Token(t *testing.T) {
	fc := &fakeClient{lifetime: time.Hour, refreshToken: "rt"}
	client, _ := startAgent(t, NewRefresher(fc, tokenWithID("access-1", "id-1", time.Hour), nil))
	ctx := context.Background()

	resp, err := client.Token(ctx, TypeAccessToken, 0)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Token != "access-1" || resp.Type != TypeAccessToken || resp.Expiry.IsZero() {
		t.Errorf("unexpected response %+v", resp)
	}

	resp, err = client.Token(ctx, TypeIDToken, 0)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Token != "id-1" {
		t.Errorf("id token = %q", resp.Token)
	}

	if _, err := client.Token(ctx, "refresh_token", 0); err == nil || !strings.Contains(err.Error(), "unknown token type") {
		t.Errorf("expected an unknown type error, got %v", err)
	}
	if _, refreshes := fc.counts(); refreshes != 0 {
		t.Errorf("a valid token must be served without renewal, got %d refreshes", refreshes)
	}
}

func TestServer_TokenMinTTLRenews(t *testing.T) {
	fc := &fakeClient{lifetime: time.Hour, refreshToken: "rt"}
	client, _ := startAgent(t, NewRefresher(fc, tokenWithID("old", "", 20*time.Second), nil))

	resp, err := client.Token(context.Background(), TypeAccessToken, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, refreshes := fc.counts(); refreshes != 1 {
		t.Errorf("expected 1 refresh, got %d", refreshes)
	}
	if time.Until(resp.Expiry) < 59*time.Minute {
		t.Errorf("expected the renewed token, expiry %v", resp.Expiry)
	}
}

func TestServer_TokenMissingID(t *testing.T) {
	fc := &fakeClient{lifetime: time.Hour}
	client, _ := startAgent(t, NewRefresher(fc, tokenWithID("a", "", time.Hour), nil))

	_, err := client.Token(context.Background(), TypeIDToken, 0)
	if err == nil || !strings.Contains(err.Error(), "no ID Token") {
		t.Errorf("expected a missing ID Token error, got %v", err)
	}
}

func TestServer_ExpiredTokenRenewalFails(t *testing.T) {
	fc := &fakeClient{lifetime: time.Hour, getErr: errors.New("provider down")}
	expired := &oauth2.Token{AccessToken: "a", Expiry: time.Now().Add(-time.Minute)}
	client, _ := startAgent(t, NewRefresher(fc, expired, nil))

	_, err := client.Token(context.Background(), TypeAccessToken, 0)
	if err == nil || !strings.Contains(err.Error(), "provider down") {
		t.Errorf("expected the renewal error, got %v", err)
	}
}

func TestServer_StatusRefreshStop(t *testing.T) {
	fc := &fakeClient{lifetime: time.Hour, refreshToken: "rt"}
	client, stopped := startAgent(t, NewRefresher(fc, tokenWithID("a", "i", time.Hour), nil))
	ctx := context.Background()

	st, err := client.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.PID != os.Getpid() || st.Issuer != "https://idp" || !st.HasRefreshToken || !st.HasIDToken {
		t.Errorf("unexpected status %+v", st)
	}

	if _, err := client.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, refreshes := fc.counts(); refreshes != 1 {
		t.Errorf("expected 1 refresh, got %d", refreshes)
	}

	if err := client.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !stopped.Load() {
		if time.Now().After(deadline) {
			t.Fatal("stop was not called")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServer_AlreadyRunning(t *testing.T) {
	fc := &fakeClient{lifetime: time.Hour}
	r := NewRefresher(fc, tokenWithID("a", "", time.Hour), nil)
	client, _ := startAgent(t, r)

	err := serveOn(context.Background(), client.socket, r, Info{}, func() {})
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("expected ErrAlreadyRunning, got %v", err)
	}
}

func TestClient_NotRunning(t *testing.T) {
	socket := shortSocket(t)

	// No socket file
	if _, err := NewClient(socket).Status(context.Background()); !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning, got %v", err)
	}

	// Stale socket left by a crashed agent
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	if _, err := NewClient(socket).Status(context.Background()); !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning on a stale socket, got %v", err)
	}

	// A new agent replaces the stale socket
	fc := &fakeClient{lifetime: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveOn(ctx, socket, NewRefresher(fc, tokenWithID("a", "", time.Hour), nil), Info{}, cancel)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := NewClient(socket).Status(context.Background()); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not replace the stale socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestIDAndSocket(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	t.Setenv(SocketEnv, "")

	a := ID("/projects/a/authk.cue", "default", "", "")
	if a != ID("/projects/a/authk.cue", "default", "", "") {
		t.Error("ID must be stable")
	}
	if a != ID("/projects/a/authk.cue", "", "", "") {
		t.Error("the default profile must keep the ID of a version 1 config")
	}
	if a == ID("/projects/b/authk.cue", "default", "", "") {
		t.Error("configs must give different IDs")
	}
	if ID("/projects/a/authk.cue", "dev", "", "") == ID("/projects/a/authk.cue", "prod", "", "") {
		t.Error("profiles must give different IDs")
	}
	front := ID("/projects/a/authk.cue", "default", "/projects/a/front/.env", "")
	back := ID("/projects/a/authk.cue", "default", "/projects/a/back/.env", "")
	if front == back || !strings.HasPrefix(front, a+"-") {
		t.Errorf("env files must give different IDs sharing the config prefix: %s %s %s", a, front, back)
	}
	if ID("/projects/a/authk.cue", "default", "", "/custom.sock") == a {
		t.Error("a custom socket must give a different ID")
	}

	if got, want := SocketFor(a), filepath.Join("/run/user/1000", "authk", a+".sock"); got != want {
		t.Errorf("SocketFor() = %s, want %s", got, want)
	}
	t.Setenv(SocketEnv, "/custom.sock")
	if got := SocketFor(a); got != "/custom.sock" {
		t.Errorf("%s must override the socket, got %s", SocketEnv, got)
	}
}

func TestEnsureSocketDir_RejectsSharedDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := filepath.Join(t.TempDir(), "authk")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(dir); err == nil {
		t.Error("a directory readable by others must be rejected")
	}
}

func TestServer_InteractiveLogin(t *testing.T) {
	r := testRefresher(&fakeClient{lifetime: time.Hour}, nil, nil)
	fl := newFakeLogin(&oauth2.Token{AccessToken: "logged", Expiry: time.Now().Add(time.Hour)})
	r.SetLogin(fl.login)
	client, _ := startAgent(t, r)
	ctx := context.Background()

	_, err := client.Token(ctx, TypeAccessToken, 0)
	if !errors.Is(err, ErrLoginRequired) || !strings.Contains(err.Error(), "authk agent login") {
		t.Fatalf("Token() before login error = %v, want ErrLoginRequired with a hint", err)
	}
	if _, err := client.Refresh(ctx); !errors.Is(err, ErrLoginRequired) {
		t.Errorf("Refresh() before login error = %v, want ErrLoginRequired", err)
	}
	st, err := client.Status(ctx)
	if err != nil || st.Ready || !st.LoginRequired {
		t.Fatalf("Status() before login = %+v, %v", st, err)
	}

	prompt, err := client.Login(ctx)
	if err != nil || prompt.Code != "ABCD" {
		t.Fatalf("Login() = %+v, %v", prompt, err)
	}
	if st, _ := client.Status(ctx); st.Login == nil || st.Login.URL != "https://idp/device" {
		t.Errorf("pending login not in status: %+v", st)
	}

	fl.release <- nil
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := client.Token(ctx, TypeAccessToken, 0)
		if err == nil {
			if resp.Token != "logged" {
				t.Errorf("token = %q", resp.Token)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no token after login: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st, _ := client.Status(ctx); !st.Ready || st.LoginRequired || st.Login != nil {
		t.Errorf("status after login = %+v", st)
	}
}

func TestServer_LoginNonInteractive(t *testing.T) {
	client, _ := startAgent(t, testRefresher(&fakeClient{}, tokenWithID("a", "", time.Hour), nil))
	if _, err := client.Login(context.Background()); err == nil {
		t.Error("expected an error for a non-interactive flow")
	}
}

func TestServer_LoginComplete(t *testing.T) {
	r := testRefresher(&fakeClient{lifetime: time.Hour}, nil, nil)
	fl := newFakeLogin(&oauth2.Token{AccessToken: "pasted", Expiry: time.Now().Add(time.Hour)})
	r.SetLogin(fl.login)
	client, _ := startAgent(t, r)
	ctx := context.Background()

	if err := client.CompleteLogin(ctx, "http://127.0.0.1/callback?code=c"); err == nil {
		t.Error("CompleteLogin() without a pending login must fail")
	}
	if _, err := client.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.CompleteLogin(ctx, "http://127.0.0.1/callback?code=c&state=s"); err != nil {
		t.Fatalf("CompleteLogin() error = %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if resp, err := client.Token(ctx, TypeAccessToken, 0); err == nil {
			if resp.Token != "pasted" {
				t.Errorf("token = %q", resp.Token)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no token after CompleteLogin")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
