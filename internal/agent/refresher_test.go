package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// fakeClient records calls and returns tokens valid for lifetime.
type fakeClient struct {
	mu           sync.Mutex
	lifetime     time.Duration
	refreshToken string // returned in new tokens
	getErr       error
	refreshErr   error
	gets         int
	refreshes    int
	refreshedAt  []time.Time
}

func (f *fakeClient) newToken() *oauth2.Token {
	return &oauth2.Token{AccessToken: "t", RefreshToken: f.refreshToken, Expiry: time.Now().Add(f.lifetime)}
}

func (f *fakeClient) GetToken(context.Context) (*oauth2.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.newToken(), nil
}

func (f *fakeClient) RefreshToken(_ context.Context, old *oauth2.Token) (*oauth2.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes++
	f.refreshedAt = append(f.refreshedAt, time.Now())
	if f.refreshErr != nil {
		return nil, f.refreshErr
	}
	return f.newToken(), nil
}

func (f *fakeClient) counts() (gets, refreshes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets, f.refreshes
}

func testRefresher(c TokenClient, token *oauth2.Token, onToken func(*oauth2.Token)) *Refresher {
	r := NewRefresher(c, token, onToken)
	r.RefreshBuffer = 200 * time.Millisecond
	r.MinDelay = 10 * time.Millisecond
	r.RetryDelay = 20 * time.Millisecond
	r.MaxRetryDelay = 40 * time.Millisecond
	r.CheckInterval = 10 * time.Millisecond
	return r
}

func TestRefresher_RefreshesBeforeExpiry(t *testing.T) {
	client := &fakeClient{lifetime: time.Second, refreshToken: "rt"}
	initial := client.newToken()

	var mu sync.Mutex
	updates := 0
	ctx, cancel := context.WithCancel(context.Background())
	r := testRefresher(client, initial, func(*oauth2.Token) {
		mu.Lock()
		updates++
		mu.Unlock()
		cancel() // stop after the first renewal
	})

	done := make(chan error)
	go func() { done <- r.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run() did not return")
	}

	gets, refreshes := client.counts()
	if refreshes != 1 || gets != 0 {
		t.Fatalf("expected 1 refresh and no full authentication, got refreshes=%d gets=%d", refreshes, gets)
	}
	if updates != 1 {
		t.Errorf("expected 1 target update, got %d", updates)
	}
	// Renewed refreshBuffer before expiry, not when the token is almost expired
	if margin := initial.Expiry.Sub(client.refreshedAt[0]); margin < 150*time.Millisecond || margin > 300*time.Millisecond {
		t.Errorf("refreshed %v before expiry, want about 200ms", margin)
	}
}

func TestRefresher_NoRefreshTokenReauthenticates(t *testing.T) {
	client := &fakeClient{lifetime: 300 * time.Millisecond} // client_credentials: no refresh token
	ctx, cancel := context.WithCancel(context.Background())
	r := testRefresher(client, client.newToken(), func(*oauth2.Token) { cancel() })

	if err := r.Run(ctx); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	gets, refreshes := client.counts()
	if gets != 1 || refreshes != 0 {
		t.Errorf("expected 1 full authentication and no refresh, got gets=%d refreshes=%d", gets, refreshes)
	}
}

func TestRefresher_RetriesAfterFailure(t *testing.T) {
	client := &fakeClient{lifetime: 100 * time.Millisecond, getErr: errors.New("provider down")}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	r := testRefresher(client, client.newToken(), func(*oauth2.Token) { t.Error("unexpected token update") })

	if err := r.Run(ctx); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	// ~350ms of failures with a 20ms delay doubled up to 40ms: several retries, no busy loop
	if gets, _ := client.counts(); gets < 3 || gets > 15 {
		t.Errorf("expected a few retries, got %d", gets)
	}
}

func TestRefresher_StopsOnCancel(t *testing.T) {
	client := &fakeClient{lifetime: time.Hour, refreshToken: "rt"}
	ctx, cancel := context.WithCancel(context.Background())
	r := testRefresher(client, client.newToken(), nil)

	done := make(chan error)
	go func() { done <- r.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("run() did not stop on cancel")
	}
}

func TestRefresher_NextRefresh(t *testing.T) {
	r := NewRefresher(nil, nil, nil)

	if _, ok := r.nextRefresh(&oauth2.Token{AccessToken: "t"}); ok {
		t.Error("a token without expiry must not be scheduled")
	}

	// Long-lived token: refreshBuffer before expiry
	expiry := time.Now().Add(5 * time.Minute)
	at, _ := r.nextRefresh(&oauth2.Token{Expiry: expiry})
	if d := expiry.Sub(at); d != 60*time.Second {
		t.Errorf("long-lived token renewed %v before expiry, want 60s", d)
	}

	// Short-lived token: at most half its lifetime before expiry
	expiry = time.Now().Add(40 * time.Second)
	at, _ = r.nextRefresh(&oauth2.Token{Expiry: expiry})
	if d := expiry.Sub(at); d < 19*time.Second || d > 21*time.Second {
		t.Errorf("short-lived token renewed %v before expiry, want about 20s", d)
	}

	// Expired token: not sooner than minDelay
	at, _ = r.nextRefresh(&oauth2.Token{Expiry: time.Now().Add(-time.Minute)})
	if d := time.Until(at); d < 9*time.Second {
		t.Errorf("expired token renewed in %v, want at least minDelay", d)
	}
}

func TestRefresher_RenewDeduplicates(t *testing.T) {
	client := &fakeClient{lifetime: time.Hour, refreshToken: "rt"}
	initial := client.newToken()
	r := testRefresher(client, initial, nil)

	// Concurrent callers that saw the same token: a single renewal
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Renew(context.Background(), initial); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, refreshes := client.counts(); refreshes != 1 {
		t.Errorf("expected 1 refresh, got %d", refreshes)
	}
	if r.Current() == initial {
		t.Error("current token was not replaced")
	}

	// nil always renews
	if _, err := r.Renew(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, refreshes := client.counts(); refreshes != 2 {
		t.Errorf("expected 2 refreshes, got %d", refreshes)
	}
}

func TestRefresher_OnDemandRenewReschedules(t *testing.T) {
	// Without rescheduling, the loop would renew at the old token schedule (~300ms)
	client := &fakeClient{lifetime: 500 * time.Millisecond, refreshToken: "rt"}
	r := testRefresher(client, client.newToken(), nil)
	r.RefreshBuffer = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- r.Run(ctx) }()

	time.Sleep(100 * time.Millisecond)
	if _, err := r.Renew(context.Background(), nil); err != nil { // new token expires at ~600ms
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond) // ~350ms: past the old schedule (~300ms), before the new one (~400ms)
	_, refreshes := client.counts()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if refreshes != 1 {
		t.Errorf("expected only the on-demand refresh, got %d refreshes", refreshes)
	}
}

func TestRefresher_State(t *testing.T) {
	client := &fakeClient{lifetime: time.Hour, getErr: errors.New("boom")}
	r := testRefresher(client, client.newToken(), nil)

	if _, err := r.Renew(context.Background(), nil); err == nil {
		t.Fatal("expected an error")
	}
	if st := r.State(); st.LastErr == nil || st.Token == nil {
		t.Errorf("state = %+v, want the error and the previous token", st)
	}
}

// fakeLogin is a LoginFunc whose logins end when release receives a result.
type fakeLogin struct {
	mu        sync.Mutex
	starts    int
	completed []string // URLs given to Complete, which then ends the login
	release   chan error
	token     *oauth2.Token
}

func newFakeLogin(token *oauth2.Token) *fakeLogin {
	return &fakeLogin{release: make(chan error, 1), token: token}
}

func (f *fakeLogin) login(context.Context) (*LoginSession, error) {
	f.mu.Lock()
	f.starts++
	f.mu.Unlock()
	prompt := LoginPrompt{URL: "https://idp/device", Code: "ABCD", Expiry: time.Now().Add(time.Minute)}
	complete := func(u string) error {
		if !strings.HasPrefix(u, "http://127.0.0.1/callback") {
			return errors.New("bad redirect")
		}
		f.mu.Lock()
		f.completed = append(f.completed, u)
		f.mu.Unlock()
		f.release <- nil
		return nil
	}
	return &LoginSession{Prompt: prompt, Complete: complete, Wait: func(ctx context.Context) (*oauth2.Token, error) {
		select {
		case err := <-f.release:
			if err != nil {
				return nil, err
			}
			return f.token, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}, nil
}

func waitDone(t *testing.T, l *Login) {
	t.Helper()
	select {
	case <-l.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("login did not end")
	}
}

func TestRefresher_InteractiveLogin(t *testing.T) {
	client := &fakeClient{lifetime: time.Hour, refreshToken: "rt"}
	var written []*oauth2.Token
	var mu sync.Mutex
	r := testRefresher(client, nil, func(tok *oauth2.Token) {
		mu.Lock()
		written = append(written, tok)
		mu.Unlock()
	})
	fl := newFakeLogin(&oauth2.Token{AccessToken: "logged", RefreshToken: "rt", Expiry: time.Now().Add(time.Hour)})
	r.SetLogin(fl.login)

	if st := r.State(); !st.LoginRequired || st.Token != nil || !st.LastRenewal.IsZero() {
		t.Fatalf("before login: %+v", st)
	}
	if _, err := r.Renew(context.Background(), nil); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("Renew() before login error = %v, want ErrLoginRequired", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- r.Run(ctx) }()

	l, err := r.StartLogin(ctx, ctx)
	if err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	if l.Prompt.Code != "ABCD" {
		t.Errorf("prompt = %+v", l.Prompt)
	}
	// A second call joins the pending login
	l2, err := r.StartLogin(ctx, ctx)
	if err != nil || l2 != l {
		t.Errorf("second StartLogin() = %p, %v; want the pending login %p", l2, err, l)
	}
	if st := r.State(); st.Login == nil || st.Login.Code != "ABCD" {
		t.Errorf("pending login not in state: %+v", st)
	}

	fl.release <- nil
	waitDone(t, l)
	if l.Err() != nil {
		t.Fatalf("login error = %v", l.Err())
	}
	st := r.State()
	if st.LoginRequired || st.Login != nil || st.Token == nil || st.Token.AccessToken != "logged" {
		t.Errorf("after login: %+v", st)
	}
	mu.Lock()
	if len(written) != 1 {
		t.Errorf("onToken called %d times, want 1", len(written))
	}
	mu.Unlock()
	fl.mu.Lock()
	if fl.starts != 1 {
		t.Errorf("login started %d times, want 1", fl.starts)
	}
	fl.mu.Unlock()
	// Interactive flows never authenticate by themselves
	if gets, _ := client.counts(); gets != 0 {
		t.Errorf("GetToken called %d times", gets)
	}
	cancel()
	if err := <-runDone; err != nil {
		t.Errorf("Run() error = %v", err)
	}
}

func TestRefresher_InteractiveLoginFails(t *testing.T) {
	r := testRefresher(&fakeClient{}, nil, nil)
	fl := newFakeLogin(nil)
	r.SetLogin(fl.login)

	l, err := r.StartLogin(context.Background(), context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fl.release <- errors.New("code expired")
	waitDone(t, l)
	if l.Err() == nil {
		t.Fatal("expected a login error")
	}
	st := r.State()
	if st.Login != nil || !st.LoginRequired || st.LastErr == nil {
		t.Errorf("after failed login: %+v", st)
	}
	// A new login can start
	l2, err := r.StartLogin(context.Background(), context.Background())
	if err != nil || l2 == l {
		t.Errorf("new StartLogin() = %v, %v", l2, err)
	}
	fl.release <- errors.New("stop")
	waitDone(t, l2)
}

func TestRefresher_InteractiveSessionExpired(t *testing.T) {
	expired := &oauth2.RetrieveError{ErrorCode: "invalid_grant"}
	for _, tc := range []struct {
		name       string
		refreshErr error
		wantLogin  bool
	}{
		{"session expired", fmt.Errorf("failed to refresh token: %w", expired), true},
		{"transient error", errors.New("connection refused"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeClient{lifetime: time.Hour, refreshErr: tc.refreshErr}
			r := testRefresher(client, &oauth2.Token{AccessToken: "a", RefreshToken: "rt", Expiry: time.Now().Add(time.Minute)}, nil)
			r.SetLogin(newFakeLogin(nil).login)
			if r.State().LoginRequired {
				t.Fatal("login required with a token")
			}

			_, err := r.Renew(context.Background(), nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := errors.Is(err, ErrLoginRequired); got != tc.wantLogin {
				t.Errorf("errors.Is(ErrLoginRequired) = %v, want %v (%v)", got, tc.wantLogin, err)
			}
			if got := r.State().LoginRequired; got != tc.wantLogin {
				t.Errorf("LoginRequired = %v, want %v", got, tc.wantLogin)
			}
			if gets, _ := client.counts(); gets != 0 {
				t.Errorf("GetToken called %d times", gets)
			}
		})
	}
}

func TestRefresher_StartLoginNonInteractive(t *testing.T) {
	r := testRefresher(&fakeClient{}, &oauth2.Token{AccessToken: "a"}, nil)
	if _, err := r.StartLogin(context.Background(), context.Background()); err == nil {
		t.Error("expected an error for a non-interactive flow")
	}
}

func TestRefresher_CompleteLogin(t *testing.T) {
	r := testRefresher(&fakeClient{}, nil, nil)
	fl := newFakeLogin(&oauth2.Token{AccessToken: "pasted", Expiry: time.Now().Add(time.Hour)})
	r.SetLogin(fl.login)

	if err := r.CompleteLogin("http://127.0.0.1/callback?code=c"); err == nil {
		t.Error("CompleteLogin() without a pending login must fail")
	}
	l, err := r.StartLogin(context.Background(), context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CompleteLogin("https://elsewhere"); err == nil {
		t.Error("CompleteLogin() must report a rejected URL")
	}
	if err := r.CompleteLogin("http://127.0.0.1/callback?code=c"); err != nil {
		t.Fatalf("CompleteLogin() error = %v", err)
	}
	waitDone(t, l)
	if l.Err() != nil || r.Current() == nil || r.Current().AccessToken != "pasted" {
		t.Errorf("after CompleteLogin: err %v, token %+v", l.Err(), r.Current())
	}
}
