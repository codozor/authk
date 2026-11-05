package agent

import (
	"context"
	"errors"
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
	gets         int
	refreshes    int
	refreshedAt  []time.Time
}

func (f *fakeClient) newToken() *oauth2.Token {
	return &oauth2.Token{AccessToken: "t", RefreshToken: f.refreshToken, Expiry: time.Now().Add(f.lifetime)}
}

func (f *fakeClient) GetToken(context.Context, string, string) (*oauth2.Token, error) {
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
