package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codozor/authk/internal/config"
)

// newAuthCodeTestServer returns a provider for the authorization_code flow. Its
// authorization endpoint redirects at once to the redirect URI with a code, or with
// denyErr. The token endpoint checks the PKCE verifier and the redirect URI.
func newAuthCodeTestServer(t *testing.T, denyErr string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	pending := map[string][2]string{} // code -> challenge, redirect URI
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                srv.URL,
				"authorization_endpoint":                srv.URL + "/auth",
				"token_endpoint":                        srv.URL + "/token",
				"jwks_uri":                              srv.URL + "/certs",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/auth":
			q := r.URL.Query()
			redirect, err := url.Parse(q.Get("redirect_uri"))
			if err != nil || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
				q.Get("code_challenge") == "" || q.Get("client_id") != "cli" {
				http.Error(w, "bad authorization request: "+r.URL.RawQuery, http.StatusBadRequest)
				return
			}
			back := url.Values{"state": {q.Get("state")}}
			if denyErr != "" {
				back.Set("error", denyErr)
			} else {
				mu.Lock()
				pending["the-code"] = [2]string{q.Get("code_challenge"), q.Get("redirect_uri")}
				mu.Unlock()
				back.Set("code", "the-code")
			}
			redirect.RawQuery = back.Encode()
			http.Redirect(w, r, redirect.String(), http.StatusFound)
		case "/token":
			_ = r.ParseForm()
			mu.Lock()
			p, ok := pending[r.PostForm.Get("code")]
			delete(pending, r.PostForm.Get("code"))
			mu.Unlock()
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			w.Header().Set("Content-Type", "application/json")
			if r.PostForm.Get("grant_type") != "authorization_code" || !ok ||
				base64.RawURLEncoding.EncodeToString(sum[:]) != p[0] || r.PostForm.Get("redirect_uri") != p[1] {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(mockTokenResponse{
				AccessToken: "browser_access", RefreshToken: "browser_refresh", TokenType: "Bearer", ExpiresIn: 300,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func browserClient(t *testing.T, srv *httptest.Server, port int) *Client {
	t.Helper()
	client, err := NewClient(&config.Profile{
		Issuer: srv.URL, ClientID: "cli", ClientAuth: config.AuthNone, Flow: config.FlowAuthorizationCode, RedirectPort: port,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return client
}

// noRedirect is an HTTP client that stops at the first redirect, like a browser that
// cannot reach the callback.
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func TestClient_GetToken_AuthorizationCode(t *testing.T) {
	srv := newAuthCodeTestServer(t, "")
	client := browserClient(t, srv, 0)
	if !client.Interactive() {
		t.Error("authorization_code must be interactive")
	}
	var shown *Login
	client.OnLogin = func(l *Login) {
		shown = l
		// The "browser" follows the redirect to the local callback
		go func() {
			resp, err := http.Get(l.URL)
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("callback status = %s", resp.Status)
			}
		}()
	}
	token, err := client.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}
	if token.AccessToken != "browser_access" || token.RefreshToken != "browser_refresh" {
		t.Errorf("unexpected token %+v", token)
	}
	if !shown.Browser || shown.UserCode != "" || time.Until(shown.Expiry) <= 0 {
		t.Errorf("unexpected login %+v", shown)
	}
}

func TestClient_BrowserLogin_FixedPortAndPastedURL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	srv := newAuthCodeTestServer(t, "")
	login, err := browserClient(t, srv, port).StartLogin(context.Background())
	if err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	authURL, _ := url.Parse(login.URL)
	if want := fmt.Sprintf("http://127.0.0.1:%d/callback", port); authURL.Query().Get("redirect_uri") != want {
		t.Errorf("redirect_uri = %q, want %q", authURL.Query().Get("redirect_uri"), want)
	}

	// The browser cannot reach the callback: the user pastes the URL it ended on
	resp, err := noRedirect.Get(login.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	location := resp.Header.Get("Location")

	if err := login.Complete("http://127.0.0.1/callback?code=x&state=forged"); err == nil {
		t.Error("Complete() accepted a URL with another state")
	}
	if err := login.Complete("  " + location + "\n"); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	token, err := login.Wait(context.Background())
	if err != nil || token.AccessToken != "browser_access" {
		t.Fatalf("Wait() = %+v, %v", token, err)
	}
	// The callback server is closed once the login ended
	if _, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback", port)); err == nil {
		t.Error("callback still served after the login")
	}
}

func TestClient_BrowserLogin_Errors(t *testing.T) {
	t.Run("access denied", func(t *testing.T) {
		srv := newAuthCodeTestServer(t, "access_denied")
		login, err := browserClient(t, srv, 0).StartLogin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.Get(login.URL)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("callback status = %s, want 400", resp.Status)
		}
		if _, err := login.Wait(context.Background()); err == nil || !strings.Contains(err.Error(), "access_denied") {
			t.Errorf("Wait() error = %v, want access_denied", err)
		}
	})

	t.Run("forged redirect is ignored", func(t *testing.T) {
		srv := newAuthCodeTestServer(t, "")
		login, err := browserClient(t, srv, 0).StartLogin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		redirect, _ := url.Parse(login.URL)
		callback := redirect.Query().Get("redirect_uri")
		resp, err := http.Get(callback + "?code=evil&state=forged")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("forged callback status = %s, want 400", resp.Status)
		}
		// The login still waits for the real redirect
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, err := login.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Wait() error = %v, want the context deadline", err)
		}
	})

	t.Run("port in use", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		srv := newAuthCodeTestServer(t, "")
		if _, err := browserClient(t, srv, ln.Addr().(*net.TCPAddr).Port).StartLogin(context.Background()); err == nil {
			t.Error("expected an error for a port in use")
		}
	})
}
