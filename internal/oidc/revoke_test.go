package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/codozor/authk/internal/config"
)

type revokeRequest struct {
	form           url.Values
	user, password string
	basic          bool
}

// newRevokeTestServer returns a provider with a revocation endpoint answering status
// (0: no revocation_endpoint in the discovery document).
func newRevokeTestServer(t *testing.T, status int) (*httptest.Server, func() []revokeRequest) {
	t.Helper()
	var mu sync.Mutex
	var reqs []revokeRequest
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			doc := map[string]any{
				"issuer":                                srv.URL,
				"token_endpoint":                        srv.URL + "/token",
				"jwks_uri":                              srv.URL + "/certs",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}
			if status != 0 {
				doc["revocation_endpoint"] = srv.URL + "/revoke"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(doc)
		case "/revoke":
			_ = r.ParseForm()
			user, password, basic := r.BasicAuth()
			mu.Lock()
			reqs = append(reqs, revokeRequest{form: r.PostForm, user: user, password: password, basic: basic})
			mu.Unlock()
			w.WriteHeader(status)
			if status != http.StatusOK {
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []revokeRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]revokeRequest(nil), reqs...)
	}
}

func TestClient_Revoke(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		clientAuth string
		check      func(t *testing.T, r revokeRequest)
	}{
		{"basic", "s3cr:t", config.AuthBasic, func(t *testing.T, r revokeRequest) {
			if !r.basic || r.user != "cli" || r.password != url.QueryEscape("s3cr:t") || r.form.Has("client_secret") {
				t.Errorf("expected HTTP Basic client authentication, got %+v", r)
			}
		}},
		{"post", "s3cret", config.AuthPost, func(t *testing.T, r revokeRequest) {
			if r.basic || r.form.Get("client_id") != "cli" || r.form.Get("client_secret") != "s3cret" {
				t.Errorf("expected the secret in the body, got %+v", r)
			}
		}},
		{"public", "", config.AuthNone, func(t *testing.T, r revokeRequest) {
			if r.basic || r.form.Get("client_id") != "cli" || r.form.Has("client_secret") {
				t.Errorf("expected client_id only, got %+v", r)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, reqs := newRevokeTestServer(t, http.StatusOK)
			c, err := NewClient(&config.Profile{Issuer: srv.URL, ClientID: "cli", ClientSecret: tt.secret,
				ClientAuth: tt.clientAuth, Flow: config.FlowDeviceCode})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Revoke(context.Background(), "rt-1"); err != nil {
				t.Fatal(err)
			}
			got := reqs()
			if len(got) != 1 {
				t.Fatalf("%d revocation requests", len(got))
			}
			if got[0].form.Get("token") != "rt-1" || got[0].form.Get("token_type_hint") != "refresh_token" {
				t.Errorf("unexpected form %v", got[0].form)
			}
			tt.check(t, got[0])
		})
	}
}

func TestClient_Revoke_Errors(t *testing.T) {
	srv, _ := newRevokeTestServer(t, 0)
	c, err := NewClient(&config.Profile{Issuer: srv.URL, ClientID: "cli", Flow: config.FlowDeviceCode})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Revoke(context.Background(), "rt"); !errors.Is(err, ErrRevocationNotSupported) {
		t.Errorf("expected ErrRevocationNotSupported, got %v", err)
	}

	srv, _ = newRevokeTestServer(t, http.StatusUnauthorized)
	c, err = NewClient(&config.Profile{Issuer: srv.URL, ClientID: "cli", Flow: config.FlowDeviceCode})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Revoke(context.Background(), "rt"); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("expected the provider error, got %v", err)
	}
}
