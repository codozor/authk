package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/codozor/authk/internal/config"
	"golang.org/x/oauth2"
)

type mockTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"` // seconds
	IDToken      string `json:"id_token,omitempty"`
}

func TestClient_GetToken(t *testing.T) {
	// Mock OIDC Provider
	var testServer *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			// go-oidc requires an issuer that matches the discovery URL
			// and a jwks_uri for ID token validation (even if we don't validate it in this test)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":           testServer.URL,
				"token_endpoint":   testServer.URL + "/token",
				"jwks_uri":         testServer.URL + "/certs", // Dummy JWKS URI
				"response_types_supported": []string{"code"}, // Minimal required by go-oidc
				"subject_types_supported": []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}); err != nil {
				t.Error(err)
			}
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("grant_type") == "client_credentials" {
				w.Header().Set("Content-Type", "application/json")
				resp := mockTokenResponse{
					AccessToken: "mock_access_token",
					ExpiresIn:   3600,
					TokenType:   "Bearer",
				}
				if err := json.NewEncoder(w).Encode(resp); err != nil {
					t.Error(err)
				}
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	testServer = httptest.NewServer(handler)
	defer testServer.Close()

	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			IssuerURL:    testServer.URL,
			ClientID:     "client",
			ClientSecret: "secret",
			AuthMethod:   "client_secret_basic",
		},
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	token, err := client.GetToken("", "")
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	if token.AccessToken != "mock_access_token" {
		t.Errorf("expected access token 'mock_access_token', got %s", token.AccessToken)
	}
	if token.TokenType != "Bearer" {
		t.Errorf("expected token type 'Bearer', got %s", token.TokenType)
	}
	if token.Expiry.IsZero() {
		t.Error("expected token expiry to be set")
	}
}

func TestClient_RefreshToken(t *testing.T) {
	var testServer *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			// go-oidc requires an issuer that matches the discovery URL
			// and a jwks_uri for ID token validation (even if we don't validate it in this test)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":           testServer.URL,
				"token_endpoint":   testServer.URL + "/token",
				"jwks_uri":         testServer.URL + "/certs", // Dummy JWKS URI
				"response_types_supported": []string{"code"}, // Minimal required by go-oidc
				"subject_types_supported": []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}); err != nil {
				t.Error(err)
			}
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("grant_type") == "refresh_token" && r.Form.Get("refresh_token") == "valid_refresh" {
				w.Header().Set("Content-Type", "application/json")
				resp := mockTokenResponse{
					AccessToken: "new_access_token",
					ExpiresIn:   3600,
					TokenType:   "Bearer",
				}
				if err := json.NewEncoder(w).Encode(resp); err != nil {
					t.Error(err)
				}
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		case "/certs":
			// Provide a minimal JWKS endpoint for go-oidc
			w.Write([]byte(`{"keys":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	testServer = httptest.NewServer(handler)
	defer testServer.Close()

	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			IssuerURL:    testServer.URL,
			ClientID:     "client",
			ClientSecret: "secret",
			AuthMethod:   "client_secret_basic",
		},
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Create a dummy old token with the refresh token
	oldToken := &oauth2.Token{
		RefreshToken: "valid_refresh",
		Expiry:       time.Now().Add(-1 * time.Hour), // Expired to force refresh
	}

	token, err := client.RefreshToken(oldToken)
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	if token.AccessToken != "new_access_token" {
		t.Errorf("expected access token 'new_access_token', got %s", token.AccessToken)
	}
	if token.TokenType != "Bearer" {
		t.Errorf("expected token type 'Bearer', got %s", token.TokenType)
	}
	if token.Expiry.IsZero() {
		t.Error("expected token expiry to be set")
	}
}
