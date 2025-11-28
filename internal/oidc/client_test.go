package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codozor/authk/internal/config"
)

func TestClient_GetToken(t *testing.T) {
	// Mock OIDC Provider
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("grant_type") == "client_credentials" {
				json.NewEncoder(w).Encode(TokenResponse{
					AccessToken: "mock_access_token",
					ExpiresIn:   3600,
					TokenType:   "Bearer",
				})
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			IssuerURL:    ts.URL,
			ClientID:     "client",
			ClientSecret: "secret",
			AuthMethod:   "basic",
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
}

func TestClient_RefreshToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("grant_type") == "refresh_token" && r.Form.Get("refresh_token") == "valid_refresh" {
				json.NewEncoder(w).Encode(TokenResponse{
					AccessToken: "new_access_token",
					ExpiresIn:   3600,
				})
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		}
	}))
	defer ts.Close()

	cfg := &config.Config{
		OIDC: config.OIDCConfig{
			IssuerURL: ts.URL,
		},
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	token, err := client.RefreshToken("valid_refresh")
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	if token.AccessToken != "new_access_token" {
		t.Errorf("expected access token 'new_access_token', got %s", token.AccessToken)
	}
}
