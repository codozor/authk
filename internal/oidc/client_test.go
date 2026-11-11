package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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
				"issuer":                                testServer.URL,
				"token_endpoint":                        testServer.URL + "/token",
				"jwks_uri":                              testServer.URL + "/certs", // Dummy JWKS URI
				"response_types_supported":              []string{"code"},          // Minimal required by go-oidc
				"subject_types_supported":               []string{"public"},
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

	cfg := &config.Profile{
		Issuer:       testServer.URL,
		ClientID:     "client",
		ClientSecret: "secret",
		ClientAuth:   config.AuthBasic,
		Flow:         config.FlowClientCredentials,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	token, err := client.GetToken(context.Background())
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

func TestClient_GetToken_Password(t *testing.T) {
	// Mock OIDC Provider
	var testServer *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                                testServer.URL,
				"token_endpoint":                        testServer.URL + "/token",
				"jwks_uri":                              testServer.URL + "/certs",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}); err != nil {
				t.Error(err)
			}
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("grant_type") == "password" && r.Form.Get("username") == "testuser" && r.Form.Get("password") == "testpass" {
				w.Header().Set("Content-Type", "application/json")
				resp := mockTokenResponse{
					AccessToken: "mock_password_access_token",
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

	cfg := &config.Profile{
		Issuer:       testServer.URL,
		ClientID:     "client",
		ClientSecret: "secret",
		ClientAuth:   config.AuthBasic,
		Flow:         config.FlowPassword,
		Username:     "testuser",
		Password:     "testpass",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	token, err := client.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	if token.AccessToken != "mock_password_access_token" {
		t.Errorf("expected access token 'mock_password_access_token', got %s", token.AccessToken)
	}
}

func TestClient_GetToken_IDToken(t *testing.T) {
	// Mock OIDC Provider
	var testServer *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                                testServer.URL,
				"token_endpoint":                        testServer.URL + "/token",
				"jwks_uri":                              testServer.URL + "/certs",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}); err != nil {
				t.Error(err)
			}
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			// Create a 3-part "JWT" that might still fail verification but won't be "malformed"
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
			payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + testServer.URL + `","sub":"user"}`))
			signature := base64.RawURLEncoding.EncodeToString([]byte("sig"))
			idToken := header + "." + payload + "." + signature
			resp := mockTokenResponse{
				AccessToken: "mock_access_token",
				IDToken:     idToken,
				ExpiresIn:   3600,
				TokenType:   "Bearer",
			}
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Error(err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	testServer = httptest.NewServer(handler)
	defer testServer.Close()

	cfg := &config.Profile{
		Issuer:       testServer.URL,
		ClientID:     "client",
		ClientSecret: "secret",
		ClientAuth:   config.AuthBasic,
		Flow:         config.FlowClientCredentials,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	token, err := client.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		t.Fatal("expected id_token to be present in extra")
	}
	if !strings.HasPrefix(idToken, "eyJhbGciOiJub25lIn0") {
		t.Errorf("expected id token to start with expected header, got %s", idToken)
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
				"issuer":                                testServer.URL,
				"token_endpoint":                        testServer.URL + "/token",
				"jwks_uri":                              testServer.URL + "/certs", // Dummy JWKS URI
				"response_types_supported":              []string{"code"},          // Minimal required by go-oidc
				"subject_types_supported":               []string{"public"},
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
			if _, err := w.Write([]byte(`{"keys":[]}`)); err != nil {
				t.Errorf("w.Write failed: %v", err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	testServer = httptest.NewServer(handler)
	defer testServer.Close()

	cfg := &config.Profile{
		Issuer:       testServer.URL,
		ClientID:     "client",
		ClientSecret: "secret",
		ClientAuth:   config.AuthBasic,
		Flow:         config.FlowClientCredentials,
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

	token, err := client.RefreshToken(context.Background(), oldToken)
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

func TestClient_GetToken_PublicClient(t *testing.T) {
	// Mock OIDC Provider
	var testServer *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                                testServer.URL,
				"token_endpoint":                        testServer.URL + "/token",
				"jwks_uri":                              testServer.URL + "/certs",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}); err != nil {
				t.Error(err)
			}
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			// A public client must send client_id in the body, without secret nor Basic auth
			if r.Header.Get("Authorization") != "" {
				t.Errorf("unexpected Authorization header: %q", r.Header.Get("Authorization"))
			}
			if _, ok := r.PostForm["client_secret"]; ok {
				t.Error("unexpected client_secret in request body")
			}
			if r.PostForm.Get("client_id") == "public-client" && r.Form.Get("grant_type") == "password" {
				w.Header().Set("Content-Type", "application/json")
				resp := mockTokenResponse{
					AccessToken: "mock_public_access_token",
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

	for _, authMethod := range []string{config.AuthNone, config.AuthBasic} {
		t.Run(authMethod, func(t *testing.T) {
			cfg := &config.Profile{
				Issuer:     testServer.URL,
				ClientID:   "public-client",
				ClientAuth: authMethod,
				Flow:       config.FlowPassword,
				Username:   "testuser",
				Password:   "testpass",
			}

			client, err := NewClient(cfg)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			token, err := client.GetToken(context.Background())
			if err != nil {
				t.Fatalf("GetToken() error = %v", err)
			}
			if token.AccessToken != "mock_public_access_token" {
				t.Errorf("expected access token 'mock_public_access_token', got %s", token.AccessToken)
			}

			// client_credentials is not possible without a secret
			cfg.Flow = config.FlowClientCredentials
			if _, err := client.GetToken(context.Background()); err == nil {
				t.Error("expected error for public client with the client_credentials flow")
			}
		})
	}
}

// newRefreshTestServer serves discovery and a refresh_token grant that returns a new token.
func newRefreshTestServer(t *testing.T, calls *int) *httptest.Server {
	t.Helper()
	var testServer *httptest.Server
	testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                                testServer.URL,
				"token_endpoint":                        testServer.URL + "/token",
				"jwks_uri":                              testServer.URL + "/certs",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}); err != nil {
				t.Error(err)
			}
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "valid_refresh" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			*calls++
			w.Header().Set("Content-Type", "application/json")
			// No refresh_token in the response: the old one must be kept
			if err := json.NewEncoder(w).Encode(mockTokenResponse{
				AccessToken: "new_access_token",
				ExpiresIn:   3600,
				TokenType:   "Bearer",
			}); err != nil {
				t.Error(err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(testServer.Close)
	return testServer
}

func TestClient_RefreshToken_StillValidToken(t *testing.T) {
	calls := 0
	srv := newRefreshTestServer(t, &calls)

	client, err := NewClient(&config.Profile{
		Issuer: srv.URL, ClientID: "client", ClientSecret: "secret", Flow: config.FlowClientCredentials,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Still valid for 30s: the refresh must happen anyway (refresh buffer is 60s)
	oldToken := &oauth2.Token{
		AccessToken:  "old_access_token",
		RefreshToken: "valid_refresh",
		Expiry:       time.Now().Add(30 * time.Second),
	}

	token, err := client.RefreshToken(context.Background(), oldToken)
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call to the token endpoint, got %d", calls)
	}
	if token.AccessToken != "new_access_token" {
		t.Errorf("expected a new access token, got %s", token.AccessToken)
	}
	if token.RefreshToken != "valid_refresh" {
		t.Errorf("expected the refresh token to be kept, got %q", token.RefreshToken)
	}
}

func TestClient_RefreshToken_NoRefreshToken(t *testing.T) {
	calls := 0
	srv := newRefreshTestServer(t, &calls)

	client, err := NewClient(&config.Profile{
		Issuer: srv.URL, ClientID: "client", ClientSecret: "secret", Flow: config.FlowClientCredentials,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	_, err = client.RefreshToken(context.Background(), &oauth2.Token{AccessToken: "a"})
	if !errors.Is(err, ErrNoRefreshToken) {
		t.Fatalf("expected ErrNoRefreshToken, got %v", err)
	}
	if calls != 0 {
		t.Errorf("expected no call to the token endpoint, got %d", calls)
	}
}

// newDeviceTestServer returns a provider supporting the device_code flow. The token
// endpoint answers authorization_pending pending times, then finalErr ("" for a token).
func newDeviceTestServer(t *testing.T, pending int, finalErr string) (*httptest.Server, *[]url.Values) {
	t.Helper()
	var mu sync.Mutex
	var deviceRequests []url.Values
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                srv.URL,
				"token_endpoint":                        srv.URL + "/token",
				"device_authorization_endpoint":         srv.URL + "/device",
				"jwks_uri":                              srv.URL + "/certs",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/device":
			_ = r.ParseForm()
			mu.Lock()
			deviceRequests = append(deviceRequests, r.PostForm)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":               "dev-code",
				"user_code":                 "ABCD-EFGH",
				"verification_uri":          srv.URL + "/activate",
				"verification_uri_complete": srv.URL + "/activate?code=ABCD-EFGH",
				"expires_in":                60,
				"interval":                  1,
			})
		case "/token":
			_ = r.ParseForm()
			if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" ||
				r.PostForm.Get("device_code") != "dev-code" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
				return
			}
			mu.Lock()
			wait := pending > 0
			pending--
			mu.Unlock()
			switch {
			case wait:
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
			case finalErr != "":
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"` + finalErr + `"}`))
			default:
				_ = json.NewEncoder(w).Encode(mockTokenResponse{
					AccessToken: "device_access", RefreshToken: "device_refresh", TokenType: "Bearer", ExpiresIn: 300,
				})
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &deviceRequests
}

func TestClient_GetToken_DeviceCode(t *testing.T) {
	srv, deviceRequests := newDeviceTestServer(t, 1, "")
	client, err := NewClient(&config.Profile{
		Issuer: srv.URL, ClientID: "cli", ClientSecret: "sec", ClientAuth: config.AuthBasic, Flow: config.FlowDeviceCode,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if !client.Interactive() {
		t.Error("device_code must be interactive")
	}
	var shown []DeviceLogin
	client.OnDeviceLogin = func(l DeviceLogin) { shown = append(shown, l) }

	token, err := client.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}
	if token.AccessToken != "device_access" || token.RefreshToken != "device_refresh" {
		t.Errorf("unexpected token %+v", token)
	}
	if len(shown) != 1 || shown[0].UserCode != "ABCD-EFGH" || !strings.HasSuffix(shown[0].VerificationURIComplete, "?code=ABCD-EFGH") {
		t.Errorf("unexpected login shown: %+v", shown)
	}
	if time.Until(shown[0].Expiry) <= 0 {
		t.Errorf("expiry not set: %v", shown[0].Expiry)
	}
	// A confidential client authenticates on the device endpoint
	if got := (*deviceRequests)[0].Get("client_secret"); got != "sec" {
		t.Errorf("device request client_secret = %q, want sec", got)
	}
}

func TestClient_DeviceLogin_PublicClient(t *testing.T) {
	srv, deviceRequests := newDeviceTestServer(t, 0, "")
	client, err := NewClient(&config.Profile{
		Issuer: srv.URL, ClientID: "cli", ClientAuth: config.AuthNone, Flow: config.FlowDeviceCode,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	l, err := client.StartDeviceLogin(context.Background())
	if err != nil {
		t.Fatalf("StartDeviceLogin() error = %v", err)
	}
	if _, err := l.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	form := (*deviceRequests)[0]
	if form.Has("client_secret") || form.Get("client_id") != "cli" {
		t.Errorf("unexpected device request %v", form)
	}
}

func TestClient_DeviceLogin_Errors(t *testing.T) {
	for _, tc := range []struct{ code, want string }{
		{"access_denied", "refused"},
		{"expired_token", "expired"},
		{"invalid_client", "set clientSecret, or make the client public"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			srv, _ := newDeviceTestServer(t, 0, tc.code)
			client, err := NewClient(&config.Profile{Issuer: srv.URL, ClientID: "cli", ClientAuth: config.AuthNone, Flow: config.FlowDeviceCode})
			if err != nil {
				t.Fatal(err)
			}
			l, err := client.StartDeviceLogin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := l.Wait(context.Background()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Wait() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestClient_DeviceCode_NotSupportedByProvider(t *testing.T) {
	calls := 0
	srv := newRefreshTestServer(t, &calls) // no device_authorization_endpoint
	client, err := NewClient(&config.Profile{Issuer: srv.URL, ClientID: "client", Flow: config.FlowDeviceCode})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	client.OnDeviceLogin = func(DeviceLogin) {}
	if _, err := client.GetToken(context.Background()); err == nil || !strings.Contains(err.Error(), "device_authorization_endpoint") {
		t.Errorf("expected a missing endpoint error, got %v", err)
	}
}

func TestNewClient_DiscoveryErrorIsShort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("\n\n<!DOCTYPE html>\n<html><body>Not Found</body></html>\n"))
	}))
	defer srv.Close()

	_, err := NewClient(&config.Profile{Issuer: srv.URL + "/application/o/app/", ClientID: "c", Flow: config.FlowDeviceCode})
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if strings.Contains(msg, "html") || strings.Contains(msg, "\n") {
		t.Errorf("error contains the response body: %q", msg)
	}
	for _, want := range []string{srv.URL + "/application/o/app/.well-known/openid-configuration", "404", "check the issuer"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not contain %q", msg, want)
		}
	}
}
