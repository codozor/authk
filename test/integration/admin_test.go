//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// admin calls the Keycloak admin API (admin/admin, see the CI job).
type admin struct {
	t     *testing.T
	token string
}

func newAdmin(t *testing.T) *admin {
	t.Helper()
	resp, err := http.PostForm(keycloakURL+"/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {"admin"}, "password": {"admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("admin token: %s, %v", resp.Status, err)
	}
	return &admin{t: t, token: tok.AccessToken}
}

func (a *admin) do(method, path string, out any) {
	a.t.Helper()
	req, _ := http.NewRequest(method, keycloakURL+"/admin/realms/"+realm+path, nil)
	req.Header.Set("Authorization", "Bearer "+a.token)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		a.t.Fatalf("admin %s %s: %s", method, path, resp.Status)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			a.t.Fatal(err)
		}
	}
}

func (a *admin) aliceID() string {
	a.t.Helper()
	var users []struct {
		ID string `json:"id"`
	}
	a.do(http.MethodGet, "/users?exact=true&username=alice", &users)
	if len(users) != 1 {
		a.t.Fatalf("found %d users named alice", len(users))
	}
	return users[0].ID
}

// sessions returns the clients of alice's online sessions.
func (a *admin) sessions() []string {
	a.t.Helper()
	var sessions []struct {
		Clients map[string]string `json:"clients"`
	}
	a.do(http.MethodGet, "/users/"+a.aliceID()+"/sessions", &sessions)
	var clients []string
	for _, s := range sessions {
		for _, c := range s.Clients {
			clients = append(clients, c)
		}
	}
	return clients
}

// logoutAlice ends every session of alice, as an administrator would.
func (a *admin) logoutAlice() {
	a.t.Helper()
	a.do(http.MethodPost, "/users/"+a.aliceID()+"/logout", nil)
}
