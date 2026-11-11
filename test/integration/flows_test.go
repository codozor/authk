//go:build integration

package integration

import (
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
)

var jwtRe = regexp.MustCompile(`^[\w-]+\.[\w-]+\.[\w-]+$`)

func requireJWT(t *testing.T, what, s string) {
	t.Helper()
	if !jwtRe.MatchString(s) {
		t.Fatalf("%s is not a JWT: %q", what, s)
	}
}

func TestClientCredentialsAndPassword(t *testing.T) {
	e := newEnv(t)
	for _, profile := range []string{"svc", "svc-post", "pwd"} {
		requireJWT(t, profile+" access token", e.ok("get", "-p", profile))
	}
	requireJWT(t, "ID Token of the password flow", e.ok("get", "-p", "pwd", "--id-token"))
}

func TestAgentWritesAndRenews(t *testing.T) {
	e := newEnv(t)
	e.ok("agent", "-d", "-p", "svc")
	first := readEnvKey(t, e.path(".env"), "TOKEN")
	requireJWT(t, "TOKEN in .env", first)
	if got := e.ok("get", "-p", "svc"); got != first {
		t.Fatalf("get did not return the agent token")
	}

	e.ok("agent", "refresh", "-p", "svc")
	second := readEnvKey(t, e.path(".env"), "TOKEN")
	if second == first {
		t.Fatal("agent refresh did not write a new token")
	}
}

func TestExec(t *testing.T) {
	e := newEnv(t)
	// The keys of the targets, never written to a file
	out := e.ok("exec", "-p", "svc", "--", "sh", "-c", `printf %s "$TOKEN"`)
	requireJWT(t, "TOKEN", out)
	if _, err := os.Stat(e.path(".env")); err == nil {
		t.Fatal("exec wrote the .env file")
	}
	out = e.ok("exec", "-p", "pwd", "--", "sh", "-c", `printf '%s %s' "$ACCESS_TOKEN" "$ID_TOKEN"`)
	tokens := strings.Fields(out)
	if len(tokens) != 2 {
		t.Fatalf("expected ACCESS_TOKEN and ID_TOKEN, got %q", out)
	}
	requireJWT(t, "ACCESS_TOKEN", tokens[0])
	requireJWT(t, "ID_TOKEN", tokens[1])

	_, _, code := e.run("exec", "-p", "svc", "--", "sh", "-c", "exit 7")
	if code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
}

func TestDeviceCode(t *testing.T) {
	e := newEnv(t)
	out := e.interactive("agent", "-d", "-p", "tv")
	if !strings.Contains(out, "started in the background") {
		t.Fatalf("unexpected output: %s", out)
	}
	status := e.ok("agent", "status", "-p", "tv")
	if !strings.Contains(status, "Session:      stored in file, expires in") {
		t.Fatalf("no stored session with expiry (refresh_expires_in) in status:\n%s", status)
	}
	requireJWT(t, "token served by the agent", e.ok("get", "-p", "tv"))

	// A new agent restores the stored session: no login (stdin is not a terminal, and
	// nobody would log in)
	e.ok("agent", "stop", "-p", "tv")
	e.ok("agent", "-d", "-p", "tv")
	requireJWT(t, "token of the restarted agent", e.ok("get", "-p", "tv"))
}

func TestAuthorizationCode(t *testing.T) {
	e := newEnv(t)

	// Without session and without terminal, get fails at once
	if errOut := e.fails("get", "-p", "web", "--direct"); !strings.Contains(errOut, `run "authk login -p web"`) {
		t.Fatalf("unexpected error: %s", errOut)
	}

	out := e.interactive("login", "-p", "web")
	if !strings.Contains(out, "Logged in as alice, session stored in the file") {
		t.Fatalf("unexpected login output: %s", out)
	}
	requireJWT(t, "token from the stored session", e.ok("get", "-p", "web", "--direct"))
	out = e.ok("exec", "-p", "web", "--", "sh", "-c", `printf %s "$ACCESS_TOKEN"`)
	requireJWT(t, "ACCESS_TOKEN", out)
}

// With "Revoke Refresh Token", each refresh token works once: an agent and direct
// requests sharing the stored session must never use a spent one.
func TestRefreshTokenRotation(t *testing.T) {
	e := newEnv(t)
	e.interactive("login", "-p", "web")
	e.ok("agent", "-d", "-p", "web")

	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			args := []string{"get", "-p", "web", "--direct"}
			if i%2 == 0 {
				args = []string{"agent", "refresh", "-p", "web"}
			}
			if out, errOut, code := e.run(args...); code != 0 {
				errs <- strings.Join(args, " ") + ": " + out + errOut
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	e.ok("agent", "refresh", "-p", "web")
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	a := newAdmin(t)
	e.interactive("login", "-p", "web")
	e.ok("agent", "-d", "-p", "web")
	before := countClient(a.sessions(), "web")
	if before == 0 {
		t.Fatalf("no Keycloak session for web: %v", a.sessions())
	}

	out := e.ok("logout", "-p", "web")
	for _, want := range []string{"Stored session of profile web deleted", "Session revoked at the provider", "keeps its access token"} {
		if !strings.Contains(out, want) {
			t.Fatalf("logout output misses %q:\n%s", want, out)
		}
	}
	if after := countClient(a.sessions(), "web"); after != before-1 {
		t.Fatalf("%d Keycloak sessions of web before the revocation, %d after: want one less", before, after)
	}
	if errOut := e.fails("agent", "refresh", "-p", "web"); !strings.Contains(errOut, "login required") {
		t.Fatalf("expected login required, got %s", errOut)
	}
	if list := e.ok("agent", "list"); !strings.Contains(list, "LOGIN") {
		t.Fatalf("agent list does not show LOGIN:\n%s", list)
	}
}

// When the session ends at the provider, the agent waits for a login, and
// "authk login" brings it back.
func TestSessionEndedAtProvider(t *testing.T) {
	e := newEnv(t)
	e.interactive("login", "-p", "web")
	e.ok("agent", "-d", "-p", "web")

	newAdmin(t).logoutAlice()
	if errOut := e.fails("agent", "refresh", "-p", "web"); !strings.Contains(errOut, "login required") {
		t.Fatalf("expected login required, got %s", errOut)
	}

	out := e.interactive("login", "-p", "web")
	if !strings.Contains(out, "switched to the new session") {
		t.Fatalf("the agent did not switch to the new session:\n%s", out)
	}
	e.ok("agent", "refresh", "-p", "web")
	requireJWT(t, "token of the agent", e.ok("get", "-p", "web"))
}

func countClient(clients []string, client string) int {
	n := 0
	for _, c := range clients {
		if c == client {
			n++
		}
	}
	return n
}

func readEnvKey(t *testing.T, path, key string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.Trim(v, `"`)
		}
	}
	t.Fatalf("%s not found in %s", key, path)
	return ""
}
