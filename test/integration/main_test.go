//go:build integration

// Package integration runs the authk binary against a real Keycloak, started with the
// realm of realm.json (see the integration job of the CI):
//
//	AUTHK_KEYCLOAK_URL=http://localhost:8080 go test -tags integration ./test/integration/
package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const realm = "authk-test"

var (
	keycloakURL string // e.g. http://localhost:8080
	authkBin    string // the binary under test
	workRoot    string // per-test directories (short paths: unix socket limit)
)

func TestMain(m *testing.M) {
	keycloakURL = strings.TrimSuffix(os.Getenv("AUTHK_KEYCLOAK_URL"), "/")
	if keycloakURL == "" {
		fmt.Println("AUTHK_KEYCLOAK_URL is not set: skipping the integration tests")
		os.Exit(0)
	}
	// Not in os.TempDir(): it may be a small tmpfs, and socket paths must stay short
	cache, err := os.UserCacheDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	workRoot = filepath.Join(cache, "authk-it")
	if err := os.MkdirAll(workRoot, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	authkBin = filepath.Join(workRoot, "authk")
	build := exec.Command("go", "build", "-o", authkBin, "../../cmd/authk")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "failed to build authk:", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(workRoot)
	os.Exit(code)
}

// env is an isolated authk environment: its own config, .env, sockets and stored sessions.
type env struct {
	t    *testing.T
	dir  string // project directory: authk.cue, .env
	vars []string
}

// config is the authk.cue of every test: one profile per client of the realm.
const config = `version: 2

profiles: svc: {
	issuer:       "%[1]s"
	clientId:     "svc"
	clientSecret: "svc-secret"
	flow:         "client_credentials"
	targets: [{key: "TOKEN"}]
}

profiles: "svc-post": {
	issuer:       "%[1]s"
	clientId:     "svc"
	clientSecret: "svc-secret"
	clientAuth:   "post"
	flow:         "client_credentials"
}

profiles: pwd: {
	issuer:       "%[1]s"
	clientId:     "svc"
	clientSecret: "svc-secret"
	flow:         "password"
	username:     "alice"
	password:     "alice-password"
}

profiles: tv: {
	issuer:     "%[1]s"
	clientId:   "tv"
	flow:       "device_code"
	tokenStore: "file"
}

profiles: web: {
	issuer:     "%[1]s"
	clientId:   "web"
	flow:       "authorization_code"
	tokenStore: "file"
}
`

func newEnv(t *testing.T) *env {
	t.Helper()
	suffix := make([]byte, 3)
	_, _ = rand.Read(suffix)
	root := filepath.Join(workRoot, hex.EncodeToString(suffix))
	e := &env{t: t, dir: filepath.Join(root, "proj")}
	for _, d := range []string{e.dir, filepath.Join(root, "run"), filepath.Join(root, "state")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	issuer := keycloakURL + "/realms/" + realm
	if err := os.WriteFile(filepath.Join(e.dir, "authk.cue"), []byte(fmt.Sprintf(config, issuer)), 0o600); err != nil {
		t.Fatal(err)
	}
	e.vars = append(os.Environ(),
		"XDG_RUNTIME_DIR="+filepath.Join(root, "run"),
		"XDG_STATE_HOME="+filepath.Join(root, "state"),
		"AUTHK_NO_BROWSER=1",
		"AUTHK_PROFILE=",
		"AUTHK_SOCK=",
	)
	t.Cleanup(func() {
		// Only the agents of this environment: XDG_RUNTIME_DIR is private
		_, _, _ = e.run("agent", "stop", "--all")
		_ = os.RemoveAll(root)
	})
	return e
}

func (e *env) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, authkBin, args...)
	cmd.Dir = e.dir
	cmd.Env = e.vars
	cmd.Stdin = nil // not a terminal: authk never waits for a pasted URL
	return cmd
}

// run runs authk and returns its output and exit code.
func (e *env) run(args ...string) (stdout, stderr string, code int) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := e.command(ctx, args...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		e.t.Fatalf("authk %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(out.String()), strings.TrimSpace(errOut.String()), code
}

// ok runs authk, fails the test if it fails, and returns its stdout.
func (e *env) ok(args ...string) string {
	e.t.Helper()
	out, errOut, code := e.run(args...)
	if code != 0 {
		e.t.Fatalf("authk %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, out, errOut)
	}
	return out
}

// fails runs authk, fails the test if it succeeds, and returns its stderr.
func (e *env) fails(args ...string) string {
	e.t.Helper()
	out, errOut, code := e.run(args...)
	if code == 0 {
		e.t.Fatalf("authk %s: expected a failure\nstdout: %s\nstderr: %s", strings.Join(args, " "), out, errOut)
	}
	return errOut
}

var openRe = regexp.MustCompile(`Open:\s+(\S+)`)

// interactive runs authk until it shows a login, logs in as alice in the browser, and
// returns the output once authk exited.
func (e *env) interactive(args ...string) string {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := e.command(ctx, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	stderr, err := cmd.StderrPipe()
	if err != nil {
		e.t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}

	var errOut strings.Builder
	scanner := bufio.NewScanner(stderr)
	loginURL := ""
	for loginURL == "" && scanner.Scan() {
		line := scanner.Text()
		errOut.WriteString(line + "\n")
		if m := openRe.FindStringSubmatch(line); m != nil {
			loginURL = m[1]
		}
	}
	if loginURL == "" {
		_ = cmd.Wait()
		e.t.Fatalf("authk %s: no login prompt\nstdout: %s\nstderr: %s", strings.Join(args, " "), out.String(), errOut.String())
	}
	// Wait must not be called before the pipe is read to the end
	copied := make(chan struct{})
	go func() {
		_, _ = io.Copy(&errOut, stderr)
		close(copied)
	}()

	loginErr := login(loginURL)
	<-copied
	err = cmd.Wait()
	if loginErr != nil {
		e.t.Fatalf("login: %v\nstderr: %s", loginErr, errOut.String())
	}
	if err != nil {
		e.t.Fatalf("authk %s: %v\nstdout: %s\nstderr: %s", strings.Join(args, " "), err, out.String(), errOut.String())
	}
	return strings.TrimSpace(out.String())
}

func (e *env) path(name string) string { return filepath.Join(e.dir, name) }
