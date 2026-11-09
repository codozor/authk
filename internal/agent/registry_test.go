package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// useRuntimeDir points Dir() to a new short directory for the test.
func useRuntimeDir(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("", "akr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv(SocketEnv, "")
}

// runRegistered starts an agent registered like the real command does.
func runRegistered(t *testing.T, configPath, profile, envFile string) Entry {
	t.Helper()
	id := ID(configPath, profile, envFile, "")
	socket := SocketFor(id)
	ln, err := Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	e := Entry{ID: id, Name: Name(configPath, profile, envFile, ""), PID: os.Getpid(), Socket: socket, ConfigPath: configPath, Profile: profile, EnvFile: envFile, StartedAt: time.Now()}
	if err := Register(e); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	fc := &fakeClient{lifetime: time.Hour}
	go func() {
		done <- Serve(ctx, ln, NewRefresher(fc, fc.newToken(), nil), Info{ID: id, ConfigPath: configPath}, cancel)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = Unregister(id)
	})
	return e
}

func TestRegistry_ListAndFind(t *testing.T) {
	useRuntimeDir(t)
	ctx := context.Background()

	// One agent with targets on config A
	a := runRegistered(t, "/p/a/authk.cue", "default", "")
	// Two agents on config B, one per .env file
	front := runRegistered(t, "/p/b/authk.cue", "default", "/p/b/front/.env")
	runRegistered(t, "/p/b/authk.cue", "default", "/p/b/back/.env")
	// Two profiles of config C
	dev := runRegistered(t, "/p/c/authk.cue", "dev", "")
	prod := runRegistered(t, "/p/c/authk.cue", "prod", "")

	agents, err := List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 5 {
		t.Fatalf("expected 5 agents, got %d", len(agents))
	}

	// Single agent of the config: used whatever the .env file
	got, err := Find(ctx, "/p/a/authk.cue", "default", "/p/a/whatever/.env")
	if err != nil || got.ID != a.ID {
		t.Errorf("Find(A) = %v, %v; want %s", got, err, a.ID)
	}
	// Several agents: the one writing the .env file
	got, err = Find(ctx, "/p/b/authk.cue", "default", "/p/b/front/.env")
	if err != nil || got.ID != front.ID {
		t.Errorf("Find(B, front) = %v, %v; want %s", got, err, front.ID)
	}
	// Several agents, none writing this .env file: ambiguous
	if _, err := Find(ctx, "/p/b/authk.cue", "default", "/p/b/.env"); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("expected ErrAmbiguous, got %v", err)
	}
	// Profiles are separate agents
	for _, want := range []Entry{dev, prod} {
		got, err := Find(ctx, "/p/c/authk.cue", want.Profile, "/p/c/.env")
		if err != nil || got.ID != want.ID {
			t.Errorf("Find(C, %s) = %v, %v; want %s", want.Profile, got, err, want.ID)
		}
	}
	if _, err := Find(ctx, "/p/c/authk.cue", "staging", "/p/c/.env"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning for a profile without agent, got %v", err)
	}
	// No agent for the config
	if _, err := Find(ctx, "/p/d/authk.cue", "default", "/p/d/.env"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning, got %v", err)
	}

	// By ID prefix
	got, err = FindByRef(ctx, front.ID[:12])
	if err != nil || got.ID != front.ID {
		t.Errorf("FindByRef(prefix) = %v, %v; want %s", got, err, front.ID)
	}
	if _, err := FindByRef(ctx, front.ID[:8]); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("a prefix shared by the 2 agents of config B must be ambiguous, got %v", err)
	}
	if _, err := FindByRef(ctx, "ffffffff"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning, got %v", err)
	}
}

func TestRegistry_RemovesStaleEntries(t *testing.T) {
	useRuntimeDir(t)

	// Entry of an agent that crashed: its socket does not exist anymore
	stale := Entry{ID: "deadbeef", PID: 999999, Socket: filepath.Join(Dir(), "deadbeef.sock"), ConfigPath: "/p/x/authk.cue"}
	if err := Register(stale); err != nil {
		t.Fatal(err)
	}

	agents, err := List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 0 {
		t.Errorf("stale agent listed: %+v", agents)
	}
	if _, err := os.Stat(entryPath("deadbeef")); !errors.Is(err, os.ErrNotExist) {
		t.Error("stale entry was not removed")
	}
}

func TestRegistry_FindByName(t *testing.T) {
	useRuntimeDir(t)
	ctx := context.Background()

	dev := runRegistered(t, "/p/app/authk.cue", "dev", "")
	runRegistered(t, "/work/api/authk.cue", "default", "")
	runRegistered(t, "/perso/api/authk.cue", "default", "")

	got, err := FindByRef(ctx, "app/dev")
	if err != nil || got.ID != dev.ID {
		t.Errorf("FindByRef(app/dev) = %v, %v; want %s", got, err, dev.ID)
	}

	// Two projects named api: the command must not pick one
	_, err = FindByRef(ctx, "api")
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("expected ErrAmbiguous, got %v", err)
	}
	for _, want := range []string{"/work/api/authk.cue", "/perso/api/authk.cue", "use the ID"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q misses %q", err, want)
		}
	}

	if _, err := FindByRef(ctx, "nope"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning, got %v", err)
	}
}
