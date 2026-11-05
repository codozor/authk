package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
func runRegistered(t *testing.T, configPath, envFile string) Entry {
	t.Helper()
	id := ID(configPath, envFile, "")
	socket := SocketFor(id)
	ln, err := Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	e := Entry{ID: id, PID: os.Getpid(), Socket: socket, ConfigPath: configPath, EnvFile: envFile, StartedAt: time.Now()}
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
	a := runRegistered(t, "/p/a/authk.cue", "")
	// Two agents on config B, one per .env file
	front := runRegistered(t, "/p/b/authk.cue", "/p/b/front/.env")
	runRegistered(t, "/p/b/authk.cue", "/p/b/back/.env")

	agents, err := List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 3 {
		t.Fatalf("expected 3 agents, got %d", len(agents))
	}

	// Single agent of the config: used whatever the .env file
	got, err := Find(ctx, "/p/a/authk.cue", "/p/a/whatever/.env")
	if err != nil || got.ID != a.ID {
		t.Errorf("Find(A) = %v, %v; want %s", got, err, a.ID)
	}
	// Several agents: the one writing the .env file
	got, err = Find(ctx, "/p/b/authk.cue", "/p/b/front/.env")
	if err != nil || got.ID != front.ID {
		t.Errorf("Find(B, front) = %v, %v; want %s", got, err, front.ID)
	}
	// Several agents, none writing this .env file: ambiguous
	if _, err := Find(ctx, "/p/b/authk.cue", "/p/b/.env"); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("expected ErrAmbiguous, got %v", err)
	}
	// No agent for the config
	if _, err := Find(ctx, "/p/c/authk.cue", "/p/c/.env"); !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning, got %v", err)
	}

	// By ID prefix
	got, err = FindByID(ctx, front.ID[:12])
	if err != nil || got.ID != front.ID {
		t.Errorf("FindByID(prefix) = %v, %v; want %s", got, err, front.ID)
	}
	if _, err := FindByID(ctx, front.ID[:8]); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("a prefix shared by the 2 agents of config B must be ambiguous, got %v", err)
	}
	if _, err := FindByID(ctx, "ffffffff"); !errors.Is(err, ErrNotRunning) {
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
