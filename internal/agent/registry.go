package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrAmbiguous is returned when several agents match and none can be chosen.
var ErrAmbiguous = errors.New("ambiguous agent")

// pingTimeout bounds the status request used to check that a registered agent is alive.
const pingTimeout = 3 * time.Second

// Entry is the registration of a running agent, written in Dir() as <id>.json.
// It makes every agent discoverable, even one using a custom socket (AUTHK_SOCK).
type Entry struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	PID        int       `json:"pid"`
	Socket     string    `json:"socket"`
	ConfigPath string    `json:"configPath"`
	Profile    string    `json:"profile"`
	EnvFile    string    `json:"envFile,omitempty"` // only when the config has no targets
	LogFile    string    `json:"logFile,omitempty"` // only for a detached agent
	StartedAt  time.Time `json:"startedAt"`
}

// Agent is a registered agent with its live status. Status is nil and Err set if the
// agent did not answer in time.
type Agent struct {
	Entry
	Status *Status
	Err    error
}

func entryPath(id string) string {
	return filepath.Join(Dir(), id+".json")
}

// Register writes the registry entry of an agent.
func Register(e Entry) error {
	if err := ensurePrivateDir(Dir()); err != nil {
		return err
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(Dir(), "."+e.ID+".json-*")
	if err != nil {
		return fmt.Errorf("failed to register agent: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("failed to register agent: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), entryPath(e.ID)); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("failed to register agent: %w", err)
	}
	return nil
}

// Unregister removes the registry entry of an agent.
func Unregister(id string) error {
	if err := os.Remove(entryPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func readEntries() ([]Entry, error) {
	files, err := filepath.Glob(filepath.Join(Dir(), "*.json"))
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue // removed meanwhile
		}
		var e Entry
		if json.Unmarshal(data, &e) != nil || e.ID == "" {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// List returns the registered agents sorted by start time, with their live status.
// Entries of agents that are gone (their socket refuses connections) are removed.
func List(ctx context.Context) ([]Agent, error) {
	entries, err := readEntries()
	if err != nil {
		return nil, err
	}

	agents := make([]Agent, len(entries))
	alive := make([]bool, len(entries))
	var wg sync.WaitGroup
	for i, e := range entries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
			defer cancel()
			st, err := NewClient(e.Socket).Status(pingCtx)
			if errors.Is(err, ErrNotRunning) {
				removeStale(e)
				return
			}
			agents[i] = Agent{Entry: e, Status: st, Err: err}
			alive[i] = true
		}()
	}
	wg.Wait()

	var result []Agent
	for i, a := range agents {
		if alive[i] {
			result = append(result, a)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].StartedAt.Before(result[j].StartedAt) })
	return result, nil
}

// removeStale removes what an agent that crashed left behind.
func removeStale(e Entry) {
	_ = Unregister(e.ID)
	if filepath.Dir(e.Socket) == Dir() {
		_ = os.Remove(e.Socket)
	}
}

// Find returns the agent serving the profile of configPath for the .env file envFile
// (paths must be canonical):
//   - the only running agent of this profile, whatever its .env file: client and
//     credentials come from the profile, so its token is the right one;
//   - among several, the one writing envFile (or using the config targets);
//   - otherwise ErrAmbiguous, since their credentials may differ (ref+env:// secrets).
//
// It returns ErrNotRunning if no agent serves this config.
func Find(ctx context.Context, configPath, profile, envFile string) (*Agent, error) {
	agents, err := List(ctx)
	if err != nil {
		return nil, err
	}

	var candidates []Agent
	for _, a := range agents {
		if a.ConfigPath == configPath && a.Profile == profile {
			candidates = append(candidates, a)
		}
	}
	switch len(candidates) {
	case 0:
		return nil, ErrNotRunning
	case 1:
		return checkResponding(candidates[0])
	}

	var exact []Agent
	for _, a := range candidates {
		if envFile != "" && a.EnvFile == envFile {
			exact = append(exact, a)
		}
	}
	if len(exact) == 1 {
		return checkResponding(exact[0])
	}
	return nil, fmt.Errorf("%w for profile %s of %s: %s; use --env, an agent name or ID, or %s",
		ErrAmbiguous, profile, configPath, describe(candidates), SocketEnv)
}

// FindByRef returns the running agent named ref, or whose ID starts with ref.
// Several agents with that name give ErrAmbiguous, listing their configs and IDs.
func FindByRef(ctx context.Context, ref string) (*Agent, error) {
	agents, err := List(ctx)
	if err != nil {
		return nil, err
	}

	var named []Agent
	for _, a := range agents {
		if a.Name == ref {
			named = append(named, a)
		}
	}
	switch len(named) {
	case 1:
		return checkResponding(named[0])
	case 0:
	default:
		return nil, fmt.Errorf("%w: %d agents are named %s:\n%s\nuse the ID, or run the command from the project directory",
			ErrAmbiguous, len(named), ref, describeLines(named))
	}

	var matches []Agent
	for _, a := range agents {
		if a.ID == ref {
			return checkResponding(a)
		}
		if strings.HasPrefix(a.ID, ref) {
			matches = append(matches, a)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("%w: no agent named %s or with this ID", ErrNotRunning, ref)
	case 1:
		return checkResponding(matches[0])
	}
	return nil, fmt.Errorf("%w: ID prefix %s matches several agents:\n%s", ErrAmbiguous, ref, describeLines(matches))
}

func checkResponding(a Agent) (*Agent, error) {
	if a.Err != nil {
		return nil, fmt.Errorf("agent %s (pid %d) is not responding: %w", a.Name, a.PID, a.Err)
	}
	return &a, nil
}

func describe(agents []Agent) string {
	parts := make([]string, 0, len(agents))
	for _, a := range agents {
		target := a.EnvFile
		if target == "" {
			target = "config targets"
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", a.Name, target))
	}
	return strings.Join(parts, ", ")
}

// describeLines lists agents one per line: name, config and ID.
func describeLines(agents []Agent) string {
	lines := make([]string, 0, len(agents))
	for _, a := range agents {
		lines = append(lines, fmt.Sprintf("  %s  %s  (id %s)", a.Name, a.ConfigPath, a.ID))
	}
	return strings.Join(lines, "\n")
}
