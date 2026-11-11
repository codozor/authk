package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/codozor/authk/internal/agent"
	"github.com/spf13/cobra"
)

const (
	// detachedEnv marks the background process started by --detach.
	detachedEnv = "AUTHK_DETACHED"
	// logFileEnv gives the detached agent its log file, recorded in its registry entry.
	logFileEnv = "AUTHK_LOG_FILE"

	// detachTimeout bounds the wait for the detached agent to be ready (first token).
	detachTimeout = 2 * time.Minute
	// detachLoginGrace is how long the wait goes on after the login code expired, for
	// the agent to report the failure.
	detachLoginGrace = 15 * time.Second
	// logRetention is how long logs of stopped agents are kept.
	logRetention = 7 * 24 * time.Hour
)

func isDetachedChild() bool {
	return os.Getenv(detachedEnv) == "1"
}

// logDir returns the directory of detached agent logs: $XDG_STATE_HOME/authk/logs,
// ~/.local/state/authk/logs, or the user cache directory on other systems.
func logDir() (string, error) {
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "authk", "logs"), nil
	}
	home, err := os.UserHomeDir()
	if err == nil && runtime.GOOS != "windows" {
		return filepath.Join(home, ".local", "state", "authk", "logs"), nil
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, "authk", "logs"), nil
}

// detachAgent starts the agent in the background, waits until it serves its first
// token, and prints its name. For an interactive flow, it shows the login prompt of the
// agent meanwhile. If the agent fails to start, its log is printed.
func detachAgent(cmd *cobra.Command) error {
	dir, err := logDir()
	if err != nil {
		return fmt.Errorf("failed to find the log directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create the log directory: %w", err)
	}
	pruneLogs(dir)

	logPath := filepath.Join(dir, "agent-"+time.Now().Format("20060102-150405.000")+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create the log file: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		_ = logFile.Close()
		return fmt.Errorf("failed to find the authk executable: %w", err)
	}
	child := exec.Command(exe, withoutDetachFlag(os.Args[1:])...)
	child.Stdout = logFile
	child.Stderr = logFile
	child.Env = append(os.Environ(), detachedEnv+"=1", logFileEnv+"="+logPath)
	setDetachAttrs(child)

	if err := child.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("failed to start the agent: %w", err)
	}
	_ = logFile.Close() // the child keeps its own descriptor

	exited := make(chan error, 1)
	go func() { exited <- child.Wait() }()

	ctx := cmd.Context()
	deadline := time.After(detachTimeout)
	prompted := false
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-exited:
			// The log only explains the failure: print it and drop it
			printLogTail(cmd, logPath)
			_ = os.Remove(logPath)
			if err == nil {
				err = errors.New("exited")
			}
			return fmt.Errorf("agent failed to start (%v)", err)
		case <-deadline:
			_ = child.Process.Kill()
			printLogTail(cmd, logPath)
			return fmt.Errorf("agent not ready after %s, log: %s", detachTimeout, logPath)
		case <-ctx.Done():
			_ = child.Process.Kill()
			return ctx.Err()
		case <-ticker.C:
			agents, err := agent.List(ctx)
			if err != nil {
				continue
			}
			for _, a := range agents {
				if a.PID != child.Process.Pid || a.Status == nil {
					continue
				}
				if a.Status.Ready {
					_, err := fmt.Fprintf(cmd.OutOrStdout(), "Agent %s started in the background (pid %d)\nLogs: authk agent logs %s\n",
						a.Name, a.PID, a.Name)
					return err
				}
				// Interactive flow: the agent waits for the user, until the code expires
				if l := a.Status.Login; l != nil && !prompted {
					canPaste := l.Browser && stdinIsTerminal()
					showLogin(cmd.ErrOrStderr(), *l, canPaste)
					if canPaste {
						agentClient := agent.NewClient(a.Socket)
						readPastedURLs(cmd.ErrOrStderr(), func(u string) error { return agentClient.CompleteLogin(ctx, u) })
					}
					prompted = true
					if !l.Expiry.IsZero() {
						deadline = time.After(time.Until(l.Expiry) + detachLoginGrace)
					}
				}
			}
		}
	}
}

// withoutDetachFlag removes --detach / -d from the command line of the child.
func withoutDetachFlag(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		switch {
		case a == "--detach", a == "-d", strings.HasPrefix(a, "--detach="):
			continue
		}
		out = append(out, a)
	}
	return out
}

// printLogTail prints the end of a log file to stderr, to explain a failed start.
func printLogTail(cmd *cobra.Command, path string) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return
	}
	const maxTail = 4096
	if len(data) > maxTail {
		data = data[len(data)-maxTail:]
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "--- agent log ---\n%s\n-----------------\n", strings.TrimRight(string(data), "\n"))
}

// pruneLogs removes logs older than logRetention.
func pruneLogs(dir string) {
	files, err := filepath.Glob(filepath.Join(dir, "agent-*.log"))
	if err != nil {
		return
	}
	for _, f := range files {
		if info, err := os.Stat(f); err == nil && time.Since(info.ModTime()) > logRetention {
			_ = os.Remove(f)
		}
	}
}
