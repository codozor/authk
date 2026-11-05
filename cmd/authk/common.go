package main

import (
	"context"
	"fmt"
	"os"

	"github.com/codozor/authk/internal/agent"
	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/env"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/term"
)

// setupLogger configures the global logger on stderr, without colors when stderr is
// not a terminal (detached agent writing to a log file). --debug overrides the level.
func setupLogger(level zerolog.Level) {
	if debug {
		level = zerolog.DebugLevel
	}
	noColor := !term.IsTerminal(int(os.Stderr.Fd()))
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: noColor}).Level(level)
}

// findConfig looks for the config file in the current directory, its parents and the
// home directory, without loading it (loading resolves secrets, which may be slow).
func findConfig() {
	if found, err := env.Find(cfgFile); err == nil {
		cfgFile = found
	}
}

// loadConfig finds and loads the config file. All commands must use it to behave consistently.
func loadConfig() (*config.Config, error) {
	findConfig()

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	return cfg, nil
}

// resolveEnvFile sets envFile to the absolute path of the .env file to use with the
// config file (see env.ResolveEnvFile). findConfig must have been called.
func resolveEnvFile() {
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	home, _ := os.UserHomeDir()
	if resolved, err := env.ResolveEnvFile(envFile, cfgFile, cwd, home); err == nil {
		envFile = resolved
	}
}

// agentForContext returns a client for the agent serving the config and .env files
// found from the current directory, or for AUTHK_SOCK if set. It returns an error
// wrapping agent.ErrNotRunning if there is none.
func agentForContext(ctx context.Context) (*agent.Client, error) {
	if socket := os.Getenv(agent.SocketEnv); socket != "" {
		return agent.NewClient(socket), nil
	}

	findConfig()
	resolveEnvFile()
	configPath, err := agent.CanonicalPath(cfgFile)
	if err != nil {
		return nil, err
	}
	envPath, err := agent.CanonicalPath(envFile)
	if err != nil {
		return nil, err
	}
	a, err := agent.Find(ctx, configPath, envPath)
	if err != nil {
		return nil, err
	}
	return agent.NewClient(a.Socket), nil
}

// selectAgent returns a client for the agent whose ID starts with args[0], or for the
// agent of the current context without argument.
func selectAgent(ctx context.Context, args []string) (*agent.Client, error) {
	if len(args) == 0 {
		return agentForContext(ctx)
	}
	a, err := agent.FindByID(ctx, args[0])
	if err != nil {
		return nil, err
	}
	return agent.NewClient(a.Socket), nil
}
