package main

import (
	"fmt"
	"os"

	"github.com/codozor/authk/internal/agent"
	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/env"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// setupLogger configures the global logger on stderr. --debug overrides the given level.
func setupLogger(level zerolog.Level) {
	if debug {
		level = zerolog.DebugLevel
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(level)
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

// resolveEnvFile looks for the .env file in the current directory, its parents and the
// home directory. If it is not found, the flag value is kept as is.
func resolveEnvFile() {
	if found, err := env.Find(envFile); err == nil {
		envFile = found
	}
}

// agentClient returns a client for the agent serving the config file.
func agentClient() (*agent.Client, error) {
	findConfig()
	socket, err := agent.SocketPath(cfgFile)
	if err != nil {
		return nil, err
	}
	return agent.NewClient(socket), nil
}
