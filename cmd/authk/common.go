package main

import (
	"fmt"
	"os"

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

// loadConfig looks for the config file in the current directory, its parents and the
// home directory, then loads it. All commands must use it to behave consistently.
func loadConfig() (*config.Config, error) {
	if found, err := env.Find(cfgFile); err == nil {
		cfgFile = found
	}

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
