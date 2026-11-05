package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/env"
	"github.com/codozor/authk/internal/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var (
	cfgFile string
	envFile string
	debug   bool
)

var rootCmd = &cobra.Command{
	Use:   "authk",
	Short: "OIDC Token Maintainer",
	Long: `authk establishes and maintains an OIDC connection, 
updating a .env file with the valid token.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		printBanner()
		setupLogger(zerolog.InfoLevel)

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		resolveEnvFile()

		// Prepare targets
		var targets []config.Target
		if len(cfg.Targets) > 0 {
			targets = cfg.Targets
			log.Info().Int("count", len(targets)).Msg("Configured with multiple targets")
		} else {
			targets = append(targets, config.Target{
				File: envFile,
				Key:  cfg.TokenKey,
				Type: "access_token",
			})
			if cfg.IDTokenKey != "" {
				targets = append(targets, config.Target{
					File: envFile,
					Key:  cfg.IDTokenKey,
					Type: "id_token",
				})
			}
			log.Info().Str("env_file", envFile).Msg("Configured with default targets")
		}

		// Stop cleanly on Ctrl+C / SIGTERM
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		// Initialize OIDC Client
		client, err := oidc.NewClient(cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize OIDC client: %w", err)
		}

		// Initial Token Retrieval
		token, err := client.GetToken(ctx, "", "")
		if err != nil {
			return fmt.Errorf("failed to get initial token: %w", err)
		}

		updateTargets(targets, token)

		if err := newRefresher(client, func(t *oauth2.Token) { updateTargets(targets, t) }).run(ctx, token); err != nil {
			return err
		}
		log.Info().Msg("Shutting down")
		return nil
	},
}

// updateTargets writes the current tokens to every target.
func updateTargets(targets []config.Target, t *oauth2.Token) {
	for _, target := range targets {
		var tokenValue string
		switch target.Type {
		case "id_token":
			idToken, ok := t.Extra("id_token").(string)
			if !ok || idToken == "" {
				log.Warn().Str("file", target.File).Msg("ID Token requested but not found in response")
				continue
			}
			tokenValue = idToken
		default: // access_token
			tokenValue = t.AccessToken
		}

		mgr := env.NewManager(target.File, target.Key)
		if err := mgr.Update(tokenValue); err != nil {
			log.Error().Err(err).Str("file", target.File).Str("type", target.Type).Msg("Failed to update token")
		} else {
			log.Info().Str("file", target.File).Str("type", target.Type).Msg("Token updated")
		}
	}
}

func printBanner() {
	banner := `
   __ _ _   _| |_| |__ | | __
  / _' | | | | __| '_ \| |/ /
 | (_| | |_| | |_| | | |   < 
  \__,_|\__,_|\__|_| |_|_|\_\
`
	fmt.Println(banner)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "authk.cue", "config file (default is authk.cue)")
	rootCmd.PersistentFlags().StringVar(&envFile, "env", ".env", "env file (default is .env)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logging")
}
