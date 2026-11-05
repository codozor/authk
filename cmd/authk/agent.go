package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/codozor/authk/internal/agent"
	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/env"
	"github.com/codozor/authk/internal/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

var statusJSON bool

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Keep the token valid and serve it to other commands",
	Long: `Run in the foreground: fetch a token, write it to the configured targets and renew it
before it expires. While it runs, "authk get" and "authk inspect" use its current token
through a local socket instead of authenticating again.

One agent runs per config file. Set AUTHK_SOCK to use a specific socket path.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runAgent(cmd.Context())
	},
}

var agentStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the status of the agent",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		client, err := agentClient()
		if err != nil {
			return err
		}
		st, err := client.Status(cmd.Context())
		if err != nil {
			return err
		}
		return printStatus(cmd, st)
	},
}

var agentRefreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Make the agent renew its token now",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		client, err := agentClient()
		if err != nil {
			return err
		}
		st, err := client.Refresh(cmd.Context())
		if err != nil {
			return err
		}
		return printStatus(cmd, st)
	},
}

var agentStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the agent",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		client, err := agentClient()
		if err != nil {
			return err
		}
		if err := client.Stop(cmd.Context()); err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Agent stopped")
		return err
	},
}

func runAgent(parent context.Context) error {
	printBanner()
	setupLogger(zerolog.InfoLevel)

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	resolveEnvFile()

	socket, err := agent.SocketPath(cfgFile)
	if err != nil {
		return err
	}
	// Fail fast, before authenticating, if an agent already serves this config
	if _, err := agent.NewClient(socket).Status(parent); err == nil {
		return fmt.Errorf("%w (socket %s)", agent.ErrAlreadyRunning, socket)
	}

	targets := buildTargets(cfg)

	// Stop cleanly on Ctrl+C / SIGTERM, or when a client asks to
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := oidc.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize OIDC client: %w", err)
	}

	token, err := client.GetToken(ctx, "", "")
	if err != nil {
		return fmt.Errorf("failed to get initial token: %w", err)
	}
	updateTargets(targets, token)

	refresher := agent.NewRefresher(client, token, func(t *oauth2.Token) { updateTargets(targets, t) })
	info := agent.Info{
		ConfigPath: cfgFile,
		Issuer:     cfg.OIDC.IssuerURL,
		ClientID:   cfg.OIDC.ClientID,
	}
	for _, t := range targets {
		info.Targets = append(info.Targets, fmt.Sprintf("%s (%s → %s)", t.File, t.Type, t.Key))
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return refresher.Run(gctx) })
	g.Go(func() error { return agent.Serve(gctx, socket, refresher, info, stop) })
	if err := g.Wait(); err != nil {
		return err
	}
	log.Info().Msg("Shutting down")
	return nil
}

// buildTargets returns the configured targets, or the default ones written to --env.
func buildTargets(cfg *config.Config) []config.Target {
	if len(cfg.Targets) > 0 {
		log.Info().Int("count", len(cfg.Targets)).Msg("Configured with multiple targets")
		return cfg.Targets
	}

	targets := []config.Target{{File: envFile, Key: cfg.TokenKey, Type: agent.TypeAccessToken}}
	if cfg.IDTokenKey != "" {
		targets = append(targets, config.Target{File: envFile, Key: cfg.IDTokenKey, Type: agent.TypeIDToken})
	}
	log.Info().Str("env_file", envFile).Msg("Configured with default targets")
	return targets
}

// updateTargets writes the current tokens to every target.
func updateTargets(targets []config.Target, t *oauth2.Token) {
	for _, target := range targets {
		var tokenValue string
		switch target.Type {
		case agent.TypeIDToken:
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

func printStatus(cmd *cobra.Command, st *agent.Status) error {
	out := cmd.OutOrStdout()
	if statusJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}

	var b strings.Builder
	line := func(label, format string, args ...any) {
		fmt.Fprintf(&b, "%-14s"+format+"\n", append([]any{label + ":"}, args...)...)
	}
	line("Agent", "running (pid %d, since %s)", st.PID, st.StartedAt.Format(time.DateTime))
	line("Config", "%s", st.ConfigPath)
	line("Issuer", "%s", st.Issuer)
	line("Client", "%s", st.ClientID)
	line("Token", "%s", describeExpiry(st.Expiry))
	line("Last renewal", "%s", st.LastRenewal.Format(time.DateTime))
	line("Refresh", "%t", st.HasRefreshToken)
	line("ID Token", "%t", st.HasIDToken)
	if st.LastError != "" {
		line("Last error", "%s", st.LastError)
	}
	for _, t := range st.Targets {
		line("Target", "%s", t)
	}
	_, err := io.WriteString(out, b.String())
	return err
}

// describeExpiry returns a human-readable expiry, e.g. "expires in 4m12s (2026-11-05 10:00:00)".
func describeExpiry(expiry time.Time) string {
	if expiry.IsZero() {
		return "no expiry"
	}
	remaining := time.Until(expiry).Round(time.Second)
	if remaining <= 0 {
		return fmt.Sprintf("EXPIRED %s ago (%s)", -remaining, expiry.Local().Format(time.DateTime))
	}
	return fmt.Sprintf("expires in %s (%s)", remaining, expiry.Local().Format(time.DateTime))
}

// isNotRunning reports whether err means that no agent serves the config.
func isNotRunning(err error) bool {
	return errors.Is(err, agent.ErrNotRunning)
}

func init() {
	for _, c := range []*cobra.Command{agentStatusCmd, agentRefreshCmd} {
		c.Flags().BoolVar(&statusJSON, "json", false, "Output as JSON")
	}
	agentCmd.AddCommand(agentStatusCmd, agentRefreshCmd, agentStopCmd)
	rootCmd.AddCommand(agentCmd)
}
