package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
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

var (
	statusJSON  bool
	stopAll     bool
	agentDetach bool
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Keep the token valid and serve it to other commands",
	Long: `Fetch a token, write it to the configured targets and renew it before it expires.
While it runs, "authk get" and "authk inspect" use its current token through a local
socket instead of authenticating again.

An agent serves one config file (and one .env file when the config has no targets).
Several agents can run at the same time: "authk agent list" shows them. Set AUTHK_SOCK
to use a specific socket path.

With --detach, the agent runs in the background and logs to a file
("authk agent logs").`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if agentDetach && !isDetachedChild() {
			return detachAgent(cmd)
		}
		return runAgent(cmd.Context(), cmd.Flags().Changed("env"))
	},
}

var agentStatusCmd = &cobra.Command{
	Use:   "status [ID]",
	Short: "Show the status of an agent",
	Long: `Show the status of the agent with the given ID (a prefix is enough), or of the agent
serving the current directory without ID.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := selectAgent(cmd.Context(), args)
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
	Use:   "refresh [ID]",
	Short: "Make an agent renew its token now",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := selectAgent(cmd.Context(), args)
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
	Use:   "stop [ID]",
	Short: "Stop an agent",
	Long: `Stop the agent with the given ID (a prefix is enough), the agent serving the current
directory without ID, or every agent with --all.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if stopAll {
			if len(args) > 0 {
				return errors.New("--all does not take an ID")
			}
			return stopAllAgents(cmd)
		}
		client, err := selectAgent(ctx, args)
		if err != nil {
			return err
		}
		st, err := client.Status(ctx)
		if err != nil {
			return err
		}
		if err := client.Stop(ctx); err != nil {
			return err
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Agent %s stopped\n", st.ID)
		return err
	},
}

func stopAllAgents(cmd *cobra.Command) error {
	agents, err := agent.List(cmd.Context())
	if err != nil {
		return err
	}
	if len(agents) == 0 {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "No agent running")
		return err
	}
	var errs []error
	for _, a := range agents {
		if err := agent.NewClient(a.Socket).Stop(cmd.Context()); err != nil {
			errs = append(errs, fmt.Errorf("agent %s: %w", a.ID, err))
			continue
		}
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Agent %s stopped\n", a.ID); err != nil {
			return err
		}
	}
	return errors.Join(errs...)
}

// runAgent runs the agent in the foreground. envChanged tells whether --env was given.
func runAgent(parent context.Context, envChanged bool) error {
	if !isDetachedChild() {
		printBanner()
	}
	setupLogger(zerolog.InfoLevel)

	profile, err := loadProfile()
	if err != nil {
		return err
	}
	resolveEnvFile()
	if envChanged && len(profile.Targets) > 0 {
		log.Warn().Msg("--env is ignored: the profile defines targets")
	}

	// The agent identity: the config and profile, and the .env file only when it is the target
	configPath, err := agent.CanonicalPath(cfgFile)
	if err != nil {
		return err
	}
	envKey := ""
	if len(profile.Targets) == 0 {
		if envKey, err = agent.CanonicalPath(envFile); err != nil {
			return err
		}
	}
	id := agent.ID(configPath, profile.Name, envKey, os.Getenv(agent.SocketEnv))
	socket := agent.SocketFor(id)

	// Fail fast, before authenticating, if an agent already serves the same files
	if _, err := agent.NewClient(socket).Status(parent); err == nil {
		return fmt.Errorf("%w (agent %s)", agent.ErrAlreadyRunning, id)
	}

	targets := buildTargets(profile)

	// Stop cleanly on Ctrl+C / SIGTERM, or when a client asks to
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := oidc.NewClient(profile)
	if err != nil {
		return fmt.Errorf("failed to initialize OIDC client: %w", err)
	}

	token, err := client.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get initial token: %w", err)
	}
	updateTargets(targets, token)

	ln, err := agent.Listen(socket)
	if err != nil {
		return err
	}
	entry := agent.Entry{
		ID:         id,
		PID:        os.Getpid(),
		Socket:     socket,
		ConfigPath: configPath,
		Profile:    profile.Name,
		EnvFile:    envKey,
		LogFile:    os.Getenv(logFileEnv),
		StartedAt:  time.Now(),
	}
	if err := agent.Register(entry); err != nil {
		_ = ln.Close()
		return err
	}
	defer func() {
		if err := agent.Unregister(id); err != nil {
			log.Warn().Err(err).Msg("Failed to unregister agent")
		}
	}()

	refresher := agent.NewRefresher(client, token, func(t *oauth2.Token) { updateTargets(targets, t) })
	info := agent.Info{
		ID:         id,
		LogFile:    entry.LogFile,
		ConfigPath: configPath,
		Profile:    profile.Name,
		Issuer:     profile.IssuerURL,
		ClientID:   profile.ClientID,
	}
	for _, t := range targets {
		info.Targets = append(info.Targets, fmt.Sprintf("%s (%s → %s)", t.File, t.Type, t.Key))
		if !slices.Contains(info.TargetFiles, t.File) {
			info.TargetFiles = append(info.TargetFiles, t.File)
		}
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return refresher.Run(gctx) })
	g.Go(func() error { return agent.Serve(gctx, ln, refresher, info, stop) })
	if err := g.Wait(); err != nil {
		return err
	}
	log.Info().Msg("Shutting down")
	return nil
}

// buildTargets returns the profile targets, or the default ones written to --env.
func buildTargets(p *config.Profile) []config.Target {
	if len(p.Targets) > 0 {
		log.Info().Int("count", len(p.Targets)).Str("profile", p.Name).Msg("Configured with multiple targets")
		return p.Targets
	}

	targets := []config.Target{{File: envFile, Key: p.EnvKeys.AccessToken, Type: agent.TypeAccessToken}}
	if p.EnvKeys.IDToken != "" {
		targets = append(targets, config.Target{File: envFile, Key: p.EnvKeys.IDToken, Type: agent.TypeIDToken})
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
	line("Agent", "%s, running (pid %d, since %s)", st.ID, st.PID, st.StartedAt.Format(time.DateTime))
	line("Config", "%s", st.ConfigPath)
	line("Profile", "%s", st.Profile)
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
	if st.LogFile != "" {
		line("Log file", "%s", st.LogFile)
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
	agentStopCmd.Flags().BoolVar(&stopAll, "all", false, "Stop every running agent")
	agentCmd.Flags().BoolVarP(&agentDetach, "detach", "d", false, "Run the agent in the background")
	agentCmd.AddCommand(agentStatusCmd, agentRefreshCmd, agentStopCmd)
	rootCmd.AddCommand(agentCmd)
}
