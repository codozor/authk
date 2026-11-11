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
	agentName   string
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
	Use:   "status [NAME|ID]",
	Short: "Show the status of an agent",
	Long: `Show the status of the agent with the given name or ID (an ID prefix is enough), or of
the agent serving the current directory without argument.`,
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
	Use:   "refresh [NAME|ID]",
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
	Use:   "stop [NAME|ID]",
	Short: "Stop an agent",
	Long: `Stop the agent with the given name or ID (an ID prefix is enough), the agent serving
the current directory without argument, or every agent with --all.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if stopAll {
			if len(args) > 0 {
				return errors.New("--all does not take an agent name")
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
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Agent %s stopped\n", st.Name)
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
			errs = append(errs, fmt.Errorf("agent %s: %w", a.Name, err))
			continue
		}
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Agent %s stopped\n", a.Name); err != nil {
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
	if envChanged && !profile.UsesEnvFile() {
		log.Warn().Str("profile", profile.Name).Msg("--env is ignored: no target of the profile writes to the .env file")
	}

	// The agent identity: the config and profile, and the .env file only when a target writes it
	configPath, err := agent.CanonicalPath(cfgFile)
	if err != nil {
		return err
	}
	envKey := ""
	if profile.UsesEnvFile() {
		if envKey, err = agent.CanonicalPath(envFile); err != nil {
			return err
		}
	}
	id := agent.ID(configPath, profile.Name, envKey, os.Getenv(agent.SocketEnv))
	socket := agent.SocketFor(id)
	name := agentName
	if name == "" {
		home, _ := os.UserHomeDir()
		name = agent.Name(configPath, profile.Name, envKey, home)
	}

	// Fail fast, before authenticating, if this agent would conflict with a running one
	if err := checkConflicts(parent, id, name, configPath, profile); err != nil {
		return err
	}

	targets := buildTargets(profile)

	// Stop cleanly on Ctrl+C / SIGTERM, or when a client asks to
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := newSession(profile)
	if err != nil {
		return err
	}

	// Interactive flows restore the stored session, or log in once the agent serves, so
	// that a detached agent can show the login prompt through its status. Others fail
	// fast before.
	interactive := client.Interactive()
	var token *oauth2.Token
	if interactive {
		if token, err = client.restore(ctx); err != nil {
			return err
		}
	} else if token, err = client.GetToken(ctx); err != nil {
		return fmt.Errorf("failed to get initial token: %w", err)
	}
	if token != nil {
		updateTargets(targets, token)
	}

	ln, err := agent.Listen(socket)
	if err != nil {
		return err
	}
	entry := agent.Entry{
		ID:         id,
		Name:       name,
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
	if interactive {
		refresher.SetLogin(client.agentLogin())
	}
	info := agent.Info{
		ID:         id,
		Name:       name,
		LogFile:    entry.LogFile,
		ConfigPath: configPath,
		Profile:    profile.Name,
		Issuer:     profile.Issuer,
		ClientID:   profile.ClientID,
	}
	if interactive {
		info.TokenStore = client.keeper.Backend()
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
	if token == nil {
		g.Go(func() error { return initialLogin(gctx, refresher) })
	}
	if err := g.Wait(); err != nil {
		return err
	}
	log.Info().Msg("Shutting down")
	return nil
}

// initialLogin runs the first login of an interactive flow. Its failure stops the agent.
func initialLogin(ctx context.Context, r *agent.Refresher) error {
	l, err := r.StartLogin(ctx, ctx)
	if err != nil {
		return fmt.Errorf("failed to start login: %w", err)
	}
	if !isDetachedChild() {
		canPaste := l.Prompt.Browser && stdinIsTerminal()
		showLogin(os.Stderr, l.Prompt, canPaste)
		if canPaste {
			readPastedURLs(os.Stderr, r.CompleteLogin)
		}
	}
	select {
	case <-l.Done():
	case <-ctx.Done():
		return nil
	}
	if err := l.Err(); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// checkConflicts refuses to start an agent that would serve or write the same things
// as a running one, or take the name given with --name.
func checkConflicts(ctx context.Context, id, name, configPath string, p *config.Profile) error {
	agents, err := agent.List(ctx)
	if err != nil {
		return err
	}
	for _, a := range agents {
		switch {
		case a.ID == id:
			return fmt.Errorf("%w (agent %s)", agent.ErrAlreadyRunning, a.Name)
		case a.ConfigPath == configPath && a.Profile == p.Name && p.HasFileTargets():
			// Several agents of a profile only differ by their project .env: targets with
			// a fixed file would be written by all of them, with different tokens.
			return fmt.Errorf("agent %s already serves profile %s, and its targets with a file would be written by both agents "+
				"(several agents of a profile are only possible when all its targets are without file)", a.Name, p.Name)
		case agentName != "" && a.Name == name:
			return fmt.Errorf("the name %s is already used by another agent (%s)", name, a.ConfigPath)
		}
	}
	return nil
}

// buildTargets returns the profile targets, with the .env file (found from the current
// directory, or --env) for targets without file. resolveEnvFile must have been called.
func buildTargets(p *config.Profile) []config.Target {
	targets := resolveTargets(p)
	if len(targets) == 0 {
		log.Info().Str("profile", p.Name).Msg("No targets: the token is only served by the agent (authk get)")
		return nil
	}
	for _, t := range targets {
		log.Info().Str("file", t.File).Str("key", t.Key).Str("type", t.Type).Msg("Target")
	}
	return targets
}

// resolveTargets returns the profile targets with the .env file set on targets
// without file. resolveEnvFile must have been called.
func resolveTargets(p *config.Profile) []config.Target {
	targets := make([]config.Target, 0, len(p.Targets))
	for _, t := range p.Targets {
		if t.File == "" {
			t.File = envFile
		}
		targets = append(targets, t)
	}
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
	line("Agent", "%s, running (pid %d, since %s)", st.Name, st.PID, st.StartedAt.Format(time.DateTime))
	line("ID", "%s", st.ID)
	line("Config", "%s", st.ConfigPath)
	line("Profile", "%s", st.Profile)
	line("Issuer", "%s", st.Issuer)
	line("Client", "%s", st.ClientID)
	switch {
	case !st.Ready:
		line("Token", "none yet")
	case st.LoginRequired:
		line("Token", "%s, cannot be renewed", describeExpiry(st.Expiry))
	default:
		line("Token", "%s", describeExpiry(st.Expiry))
	}
	if st.LoginRequired && st.Login == nil {
		line("Login", "required: run \"authk agent login %s\"", st.Name)
	}
	if l := st.Login; l != nil {
		line("Login", "pending: open %s and enter the code %s", l.URL, l.Code)
	}
	if st.TokenStore != "" {
		session := "stored in " + st.TokenStore
		if st.TokenStore == "none" {
			session = "not stored (tokenStore: none)"
		}
		if !st.SessionExpiry.IsZero() {
			session += ", " + describeExpiry(st.SessionExpiry)
		}
		line("Session", "%s", session)
	}
	if !st.LastRenewal.IsZero() {
		line("Last renewal", "%s", st.LastRenewal.Format(time.DateTime))
	}
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
	agentCmd.Flags().StringVar(&agentName, "name", "", "Name of the agent (default: <project>/<profile>)")
	agentCmd.AddCommand(agentStatusCmd, agentRefreshCmd, agentStopCmd)
	rootCmd.AddCommand(agentCmd)
}
