package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/codozor/authk/internal/agent"
	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

// newOIDCClient returns the OIDC client of a profile, showing device logins on stderr.
func newOIDCClient(p *config.Profile) (*oidc.Client, error) {
	client, err := oidc.NewClient(p)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC client: %w", err)
	}
	client.OnDeviceLogin = func(l oidc.DeviceLogin) {
		printLoginPrompt(os.Stderr, devicePrompt(l))
	}
	return client, nil
}

func devicePrompt(l oidc.DeviceLogin) agent.LoginPrompt {
	return agent.LoginPrompt{
		URL:         l.VerificationURI,
		Code:        l.UserCode,
		CompleteURL: l.VerificationURIComplete,
		Expiry:      l.Expiry,
	}
}

// agentLogin adapts the device login of client for the agent refresher.
func agentLogin(client *oidc.Client) agent.LoginFunc {
	return func(ctx context.Context) (agent.LoginPrompt, func(context.Context) (*oauth2.Token, error), error) {
		l, err := client.StartDeviceLogin(ctx)
		if err != nil {
			return agent.LoginPrompt{}, nil, err
		}
		return devicePrompt(*l), l.Wait, nil
	}
}

// printLoginPrompt tells the user how to log in.
func printLoginPrompt(w io.Writer, p agent.LoginPrompt) {
	var b strings.Builder
	b.WriteString("\nLogin required.\n")
	if p.CompleteURL != "" {
		fmt.Fprintf(&b, "  Open:  %s\n", p.CompleteURL)
		fmt.Fprintf(&b, "  or open %s and enter the code %s\n", p.URL, p.Code)
	} else {
		fmt.Fprintf(&b, "  Open:  %s\n  Code:  %s\n", p.URL, p.Code)
	}
	if !p.Expiry.IsZero() {
		fmt.Fprintf(&b, "  The code expires at %s (in %s).\n", p.Expiry.Local().Format(time.TimeOnly),
			time.Until(p.Expiry).Round(time.Second))
	}
	b.WriteString("\n")
	_, _ = io.WriteString(w, b.String())
}

var agentLoginCmd = &cobra.Command{
	Use:   "login [NAME|ID]",
	Short: "Log in again for an agent whose flow needs the user",
	Long: `Start a login for the agent with the given name or ID (an ID prefix is enough), or for
the agent serving the current directory without argument, and wait until it succeeds.

Agents of interactive flows (device_code) cannot renew the token by themselves once the
session expired: "authk agent list" then shows LOGIN, and "authk get" fails until you log in.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		client, err := selectAgent(ctx, args)
		if err != nil {
			return err
		}
		started := time.Now()
		prompt, err := client.Login(ctx)
		if err != nil {
			return err
		}
		printLoginPrompt(cmd.ErrOrStderr(), *prompt)
		st, err := waitLogin(ctx, client, started)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Agent %s logged in, token %s\n", st.Name, describeExpiry(st.Expiry))
		return err
	},
}

// waitLogin follows the pending login of an agent, started after started, until it ends.
func waitLogin(ctx context.Context, client *agent.Client, started time.Time) (*agent.Status, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
		st, err := client.Status(ctx)
		if err != nil {
			return nil, err
		}
		if st.Login != nil {
			continue // still waiting for the user
		}
		if st.Ready && st.LastRenewal.After(started) {
			return st, nil
		}
		if st.LastError != "" {
			return nil, errors.New(st.LastError)
		}
		return nil, errors.New("login failed")
	}
}

func init() {
	agentCmd.AddCommand(agentLoginCmd)
}
