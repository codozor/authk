package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/codozor/authk/internal/agent"
	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in and keep the session for the next commands",
	Long: `Log in (device_code and authorization_code flows) and store the session, so that
"authk get" and new agents use it without asking you to log in. It logs in again even
if a session is stored, e.g. to change user.

Running agents of the profile switch to the new session.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		setupLogger(zerolog.WarnLevel)
		ctx := cmd.Context()

		profile, err := loadProfile()
		if err != nil {
			return err
		}
		if !profile.Interactive() {
			return fmt.Errorf("profile %s uses the %s flow: it needs no login, authk authenticates by itself", profile.Name, profile.Flow)
		}
		s, err := newSession(profile)
		if err != nil {
			return err
		}
		if s.keeper == nil {
			return fmt.Errorf(`profile %s has tokenStore "none": the session cannot be kept, run "authk agent" instead`, profile.Name)
		}

		token, err := s.Client.GetToken(ctx)
		if err != nil {
			return err
		}
		if token.RefreshToken == "" {
			return errors.New("logged in, but the provider returned no refresh token: nothing to keep (add the offline_access scope)")
		}
		if err := s.keeper.Save(ctx, token); err != nil {
			return err
		}

		out := cmd.OutOrStdout()
		msg := "Logged in"
		if who := tokenUser(token); who != "" {
			msg += " as " + who
		}
		_, _ = fmt.Fprintf(out, "%s, session stored in the %s\n", msg, s.keeper.Backend())
		for _, a := range profileAgents(cmd, profile) {
			if a.Status == nil || !a.Status.Ready {
				continue
			}
			// The agent finds the newer stored session when it refreshes
			if _, err := agent.NewClient(a.Socket).Refresh(ctx); err != nil {
				log.Warn().Err(err).Str("agent", a.Name).Msg("The agent did not switch to the new session")
				continue
			}
			_, _ = fmt.Fprintf(out, "Agent %s switched to the new session\n", a.Name)
		}
		return nil
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Forget the stored session and revoke it",
	Long: `Delete the stored session of the profile (device_code and authorization_code flows),
and revoke it at the provider, which ends it there too. The next command will ask you
to log in.

Running agents keep their current access token until it expires, then need a login:
stop them with "authk agent stop".`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		setupLogger(zerolog.WarnLevel)
		ctx := cmd.Context()
		out := cmd.OutOrStdout()

		profile, err := loadProfile()
		if err != nil {
			return err
		}
		if !profile.Interactive() {
			return fmt.Errorf("profile %s uses the %s flow: no session is stored", profile.Name, profile.Flow)
		}
		// Forgetting needs no network: the provider is only contacted to revoke
		keeper, err := newKeeper(profile)
		if err != nil {
			return err
		}
		if keeper == nil {
			return fmt.Errorf(`profile %s has tokenStore "none": no session is stored`, profile.Name)
		}
		refreshToken, err := keeper.Forget(ctx)
		if err != nil {
			return err
		}
		if refreshToken == "" {
			_, _ = fmt.Fprintf(out, "No stored session for profile %s\n", profile.Name)
		} else {
			_, _ = fmt.Fprintf(out, "Stored session of profile %s deleted\n", profile.Name)
			if err := revoke(cmd, profile, refreshToken); err != nil {
				_, _ = fmt.Fprintf(out, "Not revoked: %v\nThe session stays valid at the provider until it expires.\n", err)
			} else {
				_, _ = fmt.Fprintln(out, "Session revoked at the provider")
			}
		}

		for _, a := range profileAgents(cmd, profile) {
			if a.Status == nil || !a.Status.Ready {
				continue
			}
			_, _ = fmt.Fprintf(out, "Agent %s keeps its access token, which %s: stop it with \"authk agent stop %s\"\n",
				a.Name, describeExpiry(a.Status.Expiry), a.Name)
		}
		return nil
	},
}

// revoke revokes a refresh token at the provider of the profile.
func revoke(cmd *cobra.Command, p *config.Profile, refreshToken string) error {
	client, err := oidc.NewClient(p)
	if err != nil {
		return err
	}
	return client.Revoke(cmd.Context(), refreshToken)
}

// profileAgents returns the running agents of the profile, whatever their .env file.
func profileAgents(cmd *cobra.Command, p *config.Profile) []agent.Agent {
	configPath, err := agent.CanonicalPath(cfgFile)
	if err != nil {
		return nil
	}
	agents, err := agent.List(cmd.Context())
	if err != nil {
		log.Debug().Err(err).Msg("Cannot list agents")
		return nil
	}
	var found []agent.Agent
	for _, a := range agents {
		if a.ConfigPath == configPath && a.Profile == p.Name {
			found = append(found, a)
		}
	}
	return found
}

// tokenUser returns who logged in, from the ID Token (already verified by the client).
func tokenUser(token *oauth2.Token) string {
	raw, _ := token.Extra("id_token").(string)
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
		Subject           string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	for _, v := range []string{claims.PreferredUsername, claims.Email, claims.Subject} {
		if v != "" {
			return v
		}
	}
	return ""
}

func init() {
	rootCmd.AddCommand(loginCmd, logoutCmd)
}
