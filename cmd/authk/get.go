package main

import (
	"fmt"
	"time"

	"github.com/codozor/authk/internal/agent"
	"github.com/codozor/authk/internal/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	showIDToken bool
	getNoAgent  bool
	getMinTTL   time.Duration
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a valid token",
	Long: `Print a valid token to stdout.

If an agent runs for this config ("authk agent"), its current token is printed: it is
renewed first if it expires within --min-ttl. Otherwise a new token is requested from the
OIDC provider.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		// Default to Error level to suppress Info logs (like "Using ... flow")
		setupLogger(zerolog.ErrorLevel)

		typ := agent.TypeAccessToken
		if showIDToken {
			typ = agent.TypeIDToken
		}

		if !getNoAgent {
			client, err := agentForContext(cmd.Context())
			if err != nil && !isNotRunning(err) {
				return err
			}
			var resp *agent.TokenResponse
			if err == nil {
				resp, err = client.Token(cmd.Context(), typ, getMinTTL)
			}
			if err == nil {
				log.Debug().Msg("Token served by the agent")
				_, err = fmt.Fprintln(cmd.OutOrStdout(), resp.Token)
				return err
			}
			// A running agent that fails must not be bypassed silently
			if !isNotRunning(err) {
				return err
			}
			log.Debug().Err(err).Msg("No agent, requesting a new token")
		}

		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		client, err := oidc.NewClient(cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize OIDC client: %w", err)
		}

		token, err := client.GetToken(cmd.Context(), "", "")
		if err != nil {
			return fmt.Errorf("failed to get token: %w", err)
		}

		value := token.AccessToken
		if showIDToken {
			idToken, ok := token.Extra("id_token").(string)
			if !ok || idToken == "" {
				return fmt.Errorf("no ID Token found in response")
			}
			value = idToken
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), value)
		return err
	},
}

func init() {
	getCmd.Flags().BoolVar(&showIDToken, "id-token", false, "Print ID Token instead of Access Token")
	getCmd.Flags().BoolVar(&getNoAgent, "no-agent", false, "Always request a new token, even if an agent runs")
	getCmd.Flags().DurationVar(&getMinTTL, "min-ttl", 10*time.Second, "Minimum remaining validity of a token served by the agent")
	rootCmd.AddCommand(getCmd)
}
