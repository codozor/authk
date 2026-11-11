package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/codozor/authk/internal/agent"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	showIDToken bool
	getDirect   bool
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
		tokens, err := fetchTokens(cmd.Context(), []string{typ}, false, getMinTTL, getDirect)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), tokens[typ])
		return err
	},
}

// fetchTokens returns the tokens of the given types (agent.TypeAccessToken,
// agent.TypeIDToken): from the agent serving the current context, unless direct, and
// otherwise from the provider (stored session or login for interactive flows). With
// idOptional, a missing ID Token is left out of the result instead of failing.
func fetchTokens(ctx context.Context, types []string, idOptional bool, minTTL time.Duration, direct bool) (map[string]string, error) {
	tokens := make(map[string]string, len(types))
	if !direct {
		client, err := agentForContext(ctx)
		if err != nil && !isNotRunning(err) {
			return nil, err
		}
		if err == nil {
			for _, typ := range types {
				var resp *agent.TokenResponse
				resp, err = client.Token(ctx, typ, minTTL)
				if err != nil && idOptional && errors.Is(err, agent.ErrNoIDToken) {
					err = nil
					continue
				}
				if err != nil {
					break
				}
				tokens[typ] = resp.Token
			}
		}
		if err == nil {
			log.Debug().Msg("Token served by the agent")
			return tokens, nil
		}
		// A running agent that fails must not be bypassed silently
		if !isNotRunning(err) {
			return nil, err
		}
		log.Debug().Err(err).Msg("No agent, requesting a new token")
	}

	profile, err := loadProfile()
	if err != nil {
		return nil, err
	}
	client, err := newSession(profile)
	if err != nil {
		return nil, err
	}
	client.noPrompt = !stderrIsTerminal()

	token, err := client.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	for _, typ := range types {
		switch typ {
		case agent.TypeIDToken:
			idToken, ok := token.Extra("id_token").(string)
			if !ok || idToken == "" {
				if idOptional {
					continue
				}
				return nil, agent.ErrNoIDToken
			}
			tokens[typ] = idToken
		default:
			tokens[typ] = token.AccessToken
		}
	}
	return tokens, nil
}

func init() {
	getCmd.Flags().BoolVar(&showIDToken, "id-token", false, "Print ID Token instead of Access Token")
	getCmd.Flags().BoolVar(&getDirect, "direct", false, "Request a new token from the provider directly, bypassing any running agent")
	getCmd.Flags().DurationVar(&getMinTTL, "min-ttl", 10*time.Second, "Minimum remaining validity of a token served by the agent")
	rootCmd.AddCommand(getCmd)
}
