package main

import (
	"fmt"
	"os"

	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	showIDToken bool
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a valid token",
	Long:  `Get a valid token from the OIDC provider and print it to stdout.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Setup Logger
		// Default to Error level to suppress Info logs (like "Using ... flow")
		// unless debug is enabled.
		logLevel := zerolog.ErrorLevel
		if debug {
			logLevel = zerolog.DebugLevel
		}
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(logLevel)

		// Load Config
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Initialize OIDC Client
		client, err := oidc.NewClient(cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize OIDC client: %w", err)
		}

		// Get Token
		token, err := client.GetToken("", "")
		if err != nil {
			return fmt.Errorf("failed to get token: %w", err)
		}

		if showIDToken {
			idToken, ok := token.Extra("id_token").(string)
			if !ok || idToken == "" {
				return fmt.Errorf("no ID Token found in response")
			}
			fmt.Println(idToken)
		} else {
			fmt.Println(token.AccessToken)
		}
		return nil
	},
}

func init() {
	getCmd.Flags().BoolVar(&showIDToken, "id-token", false, "Print ID Token instead of Access Token")
	rootCmd.AddCommand(getCmd)
}
