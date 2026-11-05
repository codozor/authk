package main

import (
	"fmt"

	"github.com/codozor/authk/internal/oidc"
	"github.com/rs/zerolog"
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
		// Default to Error level to suppress Info logs (like "Using ... flow")
		setupLogger(zerolog.ErrorLevel)

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
