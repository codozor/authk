package main

import (
	"fmt"

	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/oidc"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a valid token",
	Long:  `Get a valid token from the OIDC provider and print it to stdout.`,
	RunE: func(cmd *cobra.Command, args []string) error {
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

		fmt.Println(token.AccessToken)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
}
