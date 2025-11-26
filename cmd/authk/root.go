package main

import (
	"fmt"
	"os"
	"time"

	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/env"
	"github.com/codozor/authk/internal/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	envFile string
	debug   bool
)

var rootCmd = &cobra.Command{
	Use:   "authk",
	Short: "OIDC Token Maintainer",
	Long: `authk establishes and maintains an OIDC connection, 
updating a .env file with the valid token.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		printBanner()

		// Setup Logger with Pretty Print
		logLevel := zerolog.InfoLevel
		if debug {
			logLevel = zerolog.DebugLevel
		}
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(logLevel)

		// Load Config
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		log.Info().Str("env_file", envFile).Str("token_key", cfg.TokenKey).Msg("Starting authk")

		// Initialize OIDC Client
		client, err := oidc.NewClient(cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize OIDC client: %w", err)
		}

		// Initialize Env Manager
		envMgr := env.NewManager(envFile, cfg.TokenKey)

		// Initial Token Retrieval
		token, err := client.GetToken("", "")
		if err != nil {
			return fmt.Errorf("failed to get initial token: %w", err)
		}

		if err := envMgr.Update(token.AccessToken); err != nil {
			log.Error().Err(err).Msg("Failed to update .env")
		} else {
			log.Info().Msg("Token updated in .env")
		}

		// Maintenance Loop
		for {
			// Calculate sleep time (expires_in - 60s buffer)
			sleepDuration := time.Duration(token.ExpiresIn-60) * time.Second
			if sleepDuration < 10*time.Second {
				sleepDuration = 10 * time.Second
			}

			log.Info().Dur("sleep_duration", sleepDuration).Msg("Waiting for token refresh")
			time.Sleep(sleepDuration)

			token, err = client.RefreshToken(token.RefreshToken)
			if err != nil {
				log.Error().Err(err).Msg("Failed to refresh token")
				// Retry after short delay? Or exit?
				// Let's retry after 10s
				time.Sleep(10 * time.Second)
				continue
			}

			if err := envMgr.Update(token.AccessToken); err != nil {
				log.Error().Err(err).Msg("Failed to update .env")
			} else {
				log.Info().Msg("Token refreshed and updated in .env")
			}
		}
	},
}

func printBanner() {
	banner := `
   __ _ _   _| |_| |__ | | __
  / _' | | | | __| '_ \| |/ /
 | (_| | |_| | |_| | | |   < 
  \__,_|\__,_|\__|_| |_|_|\_\
`
	fmt.Println(banner)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "authk.cue", "config file (default is authk.cue)")
	rootCmd.PersistentFlags().StringVar(&envFile, "env", ".env", "env file (default is .env)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logging")
}
