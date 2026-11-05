package main

import (
	"fmt"
	"os"

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
updating a .env file with the valid token.

Run "authk agent" to keep the token valid. Running authk without a command
does the same but is deprecated.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	Args:          cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Fprintln(os.Stderr, `Warning: running authk without a command is deprecated, use "authk agent"`)
		return runAgent(cmd.Context(), cmd.Flags().Changed("env"))
	},
}

func printBanner() {
	banner := `
   __ _ _   _| |_| |__ | | __
  / _' | | | | __| '_ \| |/ /
 | (_| | |_| | |_| | | |   < 
  \__,_|\__,_|\__|_| |_|_|\_\
`
	fmt.Fprintln(os.Stderr, banner)
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
