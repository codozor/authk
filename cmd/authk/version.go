package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of authk",
	Long:  `All software has versions. This is authk's`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("authk %s\n", version)
		fmt.Printf("  Commit: %s\n", commit)
		fmt.Printf("  Date:   %s\n", date)
		fmt.Printf("  Go:     %s\n", runtime.Version())
		fmt.Printf("  OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
