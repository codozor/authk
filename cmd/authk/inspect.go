package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/env"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect the current token",
	Long:  `Read the token from the .env file and display its decoded content.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load Config
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Initialize Env Manager
		envMgr := env.NewManager(envFile, cfg.TokenKey)

		// Get Token
		token, err := envMgr.Get()
		if err != nil {
			return fmt.Errorf("failed to get token from .env: %w", err)
		}

		// Parse JWT
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			return fmt.Errorf("invalid token format: expected 3 parts, got %d", len(parts))
		}

		printJSON("Header", parts[0])
		printJSON("Payload", parts[1])

		return nil
	},
}

func printJSON(title, segment string) {
	// Header style
	headerStyle := color.New(color.FgCyan, color.Bold)
	headerStyle.Printf("--- %s ---\n", title)

	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		fmt.Printf("Error decoding %s: %v\n", title, err)
		return
	}

	var obj interface{}
	if err := json.Unmarshal(decoded, &obj); err != nil {
		fmt.Printf("Error unmarshaling %s: %v\n", title, err)
		return
	}

	pretty, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		fmt.Printf("Error pretty printing %s: %v\n", title, err)
		return
	}

	// Simple syntax highlighting for JSON keys
	jsonStr := string(pretty)
	lines := strings.Split(jsonStr, "\n")
	keyColor := color.New(color.FgBlue).SprintFunc()
	stringColor := color.New(color.FgGreen).SprintFunc()
	numberColor := color.New(color.FgYellow).SprintFunc()
	boolColor := color.New(color.FgMagenta).SprintFunc()

	for _, line := range lines {
		// Very basic highlighting
		if strings.Contains(line, "\":") {
			parts := strings.SplitN(line, "\":", 2)
			key := parts[0] + "\""
			val := ":" + parts[1]

			// Colorize key
			fmt.Print(keyColor(key))

			// Try to colorize value
			valTrimmed := strings.TrimSpace(parts[1])
			if strings.HasPrefix(valTrimmed, "\"") {
				fmt.Println(stringColor(val))
			} else if valTrimmed == "true" || valTrimmed == "false" {
				fmt.Println(boolColor(val))
			} else if valTrimmed == "null" {
				fmt.Println(color.New(color.FgRed).Sprint(val))
			} else {
				// Assume number or object/array start
				if strings.ContainsAny(valTrimmed, "0123456789") {
					fmt.Println(numberColor(val))
				} else {
					fmt.Println(val)
				}
			}
		} else {
			fmt.Println(line)
		}
	}
	fmt.Println()
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}
