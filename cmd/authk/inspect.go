package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/env"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var jsonOutput bool

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect the current token",
	Long:  `Read the token from the .env file and display its decoded content. Use the --json flag for machine-readable output.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Try to find config file
		if found, err := env.Find(cfgFile); err == nil {
			cfgFile = found
		}

		// Load Config
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Try to find .env file
		if found, err := env.Find(envFile); err == nil {
			envFile = found
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

		if jsonOutput {
			header, err := decodeSegment(parts[0])
			if err != nil {
				return fmt.Errorf("failed to decode header: %w", err)
			}
			payload, err := decodeSegment(parts[1])
			if err != nil {
				return fmt.Errorf("failed to decode payload: %w", err)
			}

			output := map[string]interface{}{
				"header":  header,
				"payload": payload,
			}

			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if err := enc.Encode(output); err != nil {
				return fmt.Errorf("failed to encode output: %w", err)
			}
			return nil
		}

		printJSON("Header", parts[0])
		printJSON("Payload", parts[1])

		return nil
	},
}

func decodeSegment(segment string) (interface{}, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, err
	}

	var obj interface{}
	if err := json.Unmarshal(decoded, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}

func printJSON(title, segment string) {
	// Header style
	headerStyle := color.New(color.FgCyan, color.Bold)
	headerStyle.Printf("--- %s ---\n", title)

	obj, err := decodeSegment(segment)
	if err != nil {
		fmt.Printf("Error decoding %s: %v\n", title, err)
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

			// Check if it's a timestamp key
			keyName := strings.Trim(parts[0], " \t\"")
			isTimestamp := false
			switch keyName {
			case "exp", "iat", "nbf", "auth_time", "updated_at":
				isTimestamp = true
			}

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
					fmt.Print(numberColor(val))

					if isTimestamp {
						cleanVal := strings.TrimSuffix(valTrimmed, ",")
													if ts, err := strconv.ParseInt(cleanVal, 10, 64); err == nil {
														tm := time.Unix(ts, 0)
														dateColor := color.New(color.Faint).SprintFunc()
														fmt.Print(dateColor(fmt.Sprintf(" (%s)", tm.Format("2006-01-02 15:04:05 MST"))))
													}					}
					fmt.Println()
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
	inspectCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as valid JSON without colors")
}