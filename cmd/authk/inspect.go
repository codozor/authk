package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/codozor/authk/internal/agent"
	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/env"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	jsonOutput     bool
	inspectID      bool
	inspectFromEnv bool
)

const (
	sourceAgent = "agent"
	sourceEnv   = "env"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect the current token",
	Long: `Display the decoded content of the current token.

If an agent runs for this config, its current token is inspected. Otherwise, or with
--from-env or --env, the token is read from the .env file, which shows what applications
actually read. Use the --json flag for machine-readable output.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		requestedType := agent.TypeAccessToken
		if inspectID {
			requestedType = agent.TypeIDToken
		}

		token, source, err := currentToken(cmd, requestedType)
		if err != nil {
			return err
		}

		// Parse JWT
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			return fmt.Errorf("invalid token format: expected 3 parts, got %d", len(parts))
		}

		header, err := decodeSegment(parts[0])
		if err != nil {
			return fmt.Errorf("failed to decode header: %w", err)
		}
		payload, err := decodeSegment(parts[1])
		if err != nil {
			return fmt.Errorf("failed to decode payload: %w", err)
		}

		if jsonOutput {
			output := map[string]interface{}{
				"source":  source,
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

		printTokenSummary(source, payload)
		printJSON("Header", parts[0])
		printJSON("Payload", parts[1])

		return nil
	},
}

// currentToken returns the token to inspect and where it comes from: the agent if it
// runs, the .env file otherwise or when asked to (--from-env, or --env given).
func currentToken(cmd *cobra.Command, requestedType string) (token, source string, err error) {
	if !inspectFromEnv && !cmd.Flags().Changed("env") {
		client, err := agentForContext(cmd.Context())
		if err != nil && !isNotRunning(err) {
			return "", "", err
		}
		var resp *agent.TokenResponse
		if err == nil {
			resp, err = client.Token(cmd.Context(), requestedType, 0)
		}
		if err == nil {
			return resp.Token, sourceAgent, nil
		}
		if !isNotRunning(err) {
			return "", "", err
		}
	}

	token, err = tokenFromEnv(cmd, requestedType)
	return token, sourceEnv, err
}

// tokenFromEnv reads the token of the requested type from the matching target file.
func tokenFromEnv(cmd *cobra.Command, requestedType string) (string, error) {
	profile, err := loadProfile()
	if err != nil {
		return "", err
	}
	resolveEnvFile()

	targets := resolveTargets(profile)

	// With --env, prefer the target writing that file; otherwise the first target of the type
	var target *config.Target
	if cmd.Flags().Changed("env") {
		for i, t := range targets {
			if t.File == envFile && t.Type == requestedType {
				target = &targets[i]
				break
			}
		}
	}
	if target == nil {
		for i, t := range targets {
			if t.Type == requestedType {
				target = &targets[i]
				break
			}
		}
	}
	if target == nil {
		return "", fmt.Errorf("profile %s has no %s target: nothing to read from a file (run an agent and use authk inspect without --from-env)",
			profile.Name, requestedType)
	}
	targetFile, targetKey := target.File, target.Key

	// Final check to find the file on disk (it might be in a parent directory)
	if foundPath, err := env.Find(targetFile); err == nil {
		targetFile = foundPath
	}

	token, err := env.NewManager(targetFile, targetKey).Get()
	if err != nil {
		return "", fmt.Errorf("failed to get token from .env: %w", err)
	}
	return token, nil
}

// printTokenSummary prints where the token comes from and when it expires.
func printTokenSummary(source string, payload interface{}) {
	headerStyle := color.New(color.FgCyan, color.Bold)
	_, _ = headerStyle.Println("--- Token ---")

	fmt.Printf("Source: %s\n", source)
	if claims, ok := payload.(map[string]interface{}); ok {
		if exp, ok := claims["exp"].(float64); ok {
			status := describeExpiry(time.Unix(int64(exp), 0))
			if strings.HasPrefix(status, "EXPIRED") {
				status = color.New(color.FgRed, color.Bold).Sprint(status)
			}
			fmt.Printf("Status: %s\n", status)
		}
	}
	fmt.Println()
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
	_, _ = headerStyle.Printf("--- %s ---\n", title)

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
						}
					}
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
	inspectCmd.Flags().BoolVar(&inspectID, "id-token", false, "Inspect the ID token instead of the Access token")
	inspectCmd.Flags().BoolVar(&inspectFromEnv, "from-env", false, "Read the token from the .env file even if an agent runs")
}
