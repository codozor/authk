package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/codozor/authk/internal/agent"
	"github.com/spf13/cobra"
)

var (
	listJSON   bool
	listWide   bool
	logsFollow bool
)

var agentListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List running agents",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		agents, err := agent.List(cmd.Context())
		if err != nil {
			return err
		}
		if listJSON {
			return printAgentsJSON(cmd.OutOrStdout(), agents)
		}
		return printAgentsTable(cmd.OutOrStdout(), agents, listWide)
	},
}

var agentLogsCmd = &cobra.Command{
	Use:   "logs [NAME|ID]",
	Short: "Show the logs of a detached agent",
	Long: `Show the log file of the agent with the given name or ID (an ID prefix is enough), or of
the agent serving the current directory without argument. Only agents started with --detach have one.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := selectAgent(cmd.Context(), args)
		if err != nil {
			return err
		}
		st, err := client.Status(cmd.Context())
		if err != nil {
			return err
		}
		if st.LogFile == "" {
			return fmt.Errorf("agent %s was not started with --detach: it logs to its terminal", st.Name)
		}
		if !logsFollow {
			f, err := os.Open(st.LogFile)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			_, err = io.Copy(cmd.OutOrStdout(), f)
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return followFile(ctx, cmd.OutOrStdout(), st.LogFile)
	},
}

// listedAgent is the JSON form of a running agent.
type listedAgent struct {
	agent.Entry
	Status *agent.Status `json:"status,omitempty"`
	Error  string        `json:"error,omitempty"`
}

func printAgentsJSON(out io.Writer, agents []agent.Agent) error {
	list := make([]listedAgent, 0, len(agents))
	for _, a := range agents {
		la := listedAgent{Entry: a.Entry, Status: a.Status}
		if a.Err != nil {
			la.Error = a.Err.Error()
		}
		list = append(list, la)
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(list)
}

func printAgentsTable(out io.Writer, agents []agent.Agent, wide bool) error {
	if len(agents) == 0 {
		_, err := fmt.Fprintln(out, "No agent running")
		return err
	}
	home, _ := os.UserHomeDir()
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	header := "NAME\tPID\tSTARTED\tTOKEN\tMODE\tWRITES"
	if wide {
		header += "\tID\tCONFIG\tPROFILE"
	}
	_, _ = fmt.Fprintln(w, header)
	for _, a := range agents {
		mode := "foreground"
		if a.LogFile != "" {
			mode = "detached"
		}
		token, writes := "not responding", "?"
		if a.Status != nil {
			switch {
			case a.Status.Login != nil:
				token = "LOGIN (pending)"
			case a.Status.LoginRequired:
				token = "LOGIN"
			default:
				token = shortExpiry(a.Status.Expiry)
				if a.Status.LastError != "" {
					token += " (error)"
				}
			}
			files := make([]string, 0, len(a.Status.TargetFiles))
			for _, f := range a.Status.TargetFiles {
				files = append(files, tildePath(f, home))
			}
			writes = strings.Join(files, ", ")
			if writes == "" {
				writes = "-"
			}
		}
		row := fmt.Sprintf("%s\t%d\t%s\t%s\t%s\t%s",
			a.Name, a.PID, a.StartedAt.Local().Format("2006-01-02 15:04"), token, mode, writes)
		if wide {
			row += fmt.Sprintf("\t%s\t%s\t%s", a.ID, tildePath(a.ConfigPath, home), a.Profile)
		}
		_, _ = fmt.Fprintln(w, row)
	}
	return w.Flush()
}

// shortExpiry returns "4m12s", "EXPIRED" or "no expiry".
func shortExpiry(expiry time.Time) string {
	if expiry.IsZero() {
		return "no expiry"
	}
	remaining := time.Until(expiry).Round(time.Second)
	if remaining <= 0 {
		return "EXPIRED"
	}
	return remaining.String()
}

// tildePath shortens a path under the home directory to ~/...
func tildePath(path, home string) string {
	if home == "" {
		return path
	}
	if rel, err := filepath.Rel(home, path); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.Join("~", rel)
	}
	return path
}

// followFile prints path, then what is appended to it, until ctx is cancelled.
func followFile(ctx context.Context, out io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := io.Copy(out, f); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func init() {
	agentListCmd.Flags().BoolVar(&listJSON, "json", false, "Output as JSON")
	agentListCmd.Flags().BoolVarP(&listWide, "wide", "w", false, "Also show the ID, config file and profile")
	agentLogsCmd.Flags().BoolVarP(&logsFollow, "follow", "f", false, "Keep printing new log lines")
	agentCmd.AddCommand(agentListCmd, agentLogsCmd)
}
