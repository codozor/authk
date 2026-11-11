package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/codozor/authk/internal/agent"
	"github.com/codozor/authk/internal/config"
	"github.com/codozor/authk/internal/oidc"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// newOIDCClient returns the OIDC client of a profile, showing interactive logins on
// stderr (and opening the browser for authorization_code).
func newOIDCClient(p *config.Profile) (*oidc.Client, error) {
	client, err := oidc.NewClient(p)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC client: %w", err)
	}
	client.OnLogin = func(l *oidc.Login) {
		showLogin(os.Stderr, loginPrompt(l), l.Browser && stdinIsTerminal())
		if l.Browser {
			readPastedURLs(os.Stderr, l.Complete)
		}
	}
	return client, nil
}

func loginPrompt(l *oidc.Login) agent.LoginPrompt {
	return agent.LoginPrompt{
		URL:         l.URL,
		Code:        l.UserCode,
		CompleteURL: l.CompleteURL,
		Expiry:      l.Expiry,
		Browser:     l.Browser,
	}
}

// agentLogin adapts the interactive login of client for the agent refresher.
func agentLogin(client *oidc.Client) agent.LoginFunc {
	return func(ctx context.Context) (*agent.LoginSession, error) {
		l, err := client.StartLogin(ctx)
		if err != nil {
			return nil, err
		}
		session := &agent.LoginSession{Prompt: loginPrompt(l), Wait: l.Wait}
		if l.Browser {
			session.Complete = l.Complete
		}
		return session, nil
	}
}

// showLogin tells the user how to log in, and opens the browser for a browser login.
// canPaste tells whether the URL the browser ended on can be pasted in this terminal.
func showLogin(w io.Writer, p agent.LoginPrompt, canPaste bool) {
	var b strings.Builder
	b.WriteString("\nLogin required.\n")
	switch {
	case p.Browser:
		fmt.Fprintf(&b, "  Open:  %s\n", p.URL)
		if openBrowser(p.URL) {
			b.WriteString("  (opening it in your browser)\n")
		}
		if canPaste {
			b.WriteString("  If the browser cannot reach this machine, paste here the address it ended on\n" +
				"  (http://127.0.0.1:…/callback?…) and press Enter.\n")
		}
	case p.CompleteURL != "":
		fmt.Fprintf(&b, "  Open:  %s\n", p.CompleteURL)
		fmt.Fprintf(&b, "  or open %s and enter the code %s\n", p.URL, p.Code)
	default:
		fmt.Fprintf(&b, "  Open:  %s\n  Code:  %s\n", p.URL, p.Code)
	}
	if !p.Expiry.IsZero() {
		what := "code"
		if p.Browser {
			what = "login"
		}
		fmt.Fprintf(&b, "  The %s expires at %s (in %s).\n", what, p.Expiry.Local().Format(time.TimeOnly),
			time.Until(p.Expiry).Round(time.Second))
	}
	b.WriteString("\n")
	_, _ = io.WriteString(w, b.String())
}

func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// readPastedURLs passes each line typed in the terminal to complete, until one is
// accepted. It returns at once: lines are read in the background, and nothing is read
// when stdin is not a terminal.
func readPastedURLs(w io.Writer, complete func(string) error) {
	if !stdinIsTerminal() {
		return
	}
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 0, 64<<10), 64<<10)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if err := complete(line); err != nil {
				_, _ = fmt.Fprintf(w, "Not accepted: %v\n", err)
				continue
			}
			_, _ = fmt.Fprintln(w, "Accepted, logging in…")
			return
		}
	}()
}

// openBrowser opens url in the browser of the user, if there is one: $BROWSER (set by
// VS Code Remote terminals to open it on the local machine), else the desktop opener.
// It reports whether a browser was started.
func openBrowser(url string) bool {
	if os.Getenv("AUTHK_NO_BROWSER") != "" {
		return false
	}
	var cmd *exec.Cmd
	switch browser := os.Getenv("BROWSER"); {
	case browser != "":
		cmd = exec.Command(strings.Split(browser, string(os.PathListSeparator))[0], url)
	case runtime.GOOS == "darwin":
		cmd = exec.Command("open", url)
	case runtime.GOOS == "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "":
		cmd = exec.Command("xdg-open", url)
	default:
		return false
	}
	if err := cmd.Start(); err != nil {
		log.Debug().Err(err).Str("command", cmd.Path).Msg("Failed to open the browser")
		return false
	}
	go func() { _ = cmd.Wait() }()
	return true
}

var agentLoginCmd = &cobra.Command{
	Use:   "login [NAME|ID]",
	Short: "Log in again for an agent whose flow needs the user",
	Long: `Start a login for the agent with the given name or ID (an ID prefix is enough), or for
the agent serving the current directory without argument, and wait until it succeeds.

Agents of interactive flows (device_code, authorization_code) cannot renew the token by themselves once the
session expired: "authk agent list" then shows LOGIN, and "authk get" fails until you log in.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		client, err := selectAgent(ctx, args)
		if err != nil {
			return err
		}
		started := time.Now()
		prompt, err := client.Login(ctx)
		if err != nil {
			return err
		}
		showLogin(cmd.ErrOrStderr(), *prompt, prompt.Browser && stdinIsTerminal())
		if prompt.Browser {
			readPastedURLs(cmd.ErrOrStderr(), func(u string) error { return client.CompleteLogin(ctx, u) })
		}
		st, err := waitLogin(ctx, client, started)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Agent %s logged in, token %s\n", st.Name, describeExpiry(st.Expiry))
		return err
	},
}

// waitLogin follows the pending login of an agent, started after started, until it ends.
func waitLogin(ctx context.Context, client *agent.Client, started time.Time) (*agent.Status, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
		st, err := client.Status(ctx)
		if err != nil {
			return nil, err
		}
		if st.Login != nil {
			continue // still waiting for the user
		}
		if st.Ready && st.LastRenewal.After(started) {
			return st, nil
		}
		if st.LastError != "" {
			return nil, errors.New(st.LastError)
		}
		return nil, errors.New("login failed")
	}
}

func init() {
	agentCmd.AddCommand(agentLoginCmd)
}
