package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// ErrNotRunning is returned by Client methods when no agent listens on the socket.
var ErrNotRunning = errors.New("agent is not running")

// Client talks to an agent over its socket.
type Client struct {
	socket string
	http   *http.Client
}

// NewClient returns a client for the agent listening on socket.
func NewClient(socket string) *Client {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return &Client{
		socket: socket,
		http: &http.Client{
			// Long enough for an on-demand renewal by the agent
			Timeout: renewTimeout + 5*time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

// Token returns a token of type typ valid for at least minTTL.
func (c *Client) Token(ctx context.Context, typ string, minTTL time.Duration) (*TokenResponse, error) {
	q := url.Values{"type": {typ}}
	if minTTL > 0 {
		q.Set("min_ttl", minTTL.String())
	}
	var resp TokenResponse
	if err := c.do(ctx, http.MethodGet, "/v1/token?"+q.Encode(), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Status returns the agent status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var st Status
	if err := c.do(ctx, http.MethodGet, "/v1/status", &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Refresh makes the agent renew its token now.
func (c *Client) Refresh(ctx context.Context) (*Status, error) {
	var st Status
	if err := c.do(ctx, http.MethodPost, "/v1/refresh", &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Login starts an interactive login (or returns the pending one). Follow it with Status.
func (c *Client) Login(ctx context.Context) (*LoginPrompt, error) {
	var prompt LoginPrompt
	if err := c.do(ctx, http.MethodPost, "/v1/login", &prompt); err != nil {
		return nil, err
	}
	return &prompt, nil
}

// CompleteLogin finishes the pending browser login of the agent with the URL the browser
// was redirected to.
func (c *Client) CompleteLogin(ctx context.Context, redirectURL string) error {
	body, err := json.Marshal(loginCompleteRequest{URL: redirectURL})
	if err != nil {
		return err
	}
	return c.doBody(ctx, http.MethodPost, "/v1/login/complete", body, nil)
}

// Stop asks the agent to stop.
func (c *Client) Stop(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/stop", nil)
}

func (c *Client) do(ctx context.Context, method, path string, out any) error {
	return c.doBody(ctx, method, path, nil, out)
}

func (c *Client) doBody(ctx context.Context, method, path string, in []byte, out any) error {
	if _, err := os.Stat(c.socket); errors.Is(err, os.ErrNotExist) {
		return ErrNotRunning
	}

	// The host is ignored: requests go to the socket
	var reqBody io.Reader
	if in != nil {
		reqBody = bytes.NewReader(in)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://authk"+path, reqBody)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			// Stale socket of a crashed agent, or no permission
			return fmt.Errorf("%w: %v", ErrNotRunning, opErr.Err)
		}
		return fmt.Errorf("agent request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("failed to read agent response: %w", err)
	}
	if resp.StatusCode >= 300 {
		var e errorResponse
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			if e.Code == codeLoginRequired {
				// The message already says login required
				return &loginRequiredError{msg: e.Error}
			}
			return fmt.Errorf("agent: %s", e.Error)
		}
		return fmt.Errorf("agent: unexpected status %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("invalid agent response: %w", err)
	}
	return nil
}

// loginRequiredError is an ErrLoginRequired reported by an agent, with its message.
type loginRequiredError struct{ msg string }

func (e *loginRequiredError) Error() string { return "agent: " + e.msg }

func (e *loginRequiredError) Is(target error) bool { return target == ErrLoginRequired }
