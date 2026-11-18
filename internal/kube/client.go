// Package kube gets service account tokens from the Kubernetes API (TokenRequest), like
// "kubectl create token".
package kube

import (
	"context"
	"errors"
	"fmt"

	"github.com/codozor/authk/internal/config"
	"golang.org/x/oauth2"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Client asks tokens for one service account.
type Client struct {
	clientset kubernetes.Interface
	context   string // kubeconfig context used
	namespace string
	account   string
	request   authenticationv1.TokenRequestSpec
}

// NewClient returns the client of a Kubernetes profile, from its kubeconfig: the
// kubeconfig field, else $KUBECONFIG, else ~/.kube/config. It needs no network.
func NewClient(p *config.Profile) (*Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if p.Kubeconfig != "" {
		rules.ExplicitPath = p.Kubeconfig
	}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules,
		&clientcmd.ConfigOverrides{CurrentContext: p.Context})

	raw, err := loader.RawConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load the kubeconfig: %w", err)
	}
	contextName := p.Context
	if contextName == "" {
		contextName = raw.CurrentContext
	}
	restConfig, err := loader.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig context %q: %w", contextName, err)
	}
	namespace := p.Namespace
	if namespace == "" {
		if namespace, _, err = loader.Namespace(); err != nil {
			return nil, fmt.Errorf("kubeconfig context %q: %w", contextName, err)
		}
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create the Kubernetes client: %w", err)
	}
	return newClient(clientset, contextName, namespace, p)
}

// newClient returns a client using clientset, for a resolved context and namespace.
func newClient(clientset kubernetes.Interface, contextName, namespace string, p *config.Profile) (*Client, error) {
	c := &Client{
		clientset: clientset,
		context:   contextName,
		namespace: namespace,
		account:   p.ServiceAccount,
		request:   authenticationv1.TokenRequestSpec{Audiences: p.Audiences},
	}
	d, err := p.TokenDuration()
	if err != nil {
		return nil, err
	}
	if d > 0 {
		seconds := int64(d.Seconds())
		c.request.ExpirationSeconds = &seconds
	}
	return c, nil
}

// Context returns the kubeconfig context used.
func (c *Client) Context() string { return c.context }

// ServiceAccount returns the service account, as namespace/name.
func (c *Client) ServiceAccount() string { return c.namespace + "/" + c.account }

// GetToken asks a new token for the service account. Its expiry is the one granted by
// the API server, which may be shorter than the requested duration.
func (c *Client) GetToken(ctx context.Context) (*oauth2.Token, error) {
	req := &authenticationv1.TokenRequest{Spec: c.request}
	resp, err := c.clientset.CoreV1().ServiceAccounts(c.namespace).CreateToken(ctx, c.account, req, metav1.CreateOptions{})
	if err != nil {
		return nil, c.explain(err)
	}
	if resp.Status.Token == "" {
		return nil, fmt.Errorf("the Kubernetes API returned no token for the service account %s", c.ServiceAccount())
	}
	return &oauth2.Token{
		AccessToken: resp.Status.Token,
		TokenType:   "Bearer",
		Expiry:      resp.Status.ExpirationTimestamp.Time,
	}, nil
}

// RefreshToken asks a new token: service account tokens have no refresh token.
func (c *Client) RefreshToken(ctx context.Context, _ *oauth2.Token) (*oauth2.Token, error) {
	return c.GetToken(ctx)
}

// explain turns the common API errors into messages saying what to fix.
func (c *Client) explain(err error) error {
	sa := c.ServiceAccount()
	switch {
	case apierrors.IsNotFound(err):
		return fmt.Errorf("service account %s not found (context %s): %w", sa, c.context, err)
	case apierrors.IsForbidden(err):
		return fmt.Errorf("not allowed to create tokens for the service account %s (context %s): "+
			"your kubeconfig user needs the RBAC permission \"create\" on \"serviceaccounts/token\": %w", sa, c.context, err)
	case apierrors.IsUnauthorized(err):
		return fmt.Errorf("the credentials of the kubeconfig context %s were rejected: %w", c.context, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	}
	return fmt.Errorf("failed to create a token for the service account %s (context %s): %w", sa, c.context, err)
}
