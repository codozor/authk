package kube

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/codozor/authk/internal/config"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// tokenAPI returns a fake clientset answering token requests with reply, and the
// requests it received.
func tokenAPI(t *testing.T, reply func(ns, name string, req *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error)) (*fake.Clientset, *[]k8stesting.CreateAction) {
	t.Helper()
	cs := fake.NewClientset()
	var calls []k8stesting.CreateAction
	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		create := a.(k8stesting.CreateAction)
		if create.GetSubresource() != "token" {
			t.Fatalf("unexpected subresource %q", create.GetSubresource())
		}
		calls = append(calls, create)
		resp, err := reply(create.GetNamespace(), create.(k8stesting.CreateActionImpl).Name,
			create.GetObject().(*authenticationv1.TokenRequest))
		return true, resp, err
	})
	return cs, &calls
}

func TestGetToken(t *testing.T) {
	expiry := time.Now().Add(42 * time.Minute).Truncate(time.Second)
	cs, calls := tokenAPI(t, func(ns, name string, req *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error) {
		if ns != "my-app" || name != "client" {
			t.Errorf("token requested for %s/%s", ns, name)
		}
		resp := req.DeepCopy()
		// The API server grants less than the requested hour
		resp.Status = authenticationv1.TokenRequestStatus{Token: "sa-jwt", ExpirationTimestamp: metav1.NewTime(expiry)}
		return resp, nil
	})
	p := &config.Profile{Provider: config.ProviderKubernetes, ServiceAccount: "client",
		Audiences: []string{"https://api.example.com"}, Duration: "1h"}
	c, err := newClient(cs, "kind-dev", "my-app", p)
	if err != nil {
		t.Fatal(err)
	}

	token, err := c.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}
	if token.AccessToken != "sa-jwt" || token.TokenType != "Bearer" || !token.Expiry.Equal(expiry) || token.RefreshToken != "" {
		t.Errorf("token = %+v, want sa-jwt expiring at %s", token, expiry)
	}
	spec := (*calls)[0].GetObject().(*authenticationv1.TokenRequest).Spec
	if !reflect.DeepEqual(spec.Audiences, p.Audiences) || spec.ExpirationSeconds == nil || *spec.ExpirationSeconds != 3600 {
		t.Errorf("requested spec = %+v", spec)
	}

	// Renewing asks a new token
	if _, err := c.RefreshToken(context.Background(), token); err != nil || len(*calls) != 2 {
		t.Errorf("RefreshToken() error = %v after %d requests", err, len(*calls))
	}
	if c.Context() != "kind-dev" || c.ServiceAccount() != "my-app/client" {
		t.Errorf("Context() = %q, ServiceAccount() = %q", c.Context(), c.ServiceAccount())
	}
}

func TestGetToken_DefaultDuration(t *testing.T) {
	cs, calls := tokenAPI(t, func(_, _ string, req *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error) {
		resp := req.DeepCopy()
		resp.Status.Token = "sa-jwt"
		return resp, nil
	})
	c, err := newClient(cs, "ctx", "default", &config.Profile{ServiceAccount: "client"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	spec := (*calls)[0].GetObject().(*authenticationv1.TokenRequest).Spec
	if spec.ExpirationSeconds != nil || len(spec.Audiences) != 0 {
		t.Errorf("without duration and audiences, the API server defaults must apply: %+v", spec)
	}
}

func TestGetToken_Errors(t *testing.T) {
	gr := schema.GroupResource{Resource: "serviceaccounts"}
	tests := map[string]struct {
		err  error
		want string
	}{
		"not found":    {apierrors.NewNotFound(gr, "client"), "service account my-app/client not found (context kind-dev)"},
		"forbidden":    {apierrors.NewForbidden(gr, "client", nil), `"create" on "serviceaccounts/token"`},
		"unauthorized": {apierrors.NewUnauthorized("bad token"), "credentials of the kubeconfig context kind-dev were rejected"},
		"other":        {apierrors.NewInternalError(os.ErrClosed), "failed to create a token for the service account my-app/client"},
		"no token":     {nil, "returned no token"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cs, _ := tokenAPI(t, func(_, _ string, req *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error) {
				return req.DeepCopy(), tt.err
			})
			c, err := newClient(cs, "kind-dev", "my-app", &config.Profile{ServiceAccount: "client"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.GetToken(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("GetToken() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

const kubeconfig = `apiVersion: v1
kind: Config
current-context: dev
clusters:
- name: c
  cluster: {server: "https://127.0.0.1:6443"}
users:
- name: u
  user: {token: "user-token"}
contexts:
- name: dev
  context: {cluster: c, user: u, namespace: team-a}
- name: other
  context: {cluster: c, user: u}
`

func TestNewClient_Kubeconfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		profile         config.Profile
		wantContext, sa string
	}{
		// Current context, and its namespace
		{config.Profile{Kubeconfig: path, ServiceAccount: "client"}, "dev", "team-a/client"},
		// A context without namespace: "default"
		{config.Profile{Kubeconfig: path, Context: "other", ServiceAccount: "client"}, "other", "default/client"},
		// The namespace of the profile wins
		{config.Profile{Kubeconfig: path, Namespace: "my-app", ServiceAccount: "client"}, "dev", "my-app/client"},
	}
	for _, tt := range tests {
		c, err := NewClient(&tt.profile)
		if err != nil {
			t.Fatalf("NewClient(%+v) error = %v", tt.profile, err)
		}
		if c.Context() != tt.wantContext || c.ServiceAccount() != tt.sa {
			t.Errorf("NewClient(%+v): context %q, account %q", tt.profile, c.Context(), c.ServiceAccount())
		}
	}

	// $KUBECONFIG is used without kubeconfig in the profile
	t.Setenv("KUBECONFIG", path)
	if c, err := NewClient(&config.Profile{ServiceAccount: "client"}); err != nil || c.Context() != "dev" {
		t.Errorf("NewClient() with $KUBECONFIG: %v, %v", c, err)
	}
}

func TestNewClient_Errors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]config.Profile{
		"missing kubeconfig": {Kubeconfig: filepath.Join(t.TempDir(), "nope"), ServiceAccount: "client"},
		"unknown context":    {Kubeconfig: path, Context: "prod", ServiceAccount: "client"},
	}
	for name, p := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClient(&p); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
