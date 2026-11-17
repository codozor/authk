//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// kubeConfig is the authk.cue of the Kubernetes tests (namespace, kubeconfig files).
const kubeConfig = `version: 2

profiles: sa: {
	provider:       "kubernetes"
	kubeconfig:     "admin.kubeconfig"
	namespace:      "%[1]s"
	serviceAccount: "client"
	audiences: ["%[2]s"]
	duration:       "20m"
	targets: [
		{key: "SA_TOKEN"},
		{format: "raw", file: "run/secrets/token"},
	]
}

// A user without RBAC permission on serviceaccounts/token
profiles: denied: {
	provider:       "kubernetes"
	kubeconfig:     "restricted.kubeconfig"
	serviceAccount: "client"
}

profiles: missing: {
	provider:       "kubernetes"
	kubeconfig:     "admin.kubeconfig"
	namespace:      "%[1]s"
	serviceAccount: "ghost"
}
`

const kubeAudience = "https://api.authk.test"

// kubeEnv is an authk environment with a namespace of the test cluster holding the
// service accounts client and nobody.
type kubeEnv struct {
	*env
	clientset *kubernetes.Clientset
	namespace string
}

func newKubeEnv(t *testing.T) *kubeEnv {
	t.Helper()
	if kubeconfig == "" {
		t.Skip("AUTHK_KUBECONFIG is not set")
	}
	ctx := context.Background()
	admin, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	restConfig, err := clientcmd.NewDefaultClientConfig(*admin, nil).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		t.Fatal(err)
	}

	suffix := make([]byte, 3)
	_, _ = rand.Read(suffix)
	namespace := "authk-it-" + hex.EncodeToString(suffix)
	if _, err := clientset.CoreV1().Namespaces().Create(ctx,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Namespaces().Delete(context.Background(), namespace, metav1.DeleteOptions{})
	})
	for _, name := range []string{"client", "nobody"} {
		if _, err := clientset.CoreV1().ServiceAccounts(namespace).Create(ctx,
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}

	e := &kubeEnv{
		env:       newEnvWithConfig(t, fmt.Sprintf(kubeConfig, namespace, kubeAudience)),
		clientset: clientset,
		namespace: namespace,
	}
	if err := clientcmd.WriteToFile(*admin, e.path("admin.kubeconfig")); err != nil {
		t.Fatal(err)
	}
	e.writeRestrictedKubeconfig(admin)
	return e
}

// writeRestrictedKubeconfig writes a kubeconfig authenticating as the service account
// nobody, which has no RBAC permission.
func (e *kubeEnv) writeRestrictedKubeconfig(admin *clientcmdapi.Config) {
	e.t.Helper()
	resp, err := e.clientset.CoreV1().ServiceAccounts(e.namespace).CreateToken(context.Background(), "nobody",
		&authenticationv1.TokenRequest{}, metav1.CreateOptions{})
	if err != nil {
		e.t.Fatal(err)
	}
	cfg := admin.DeepCopy()
	cluster := cfg.Contexts[cfg.CurrentContext].Cluster
	cfg.AuthInfos = map[string]*clientcmdapi.AuthInfo{"nobody": {Token: resp.Status.Token}}
	cfg.Contexts = map[string]*clientcmdapi.Context{
		"restricted": {Cluster: cluster, AuthInfo: "nobody", Namespace: e.namespace},
	}
	cfg.CurrentContext = "restricted"
	if err := clientcmd.WriteToFile(*cfg, e.path("restricted.kubeconfig")); err != nil {
		e.t.Fatal(err)
	}
}

// review checks a token with the API server (TokenReview), as a workload would.
func (e *kubeEnv) review(token string) authenticationv1.TokenReviewStatus {
	e.t.Helper()
	resp, err := e.clientset.AuthenticationV1().TokenReviews().Create(context.Background(),
		&authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: []string{kubeAudience}}},
		metav1.CreateOptions{})
	if err != nil {
		e.t.Fatal(err)
	}
	return resp.Status
}

type saClaims struct {
	Sub string   `json:"sub"`
	Aud []string `json:"aud"`
	Iat int64    `json:"iat"`
	Exp int64    `json:"exp"`
}

func decodeClaims(t *testing.T, token string) saClaims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c saClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestKubernetesGetAndExec(t *testing.T) {
	e := newKubeEnv(t)
	token := e.ok("get", "-p", "sa")
	requireJWT(t, "service account token", token)

	claims := decodeClaims(t, token)
	wantSub := "system:serviceaccount:" + e.namespace + ":client"
	if claims.Sub != wantSub || !slices.Contains(claims.Aud, kubeAudience) {
		t.Errorf("claims = %+v, want sub %s and audience %s", claims, wantSub, kubeAudience)
	}
	if d := time.Duration(claims.Exp-claims.Iat) * time.Second; d != 20*time.Minute {
		t.Errorf("token valid for %s, want the requested 20m", d)
	}
	if st := e.review(token); !st.Authenticated || st.User.Username != wantSub {
		t.Errorf("TokenReview = %+v", st)
	}

	out := e.ok("exec", "-p", "sa", "--", "sh", "-c", `printf %s "$SA_TOKEN"`)
	requireJWT(t, "SA_TOKEN", out)
}

func TestKubernetesAgentTargets(t *testing.T) {
	e := newKubeEnv(t)
	e.ok("agent", "-d", "-p", "sa")

	raw := e.path("run/secrets/token")
	readRaw := func() string {
		t.Helper()
		data, err := os.ReadFile(raw)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	first := readRaw()
	requireJWT(t, "raw token file", first) // the token alone, no newline
	if got := readEnvKey(t, e.path(".env"), "SA_TOKEN"); got != first {
		t.Fatal("the .env file and the raw file hold different tokens")
	}
	if info, err := os.Stat(raw); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("raw file mode = %v, %v", info.Mode().Perm(), err)
	}
	if got := e.ok("get", "-p", "sa"); got != first {
		t.Fatal("get did not return the agent token")
	}

	status := e.ok("agent", "status", "-p", "sa")
	for _, want := range []string{"Account:      " + e.namespace + "/client", raw + " (access_token, raw)"} {
		if !strings.Contains(status, want) {
			t.Errorf("status misses %q:\n%s", want, status)
		}
	}

	// iat has a one-second resolution: make sure the new token differs
	time.Sleep(1100 * time.Millisecond)
	e.ok("agent", "refresh", "-p", "sa")
	second := readRaw()
	if second == first || readEnvKey(t, e.path(".env"), "SA_TOKEN") != second {
		t.Fatal("agent refresh did not write a new token to both targets")
	}
	if !e.review(second).Authenticated {
		t.Fatal("the renewed token is not valid")
	}
	if entries, _ := os.ReadDir(filepath.Dir(raw)); len(entries) != 1 {
		t.Errorf("the token directory holds %d files, want only the token", len(entries))
	}
}

func TestKubernetesErrors(t *testing.T) {
	e := newKubeEnv(t)
	if stderr := e.fails("get", "-p", "denied"); !strings.Contains(stderr, `"create" on "serviceaccounts/token"`) {
		t.Errorf("denied: %s", stderr)
	}
	if stderr := e.fails("get", "-p", "missing"); !strings.Contains(stderr, "service account "+e.namespace+"/ghost not found") {
		t.Errorf("missing: %s", stderr)
	}
	if stderr := e.fails("login", "-p", "sa"); !strings.Contains(stderr, "needs no login") {
		t.Errorf("login: %s", stderr)
	}
}
