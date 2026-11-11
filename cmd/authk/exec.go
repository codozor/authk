package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/codozor/authk/internal/agent"
	"github.com/codozor/authk/internal/config"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

var (
	execVarFlags []string
	execMinTTL   time.Duration
	execDirect   bool
)

var execCmd = &cobra.Command{
	Use:   "exec [flags] [--] COMMAND [ARGS...]",
	Short: "Run a command with the token in its environment",
	Long: `Run a command with valid tokens in environment variables, without writing them
to a file. The tokens come from the agent serving the profile if one runs (renewed
first if they expire within --min-ttl), otherwise from the provider, as with "authk get".

Variables: the keys of the profile targets (a target {key: "TOKEN"} gives TOKEN=<access
token>), or ACCESS_TOKEN and ID_TOKEN (when the provider returns one) for a profile
without targets. --var replaces them: --var TOKEN for the access token, --var
ID=id_token for the ID Token.

The environment of a process cannot change once started: a command running longer
than the token lifetime must get new tokens itself ("authk get"), or use an agent
writing a .env file.

On Unix, authk replaces itself with the command: signals and the exit code are the
command's own.`,
	Example: `  authk exec -- terraform apply
  authk exec -p me --var API_TOKEN -- ./script.sh
  authk exec --var TOKEN --var ID=id_token -- env`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		setupLogger(zerolog.ErrorLevel)

		vars, err := execVars(execVarFlags)
		if err != nil {
			return err
		}
		types, idOptional := varTypes(vars)
		tokens, err := fetchTokens(cmd.Context(), types, idOptional, execMinTTL, execDirect)
		if err != nil {
			return err
		}

		path, err := exec.LookPath(args[0])
		if err != nil {
			return err
		}
		env := os.Environ()
		for _, v := range vars {
			if token, ok := tokens[v.Type]; ok {
				env = setEnv(env, v.Name, token)
			}
		}
		return runCommand(path, args, env)
	},
}

// execVar is an environment variable receiving a token.
type execVar struct {
	Name     string
	Type     string // agent.TypeAccessToken or agent.TypeIDToken
	Optional bool   // left unset when the provider returned no ID Token
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// execVars returns the variables to set: from --var flags, otherwise the targets of the
// profile, otherwise ACCESS_TOKEN and ID_TOKEN.
func execVars(flags []string) ([]execVar, error) {
	if len(flags) > 0 {
		return parseVarFlags(flags)
	}
	// Only the structure of the config is needed: secrets are resolved later, if needed
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	name, err := cfg.ProfileName(profileFlag())
	if err != nil {
		return nil, err
	}
	return targetVars(cfg.Profiles[name].Targets)
}

func parseVarFlags(flags []string) ([]execVar, error) {
	var vars []execVar
	for _, f := range flags {
		name, typ, found := strings.Cut(f, "=")
		if !found {
			typ = agent.TypeAccessToken
		}
		if !envNameRe.MatchString(name) {
			return nil, fmt.Errorf("--var %s: invalid variable name %q", f, name)
		}
		if typ != agent.TypeAccessToken && typ != agent.TypeIDToken {
			return nil, fmt.Errorf("--var %s: unknown token type %q (access_token or id_token)", f, typ)
		}
		vars = appendVar(vars, execVar{Name: name, Type: typ})
		if vars == nil {
			return nil, fmt.Errorf("--var %s: %s is given twice with different token types", f, name)
		}
	}
	return vars, nil
}

func targetVars(targets []config.Target) ([]execVar, error) {
	if len(targets) == 0 {
		return []execVar{
			{Name: "ACCESS_TOKEN", Type: agent.TypeAccessToken},
			{Name: "ID_TOKEN", Type: agent.TypeIDToken, Optional: true},
		}, nil
	}
	var vars []execVar
	for _, t := range targets {
		typ := t.Type
		if typ == "" {
			typ = agent.TypeAccessToken
		}
		vars = appendVar(vars, execVar{Name: t.Key, Type: typ})
		if vars == nil {
			return nil, fmt.Errorf("the targets of the profile write different tokens to %s: choose with --var", t.Key)
		}
	}
	return vars, nil
}

// appendVar appends v unless a variable of that name exists. It returns nil if the
// existing one has another type.
func appendVar(vars []execVar, v execVar) []execVar {
	i := slices.IndexFunc(vars, func(e execVar) bool { return e.Name == v.Name })
	switch {
	case i < 0:
		return append(vars, v)
	case vars[i].Type != v.Type:
		return nil
	}
	return vars
}

// varTypes returns the token types to fetch, and whether the ID Token is optional
// (only optional variables need it).
func varTypes(vars []execVar) (types []string, idOptional bool) {
	idOptional = true
	for _, v := range vars {
		if !slices.Contains(types, v.Type) {
			types = append(types, v.Type)
		}
		if v.Type == agent.TypeIDToken && !v.Optional {
			idOptional = false
		}
	}
	return types, idOptional
}

// setEnv sets name in env (KEY=value entries), replacing an existing entry.
func setEnv(env []string, name, value string) []string {
	prefix := name + "="
	env = slices.DeleteFunc(env, func(e string) bool { return strings.HasPrefix(e, prefix) })
	return append(env, prefix+value)
}

// exitError carries the exit code of the command run by exec.
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// exitCode returns the exit code of the command run by exec, if err comes from it.
func exitCode(err error) (int, bool) {
	var e *exitError
	if errors.As(err, &e) {
		return e.code, true
	}
	return 0, false
}

func init() {
	execCmd.Flags().StringArrayVar(&execVarFlags, "var", nil, "Variable to set: NAME (access token) or NAME=id_token; repeatable (default: the keys of the profile targets)")
	execCmd.Flags().DurationVar(&execMinTTL, "min-ttl", time.Minute, "Minimum remaining validity of the tokens")
	execCmd.Flags().BoolVar(&execDirect, "direct", false, "Request new tokens from the provider directly, bypassing any running agent")
	// Flags after the command belong to it: authk exec ls -l
	execCmd.Flags().SetInterspersed(false)
	rootCmd.AddCommand(execCmd)
}
