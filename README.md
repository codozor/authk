# authk

[![Go Report Card](https://goreportcard.com/badge/github.com/codozor/authk)](https://goreportcard.com/report/github.com/codozor/authk)
![Build](https://img.shields.io/github/actions/workflow/status/codozor/authk/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/codozor/authk/badge.svg)](https://coveralls.io/github/codozor/authk)
![Version](https://img.shields.io/github/v/release/codozor/authk)
![License](https://img.shields.io/github/license/codozor/authk)
![Go Version](https://img.shields.io/github/go-mod/go-version/codozor/authk)

`authk` is a CLI tool designed to establish and maintain an OIDC connection. It automatically updates a `.env` file with a valid access token, ensuring your development environment always has fresh credentials.
 
![Authk Workflow](assets/authk_workflow.png)

## Features

- **OIDC Integration**: Supports Client Credentials and Resource Owner Password Credentials flows.
- **Automatic Refresh**: Monitors token expiration and refreshes it automatically.
- **.env Management**: Updates a specific key in your `.env` file with the new token.
- **Configurable**: Uses CUE for flexible and type-safe configuration.

## Installation

```bash
go install github.com/codozor/authk/cmd/authk@latest
```

Or build from source:

```bash
git clone https://github.com/codozor/authk.git
cd authk
go build -o authk ./cmd/authk
```

## Configuration

`authk` uses a CUE configuration file (default: `authk.cue`).

Create a `authk.cue` file with your OIDC provider details:

```cue
package config

oidc: {
	issuerUrl:    "https://your-oidc-provider.com"
	clientId:     "your-client-id"
	clientSecret: "your-client-secret" // Optional, omit for a public client
	// scopes: ["openid", "profile", "email"] // Optional, default shown
	// authMethod: "basic" // Optional, "basic", "post" or "none" (public client), default is "basic"
}

// Optional: For Resource Owner Password Credentials flow
user: {
	username: "your-username"
	password: "your-password"
}

// Optional: Key to update in .env (default: "TOKEN")
tokenKey: "MY_TOKEN"

// Optional: Key to update with ID Token in .env
idTokenKey: "MY_ID_TOKEN"
```

## Configuration Examples

### Keycloak

```cue
package config

oidc: {
	issuerUrl:    "https://keycloak.example.com/realms/myrealm"
	clientId:     "my-client"
	clientSecret: "my-secret"
}

user: {
	username: "myuser"
	password: "mypassword"
}
```

### Keycloak (public client)

For a Keycloak client with *Client authentication* turned off, omit `clientSecret`
(or set `authMethod: "none"`). The `client_id` is then sent in the request body
without secret. A public client cannot use the Client Credentials flow, so `user`
credentials are required and *Direct access grants* must be enabled on the client.

```cue
package config

oidc: {
	issuerUrl:  "https://keycloak.example.com/realms/myrealm"
	clientId:   "my-public-client"
	authMethod: "none"
}

user: {
	username: "myuser"
	password: "mypassword"
}
```

### Authentik

```cue
package config

oidc: {
	issuerUrl:    "https://authentik.example.com/application/o/my-app/"
	clientId:     "my-client-id"
	clientSecret: "my-client-secret"
	scopes:       ["openid", "profile", "email", "goauthentik.io/api"]
}
```

## Advanced Targets Configuration

By default, `authk` updates a single `.env` file. For more complex setups, you can define multiple targets to update different files or keys with different token types.

```cue
// Optional: Multiple targets configuration
targets: [
    {
        file: ".env"
        key:  "MY_ACCESS_TOKEN"
        type: "access_token" // Default type
    },
    {
        file: ".env"
        key:  "MY_ID_TOKEN"
        type: "id_token"
    },
    {
        file: "apps/frontend/.env"
        key:  "API_TOKEN"
    }
]
```

When `targets` is defined, the global `tokenKey` and `idTokenKey` are ignored.

Relative `file` paths are resolved against the directory of the configuration file, so running `authk` from a subdirectory updates the same files.

`.env` files are written atomically (temporary file + rename): readers never see a partially written file. An existing file keeps its permissions and a symlink is followed; a file created by `authk` gets `0600` permissions since it holds a token.

## Secrets Management

`authk` integrates with [vals](https://github.com/helmfile/vals) to support loading secrets securely from various sources. You can use special URI schemes in your configuration file to reference secrets instead of hardcoding them.

Supported schemes:
*   `ref+env://` - Environment variables
*   `ref+file://` - File contents
*   `ref+sops://` - Files encrypted with [SOPS](https://github.com/getsops/sops)
*   `ref+k8s://` - Kubernetes Secrets

### Examples

**Environment Variables:**

```cue
oidc: {
    // ...
    clientSecret: "ref+env://OIDC_CLIENT_SECRET"
}
```

**Kubernetes Secret:**

```cue
user: {
    // ...
    // format: ref+k8s://namespace/secret-name/json-key
    password: "ref+k8s://default/my-secret/password"
}
```

**File Content:**

```cue
oidc: {
    // ...
    clientSecret: "ref+file:///path/to/secret_file"
}
```

## File Discovery

The configuration file (`authk.cue`) is searched in the following order:

1.  **Explicit Path**: If provided via `--config`.
2.  **Current Directory**: Checks the current working directory.
3.  **Parent Directories**: Walks up the directory tree to the root.
4.  **Home Directory**: Checks the user's home directory (`$HOME`).

This allows you to run `authk` from any subdirectory within your project or rely on a global configuration in your home directory.

When the config has no `targets`, the `.env` file is found as follows:

- **Explicit path** (`--env front/.env`): used as is, relative to the current directory.
- **Project config** (not in the home directory root): searched from the current directory up to the config directory, never above. If none is found, it is created next to the config.
- **Global config** (`~/authk.cue`): searched from the current directory up to, but excluding, the home directory. If none is found, it is created in the current directory.

`~/.env` is never used implicitly: a project without `.env` must not write its token there, nor share it with every other project.

## Usage

### Agent (Long-running)

This is the main mode. The agent fetches a token, updates the `.env` file (or the configured targets), and keeps running to renew the token before it expires. It stops cleanly on `Ctrl+C` or `SIGTERM`.

```bash
./authk agent             # in the foreground
./authk agent --detach    # in the background (-d)
```

While the agent runs, `authk get` and `authk inspect` use its current token through a local socket instead of authenticating again. The agent is the only process that renews the token, which matters with refresh token rotation (Keycloak *Revoke Refresh Token*).

An agent serves one config file, and one `.env` file when the config has no `targets` (`--env` is ignored, with a warning, when the config defines `targets`). Several agents can run at the same time; a second agent for the same files is refused.

```bash
./authk agent list          # list running agents (alias: ls, --json available)
./authk agent status [ID]   # show an agent state (--json available)
./authk agent refresh [ID]  # renew the token now
./authk agent logs [ID] -f  # follow the logs of a detached agent
./authk agent stop [ID]     # stop an agent
./authk agent stop --all    # stop every agent
```

Without ID, these commands act on the agent serving the current directory. An ID prefix is enough, as with Docker.

```
$ authk agent list
ID                 PID    STARTED           TOKEN  MODE        CONFIG                 WRITES
281028a4-b3def358  31337  2026-11-06 09:12  4m12s  detached    ~/dev/app/authk.cue    ~/dev/app/front/.env
281028a4-05a23f95  31420  2026-11-06 09:13  4m30s  detached    ~/dev/app/authk.cue    ~/dev/app/back/.env
d4a4eba5           31502  2026-11-06 09:30  1m58s  foreground  ~/dev/other/authk.cue  ~/dev/other/out/.env
```

`--detach` returns once the agent has its first token, or prints its log if it fails to start. Logs of detached agents are written to `$XDG_STATE_HOME/authk/logs` (default `~/.local/state/authk/logs`) and kept 7 days.

Sockets and registrations live in `$XDG_RUNTIME_DIR/authk/` (or a private directory in the system temp dir); set `AUTHK_SOCK` to use a specific socket path.

> Running `authk` without a command still starts the agent in the foreground, but is deprecated.

**Flags:**
- `--config`: Path to config file (default: `authk.cue`)
- `--env`: Path to .env file (default: `.env`), when the config has no `targets`
- `--detach`, `-d`: Run in the background
- `--debug`: Enable debug logging

### Get Token (One-off)

Prints a valid token to stdout. Useful for piping to other commands.

```bash
./authk get
curl -H "Authorization: Bearer $(./authk get)" https://api.example.com
```

If an agent serves the config, its current token is printed (renewed first if it expires within `--min-ttl`). Otherwise a new token is requested from the provider. If the agent runs but fails, `get` returns its error instead of authenticating on its own.

When several agents serve the config (one per `.env` file), `get` uses the one writing the `.env` file found from the current directory, or given with `--env`; if none matches, it fails and lists them. Set `AUTHK_SOCK` to target a specific agent.

**Flags:**
- `--id-token`: Print ID Token instead of Access Token
- `--min-ttl`: Minimum remaining validity of a token served by the agent (default: `10s`)
- `--no-agent`: Always request a new token, even if an agent runs

### Inspect Token

Displays the decoded content (Header and Payload) of the current token, with its source and expiry.

If an agent runs, its current token is inspected. Otherwise, or with `--from-env` or `--env`, the token is read from the `.env` file, which shows what applications actually read. It automatically uses the file and key defined in your `targets` if available.

```bash
./authk inspect
```

**Flags:**
- `--id-token`: Inspect the ID token instead of the Access token (searches for a target of type `id_token`)
- `--from-env`: Read the token from the `.env` file even if an agent runs
- `--env`: Path to .env file. If multiple targets exist for different files, use this to specify which one to inspect (implies `--from-env`).
- `--json`: Output as valid JSON without colors (useful for parsing). Includes a `source` field (`agent` or `env`).

## License

MIT
