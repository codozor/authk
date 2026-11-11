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

- **OIDC Integration**: Client Credentials, Resource Owner Password Credentials, Device Authorization and Authorization Code with PKCE flows, for Keycloak, Authentik or any OIDC provider.
- **Profiles**: several identities (realms, clients, users) in a single config file, with or without files to write.
- **Automatic Refresh**: an agent renews tokens before they expire and serves them to `authk get`.
- **Persistent sessions**: after a browser login, the refresh token is kept in the OS keyring (or a private file), so restarting the agent does not ask you to log in again.
- **.env Management**: updates keys of `.env` files with the new tokens.
- **Command Runner**: `authk exec` runs a command with the tokens in its environment, never written to disk.
- **Configurable**: uses CUE for flexible and type-safe configuration, with secrets from env, files, SOPS or Kubernetes.

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

`authk` uses a CUE configuration file (default: `authk.cue`) holding one or more **profiles**. A profile says:

- **which client** asks for tokens: `issuer`, `clientId`, `clientSecret`;
- **how** it gets them: `flow`, with the fields of that flow;
- **where** to write them: `targets` (optional).

```cue
package config

version: 2

profiles: dev: {
	issuer:       "https://kc.example.com/realms/dev"
	clientId:     "my-service"
	clientSecret: "ref+env://KC_CLIENT_SECRET"
	flow:         "client_credentials"
	targets: [{key: "TOKEN"}] // TOKEN=... in the .env file of the project
}
```

### Profile fields

| Field | Required | Description |
|---|---|---|
| `issuer` | yes | Issuer URL of the realm / application (OIDC discovery is done from it). |
| `clientId` | yes | Client ID registered in the identity provider. |
| `clientSecret` | no | Client secret. Absent: **public client** (Keycloak *Client authentication: Off*). |
| `clientAuth` | no | How the secret is sent: `basic` (HTTP Basic header, default), `post` (request body), or `none` (public client: setting `clientSecret` too is an error). |
| `flow` | yes | How tokens are obtained, see below. |
| `username`, `password` | `password` flow | User credentials. |
| `redirectPort` | no, `authorization_code` flow | Port of the redirect URI `http://127.0.0.1:<port>/callback`. Absent: a free port at each login. |
| `tokenStore` | no, `device_code` and `authorization_code` flows | Where the refresh token is kept between runs: `auto` (default), `keyring`, `file` or `none`. See [Stored sessions](#stored-sessions). |
| `scopes` | no | Default: `["openid", "profile", "email"]`. |
| `targets` | no | Files to write the tokens to. Absent: nothing is written. |

### Flows

| `flow` | Extra fields | Use it for | Notes |
|---|---|---|---|
| `client_credentials` | — | A service, CI, or machine-to-machine access | Requires `clientSecret`. |
| `password` | `username`, `password` | A user, non-interactively | Keycloak: enable *Direct access grants* on the client. |
| `device_code` | — | A user, logging in through the browser | authk shows a URL and a code to enter, possibly on another device. See [Device code](#device-code). |
| `authorization_code` | `redirectPort` (optional) | A user, logging in through the browser | Authorization code with PKCE: the browser comes back to authk on `http://127.0.0.1:<port>/callback`. See [Authorization code (PKCE)](#authorization-code-pkce). |

Extra fields are only allowed with their flow: `username` is rejected with `client_credentials`, so a typo or a leftover field is reported when the file is loaded.

Why `clientSecret` and `flow` are separate: the client secret authenticates the *application* on every call to the token endpoint, refreshes included, whatever the flow; the flow says how the *identity* is obtained. They combine freely, except `client_credentials`, which needs a secret.

### Interactive flows

`device_code` and `authorization_code` need you to log in, in a browser. No password is stored in the config. What follows applies to both:

- The agent logs in once, in the foreground as with `--detach` (the detached agent goes to the background once you logged in), then renews the token with the refresh token.
- The refresh token is stored (see [Stored sessions](#stored-sessions)): restarting the agent, or `authk get` without agent, reuses the session instead of logging in again.
- When the session expires (Keycloak *SSO Session Max*, idle timeout, revoked token), the agent cannot log in by itself: `authk agent list` shows `LOGIN`, `authk get` fails, and `authk agent login` logs in again.
- Without refresh token, you must log in again each time the token expires. Add the `offline_access` scope to get one: required with Authentik, optional with Keycloak, where it gives an *offline token* that survives the end of the SSO session (each login then creates an offline session, listed in the account console).
- An offline refresh token outlives your browser session: logging out of the provider in the browser does not stop authk. `authk logout` revokes the stored session (see below); a running agent notices at its next renewal (`authk agent refresh` forces it), and the access token already issued stays valid until it expires.

#### Stored sessions

After a login, and after each renewal, authk stores the refresh token, so that the next run (agent restart, reboot, `authk get` without agent) refreshes it instead of asking you to log in. `tokenStore` says where:

| `tokenStore` | Where |
|---|---|
| `auto` (default) | The OS keyring when it is available, the file otherwise. |
| `keyring` | The OS keyring: Secret Service (GNOME Keyring, KWallet) on Linux, Keychain on macOS, Credential Manager on Windows. An error if it is not available. |
| `file` | A file readable only by you, in `$XDG_STATE_HOME/authk/tokens` (default `~/.local/state/authk/tokens`). |
| `none` | Nowhere: each run logs in. |

- A machine without desktop session (SSH, VS Code Remote, container) usually has no keyring: `auto` then uses the file. The file holds the token in clear, like the `.env` files authk writes; use `none` where that is not acceptable.
- The session is shared by the runs of a profile: same config file, profile, issuer, client and scopes. Changing the scopes asks for a new login.
- With refresh token rotation (Keycloak *Revoke Refresh Token*), each refresh token works once: authk serializes the refreshes of a profile with a lock and always uses the newest stored token, so an agent and `authk get --direct` can run at the same time.
- A refresh token rejected by the provider (expired, revoked) is deleted. Keycloak tells when the session expires (`refresh_expires_in`): `authk agent status` shows it on the `Session` line, and an expired stored token is not even tried.

#### Login and logout

```bash
authk login -p me     # log in and store the session, without agent
authk logout -p me    # delete the stored session and revoke it at the provider
```

- `authk login` logs in even if a session is stored (e.g. to change user). Running agents of the profile switch to the new session. Use it before scripts: `authk get` then reuses the session.
- `authk get` logs in when there is no stored session, showing the prompt on stderr. When stderr is not a terminal (cron, CI, output redirected), nobody would see it: `get` fails at once and tells you to run `authk login`.
- `authk logout` deletes the stored session, then revokes it at the provider (`revocation_endpoint`, RFC 7009), which ends the session there too. Without network, the session is deleted locally, and stays valid at the provider until it expires. Running agents keep their access token until it expires, then need a login: `logout` lists them, stop them with `authk agent stop`.

#### Device code

With `flow: "device_code"`, authk asks the provider for a code, then shows it:

```
Login required.
  Open:  https://sso.example.com/realms/dev/device?user_code=WDJB-MJHT
  or open https://sso.example.com/realms/dev/device and enter the code WDJB-MJHT
  The code expires at 10:32:00 (in 10m0s).
```

It then waits until you log in, in any browser, on any machine: it also works over SSH, in a container, or with a detached agent.

Provider setup:

- **Keycloak**: in the client, *Capability config*, enable *OAuth 2.0 Device Authorization Grant*. The client can be public (*Client authentication: Off*) or confidential.
- **Authentik**: device codes need a flow on the brand, which Authentik does not provide by default:
  1. *Flows and Stages > Flows > Create*: name and slug `default-device-code-flow`, designation *Stage Configuration*, authentication *Require authentication*. No stage is needed.
  2. *System > Brands*, edit the brand: set *Device code flow* to this flow.
  3. In the OAuth2 provider, keep the *offline_access* scope mapping among the selected scopes, and request it in `scopes`.
  4. With `clientAuth: "none"`, set the provider *Client type* to *Public*; a *Confidential* provider needs `clientSecret`.
  5. The code is valid for the provider *Access code validity* (1 minute by default): raise it, e.g. `minutes=5`.

#### Authorization code (PKCE)

With `flow: "authorization_code"`, authk listens on `http://127.0.0.1:<port>/callback`, opens the login page in your browser and waits for the provider to redirect the browser back to it, with PKCE (S256). This is the usual flow of a desktop application, and the most comfortable on a workstation: with an active SSO session, there is nothing to type.

```
Login required.
  Open:  https://sso.example.com/realms/dev/protocol/openid-connect/auth?client_id=…
  (opening it in your browser)
  If the browser cannot reach this machine, paste here the address it ended on
  (http://127.0.0.1:…/callback?…) and press Enter.
  The login expires at 10:32:00 (in 5m0s).
```

- **Port**: `redirectPort` fixes it (e.g. `8765`, redirect URI `http://127.0.0.1:8765/callback`). Without it, a free port is chosen at each login, which the provider must accept (see below).
- **Browser**: authk uses `$BROWSER` if set, else the desktop opener (`xdg-open` with a display, `open`, Windows). Set `AUTHK_NO_BROWSER=1` to only print the URL.
- **Remote machine** (SSH, VS Code Remote): the redirect must reach the machine running authk:
  - VS Code Remote: its terminals set `$BROWSER` to open the page on your computer, and forward the callback port automatically. If that port is already busy on your computer, VS Code forwards it to another one and the redirect fails: use the paste below.
  - SSH: `ssh -L 8765:127.0.0.1:8765 host`, with `redirectPort: 8765`.
  - Otherwise, the browser ends on an error page ("unable to connect"): copy its address and paste it in the terminal where authk waits (`authk get`, `authk agent`, `authk agent --detach` while it waits, or `authk agent login`). authk checks that it belongs to the pending login.
- **Device code or authorization code?** Prefer authorization code on a workstation, device code on machines where no browser can reach authk (servers, containers) or to log in from another device.

Provider setup:

- **Keycloak**: in the client, keep *Standard flow* enabled and add the redirect URI to *Valid redirect URIs*: `http://127.0.0.1:8765/callback` with `redirectPort: 8765`. Optionally, in *Advanced*, set *Proof Key for Code Exchange Code Challenge Method* to `S256` to require PKCE.
- **Authentik**: in the OAuth2 provider, add the redirect URI: `http://127.0.0.1:8765/callback` (*Strict*) with `redirectPort: 8765`, or `http://127\.0\.0\.1:\d+/callback` (*Regex*) to accept any port. Keep the *offline_access* scope mapping, as for device code. *Client type* *Public* with `clientAuth: "none"`, or *Confidential* with `clientSecret`.
- Write `127.0.0.1`, not `localhost`: providers compare redirect URIs as strings.

### Targets

Each target writes a token to a key of a file:

```cue
targets: [
	{key: "TOKEN"},                                   // the project .env file
	{key: "ID_TOKEN", type: "id_token"},              // type: "access_token" by default
	{file: "apps/frontend/.env.local", key: "VITE_API_TOKEN"},
]
```

- **With `file`**: the path is relative to the directory of the configuration file, so running `authk` from a subdirectory updates the same file. The directory must exist.
- **Without `file`**: the `.env` file of the project, found from the current directory (see [File Discovery](#file-discovery)) or given with `--env`.
- **No `targets` at all**: nothing is written. The profile is used through `authk get` only, and with an agent the token stays in memory: nothing on disk.

`.env` files are written atomically (temporary file + rename): readers never see a partially written file. An existing file keeps its permissions and a symlink is followed; a file created by `authk` gets `0600` permissions since it holds a token.

### Profiles

A file can hold several profiles: one per realm, environment, client or user.

```cue
version: 2
defaultProfile: "dev" // optional

profiles: dev:  { ... }
profiles: prod: { ... }
```

The profile is chosen with `--profile` (`-p`), else `$AUTHK_PROFILE`, else `defaultProfile`, else the only profile of the file. `authk config profiles` lists them and marks the one that would be used.

Secrets are resolved only for the selected profile: a `prod` secret stored in Kubernetes is not read when you use `dev`.

### Version 1 files

Files without `version` (the format of authk 1.x) keep working: they are converted in memory into a single profile named `default`, and `tokenKey` / `idTokenKey` become targets without `file`. To rewrite such a file in the version 2 format:

```bash
authk config migrate --dry-run  # print the result
authk config migrate            # rewrite authk.cue, keeping authk.cue.v1.bak
```

Comments are not kept; secret references are copied as they are, never resolved.

## Configuration Examples

### A project: service token in `.env`, personal token on demand

```cue
package config

version: 2
defaultProfile: "app"

// Token of the application, written to the project .env and to the frontend
profiles: app: {
	issuer:       "https://keycloak.example.com/realms/myrealm"
	clientId:     "my-app"
	clientSecret: "ref+env://APP_CLIENT_SECRET"
	flow:         "client_credentials"
	targets: [
		{key: "API_TOKEN"},
		{file: "frontend/.env.local", key: "VITE_API_TOKEN"},
	]
}

// My own token, never written to disk: authk get -p me
profiles: me: {
	issuer:   "https://keycloak.example.com/realms/myrealm"
	clientId: "my-cli" // public client
	flow:     "password"
	username: "alice"
	password: "ref+env://KC_PASSWORD"
}
```

```bash
authk agent -d                    # keeps API_TOKEN up to date
authk agent -d -p me              # keeps my token in memory
curl -H "Authorization: Bearer $(authk get -p me)" https://api.example.com/me
```

### Keycloak (confidential client, password flow)

```cue
profiles: dev: {
	issuer:       "https://keycloak.example.com/realms/myrealm"
	clientId:     "my-client"
	clientSecret: "ref+env://KC_CLIENT_SECRET"
	flow:         "password"
	username:     "myuser"
	password:     "ref+env://KC_PASSWORD"
	targets: [{key: "TOKEN"}, {key: "ID_TOKEN", type: "id_token"}]
}
```

### Keycloak (public client)

For a Keycloak client with *Client authentication* turned off, omit `clientSecret`: the `client_id` is then sent in the request body without secret. A public client cannot use `client_credentials`, and *Direct access grants* must be enabled for the `password` flow.

```cue
profiles: dev: {
	issuer:   "https://keycloak.example.com/realms/myrealm"
	clientId: "my-public-client"
	flow:     "password"
	username: "myuser"
	password: "ref+env://KC_PASSWORD"
}
```

### Keycloak (device code, public client)

```cue
profiles: me: {
	issuer:     "https://keycloak.example.com/realms/dev"
	clientId:   "authk-cli"
	clientAuth: "none"
	flow:       "device_code"
	scopes: ["openid", "profile", "email", "offline_access"]
}
```

### Authorization code (PKCE, fixed port)

```cue
profiles: me: {
	issuer:       "https://authentik.example.com/application/o/my-app/"
	clientId:     "my-client-id"
	clientAuth:   "none"
	flow:         "authorization_code"
	redirectPort: 8765
	scopes: ["openid", "profile", "email", "offline_access"]
}
```

### Authentik (device code)

```cue
profiles: me: {
	issuer:     "https://authentik.example.com/application/o/my-app/"
	clientId:   "my-client-id"
	clientAuth: "none"
	flow:       "device_code"
	scopes: ["openid", "profile", "email", "offline_access"]
}
```

### Authentik (machine-to-machine)

```cue
profiles: api: {
	issuer:       "https://authentik.example.com/application/o/my-app/"
	clientId:     "my-client-id"
	clientSecret: "ref+env://AUTHENTIK_CLIENT_SECRET"
	clientAuth:   "post"
	flow:         "client_credentials"
	scopes: ["openid", "profile", "email", "goauthentik.io/api"]
	targets: [{key: "AUTHENTIK_TOKEN"}]
}
```

## Secrets Management

`authk` integrates with [vals](https://github.com/helmfile/vals) to support loading secrets securely from various sources. You can use special URI schemes in your configuration file to reference secrets instead of hardcoding them.

Supported schemes:
*   `ref+env://VAR` - Environment variables
*   `ref+file:///path/to/file` - File contents
*   `ref+sops://path/to/file.yaml#/key` - Files encrypted with [SOPS](https://github.com/getsops/sops)
*   `ref+k8s://v1/Secret/<namespace>/<name>/<key>` - Kubernetes Secrets (`?kubeContext=...` to choose a context)

```cue
clientSecret: "ref+env://OIDC_CLIENT_SECRET"
clientSecret: "ref+file:///path/to/secret_file"
password:     "ref+k8s://v1/Secret/default/my-secret/password"
```

## File Discovery

The configuration file (`authk.cue`) is searched in the following order:

1.  **Explicit Path**: If provided via `--config`.
2.  **Current Directory**: Checks the current working directory.
3.  **Parent Directories**: Walks up the directory tree to the root.
4.  **Home Directory**: Checks the user's home directory (`$HOME`).

This allows you to run `authk` from any subdirectory within your project or rely on a global configuration in your home directory.

For targets without `file`, the `.env` file is found as follows:

- **Explicit path** (`--env front/.env`): used as is, relative to the current directory.
- **Project config** (not in the home directory root): searched from the current directory up to the config directory, never above. If none is found, it is created next to the config.
- **Global config** (`~/authk.cue`): searched from the current directory up to, but excluding, the home directory. If none is found, it is created in the current directory.

`~/.env` is never used implicitly: a project without `.env` must not write its token there, nor share it with every other project.

## Usage

### Agent (Long-running)

This is the main mode. The agent fetches a token, writes it to the profile targets, and keeps running to renew it before it expires. It stops cleanly on `Ctrl+C` or `SIGTERM`. For a profile without targets, the agent only keeps the token in memory for `authk get`.

```bash
./authk agent             # in the foreground
./authk agent --detach    # in the background (-d)
```

With an interactive flow (`device_code`, `authorization_code`), the agent shows the login and waits for you, in the foreground as with `--detach`: the detached agent goes to the background once you logged in.

While the agent runs, `authk get` and `authk inspect` use its current token through a local socket instead of authenticating again.

An agent serves one profile of a config file. Several agents can run at the same time: one per profile, for example. A second agent for the same profile is refused, except when all the targets of the profile are without `file`: then one agent per project `.env` is possible (`--env`, or a different directory). `--env` is ignored, with a warning, when no target writes the `.env` file.

```bash
./authk agent list                # list running agents (alias: ls; --wide, --json)
./authk agent status [NAME|ID]    # show an agent state (--json available)
./authk agent refresh [NAME|ID]   # renew the token now
./authk agent login [NAME|ID]     # log in again (interactive flows, once the session expired)
./authk agent logs [NAME|ID] -f   # follow the logs of a detached agent
./authk agent stop [NAME|ID]      # stop an agent
./authk agent stop --all          # stop every agent
```

Without argument, these commands act on the agent serving the current directory (and `--profile`).

```
$ authk agent list
NAME          PID    STARTED           TOKEN  MODE        WRITES
app/dev       31337  2026-11-09 09:12  4m12s  detached    ~/dev/app/.env, ~/dev/app/frontend/.env.local
app/me        31420  2026-11-09 09:13  4m30s  detached    -
legacy@front  31502  2026-11-09 09:30  1m58s  detached    ~/dev/legacy/front/.env
legacy@back   31540  2026-11-09 09:30  2m03s  detached    ~/dev/legacy/back/.env
other         31611  2026-11-09 09:41  3m02s  foreground  ~/dev/other/.env
```

#### Agent names

Each agent gets a readable name, built from what it serves:

| Part | Rule | Example |
|---|---|---|
| Project | Directory of the config file (`~` for `~/authk.cue`) | `app` |
| Profile | `/<profile>`, except for `default` (version 1 configs) | `app/dev`, `other` |
| `.env` | `@<dir>` when the agent writes a project `.env` that is not next to the config | `legacy@front` |

Use `--name` to choose another one: `authk agent -d -p me --name kc-alice`.

Names are not unique: two projects in directories with the same name (`~/work/api` and `~/perso/api`) both give `api`. authk never picks one for you:

```
$ authk agent stop api
ambiguous agent: 2 agents are named api:
  api  /home/me/work/api/authk.cue  (id 4624831a-22a6e520)
  api  /home/me/perso/api/authk.cue  (id e9b15395-22ee9515)
use the ID, or run the command from the project directory
```

Commands accept the name, the ID, or an ID prefix (as with Docker). `authk agent list --wide` shows the ID, config file and profile of each agent.

`--detach` returns once the agent has its first token, or prints its log if it fails to start. Logs of detached agents are written to `$XDG_STATE_HOME/authk/logs` (default `~/.local/state/authk/logs`) and kept 7 days.

Sockets and registrations live in `$XDG_RUNTIME_DIR/authk/` (or a private directory in the system temp dir); set `AUTHK_SOCK` to use a specific socket path.

> Running `authk` without a command still starts the agent in the foreground, but is deprecated.

**Flags:**
- `--config`: Path to config file (default: `authk.cue`)
- `--profile`, `-p`: Profile to use (default: `$AUTHK_PROFILE`, `defaultProfile`, or the only profile)
- `--env`: Path to the .env file written by targets without `file` (default: `.env`)
- `--detach`, `-d`: Run in the background
- `--name`: Name of the agent (default: `<project>/<profile>`)
- `--debug`: Enable debug logging

### Get Token (One-off)

Prints a valid token to stdout. Useful for piping to other commands.

```bash
./authk get
curl -H "Authorization: Bearer $(./authk get)" https://api.example.com
```

`get` works with any profile, with or without targets:

```bash
authk get              # default profile
authk get -p me        # another profile
authk get --id-token   # the ID Token instead of the Access Token
```

If an agent serves the profile, its current token is printed (renewed first if it expires within `--min-ttl`). Otherwise a new token is requested from the provider: for an interactive flow, from the stored session, or by logging in (see [Login and logout](#login-and-logout)). If the agent runs but fails, `get` returns its error instead of authenticating on its own.

When several agents serve the profile (one per `.env` file), `get` uses the one writing the `.env` file found from the current directory, or given with `--env`; if none matches, it fails and lists them. Set `AUTHK_SOCK` to target a specific agent socket.

**Flags:**
- `--id-token`: Print ID Token instead of Access Token
- `--min-ttl`: Minimum remaining validity of a token served by the agent (default: `10s`)
- `--direct`: Request a new token from the provider directly, bypassing any running agent

### Run a Command with the Token

Runs a command with valid tokens in its environment, without writing them to a file:

```bash
authk exec -- terraform apply
authk exec -p me -- ./script.sh
authk exec --var API_TOKEN --var ID=id_token -- env
```

The tokens come from the agent if one serves the profile, otherwise from the provider, as with `get`. The variables are:

- the keys of the profile targets: a target `{key: "TOKEN"}` gives `TOKEN=<access token>`, an `id_token` target the ID Token;
- for a profile without targets, `ACCESS_TOKEN`, and `ID_TOKEN` when the provider returns one;
- with `--var`, only those given: `NAME` for the access token, `NAME=id_token` for the ID Token.

The environment of a process cannot change once it started: a command running longer than the token lifetime must get new tokens itself (`authk get`), or use an agent writing a `.env` file.

On Unix, authk replaces itself with the command: signals and the exit code are the command's own. On Windows, authk waits for the command and returns its exit code. Flags after the command name belong to the command (`authk exec ls -l`); `--` is only needed when the command name starts with `-`.

**Flags:**
- `--var`: Variable to set, `NAME` or `NAME=id_token`; repeatable (default: the keys of the profile targets)
- `--min-ttl`: Minimum remaining validity of the tokens (default: `1m`)
- `--direct`: Request new tokens from the provider directly, bypassing any running agent

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
