# Okta Workspace MCP

A community Model Context Protocol (MCP) server for inspecting Okta identity
context, assigned resources, groups, and authorized directory data from an AI
assistant.

The normal product path uses OAuth 2.0 Authorization Code with PKCE and starts
with read-only OIDC scopes. An optional, off-by-default security lab demonstrates
how a locally installed MCP could capture and replay browser session cookies in
an authorized test environment.

This project is not affiliated with or endorsed by Okta. Use it only with
tenants, applications, users, tokens, and sessions you are authorized to test.

## What it does

### Core identity tools

These tools use ordinary OIDC authentication:

| Tool | Purpose | Requirement |
| --- | --- | --- |
| `whoami` | Summarize the authenticated identity and token scopes | Default OIDC scopes |
| `userinfo` | Read the profile returned by Okta `/userinfo` | `openid profile email` |
| `token-details` | Inspect token metadata and claims without returning the bearer token | Authenticated session |
| `my-groups` | Show groups included in the access-token claims | A configured `groups` claim |

### Optional organization-read tools

These tools call Okta management APIs. They require the matching `okta.*` OAuth
scopes and an Okta role or resource set that authorizes the signed-in user:

| Tool | Required scope |
| --- | --- |
| `my-apps` | `okta.users.read` |
| `list-users`, `get-user`, `search-users` | `okta.users.read` |
| `list-groups` | `okta.groups.read` |
| `list-apps` | `okta.apps.read` |

Organization-read tools are registered only when their corresponding scopes are
present in the MCP configuration.

The optional session-research tools are not registered in a normal
installation. See [Authorized security lab](#authorized-security-lab).

## Security model

- Passwords and MFA values are entered only on the hosted Okta sign-in page.
- The OAuth path receives scoped bearer tokens through a localhost callback; it
  does not read browser cookies.
- Access and optional refresh tokens are cached under the current user's
  profile and tied to the configured tenant, client ID, authorization server,
  and scopes.
- Session-cookie tooling is disabled by default and must be explicitly enabled.
- Cookie proof records contain hashes and lengths by default, not cookie values.
- Configuration and credential artifacts are excluded from Git.

MCP servers run as local processes with the permissions of the user who starts
them. Review the source and package provenance before adding any third-party MCP
server to an AI client.

## Requirements

- Node.js 20 or newer
- An Okta OIDC application in a tenant you control
- An MCP-capable client such as VS Code
- Windows with Microsoft Edge or Google Chrome for the optional session lab

## Five-minute setup

### 1. Create the Okta application

Create an OIDC application with:

1. Application type: **Single-Page Application**
2. Grant type: **Authorization Code**
3. Sign-in redirect URI: `http://localhost:8749/callback`
4. Initial scopes: `openid profile email offline_access`
5. Assignment to the users or groups allowed to use the MCP

Copy the application client ID. No client secret is used; PKCE protects the
authorization-code exchange.

### 2. Install from source

This project is not currently published to npm. Clone and pin the revision you
intend to review and run:

```bash
git clone https://github.com/oreneHack/okta_mcp.git
cd okta_mcp
npm ci
npm run build
npm link
```

### 3. Initialize

```bash
okta-workspace-mcp init
```

The setup asks for the Okta organization URL and OIDC client ID. Keep
organization-management scopes disabled for the first test.

Non-interactive setup is also available:

```bash
okta-workspace-mcp init \
  --org-url "https://your-org.okta.com" \
  --client-id "your-client-id"
```

Configuration is stored at:

```text
~/.okta-workspace-mcp/config.json
```

OAuth tokens are stored separately at:

```text
~/.okta-workspace-mcp/tokens.json
```

Do not share or commit the token cache.

### 4. Add the MCP to the client

After `npm link`, use:

```json
{
  "servers": {
    "okta-workspace": {
      "command": "okta-workspace-mcp",
      "args": ["serve"]
    }
  }
}
```

For development from this repository, the checked-in `.vscode/mcp.json` runs
`build/cli.js` through a workspace-relative path.

### 5. Authenticate and use it

Start or reload the MCP client. When `authOnStart` is enabled, the MCP opens the
hosted Okta sign-in page. After authentication, Okta redirects to the localhost
callback and the tools become available.

Example requests:

```text
Use the Okta MCP to tell me who I am.
```

```text
Use the Okta MCP to summarize my profile and group claims.
```

## Organization-read setup

Run initialization with the read-only management-scope preset:

```bash
okta-workspace-mcp init \
  --org-url "https://your-org.okta.com" \
  --client-id "your-client-id" \
  --admin-scopes
```

This selects the Okta organization authorization server and requests:

```text
openid profile email offline_access
okta.users.read okta.groups.read okta.apps.read
```

Scopes do not replace Okta authorization. The signed-in user must still have a
matching role or resource set. Prefer the smallest roles and scopes needed for
the intended task.

## Authentication flow

```text
MCP client starts the server
-> server reads the local configuration
-> browser opens the hosted Okta sign-in page
-> user authenticates directly with Okta
-> Okta redirects to http://localhost:8749/callback
-> MCP exchanges the code with PKCE
-> scoped tokens are cached locally
-> Okta tools run as the authenticated user
```

## Authorized security lab

The repository includes an optional research mode for demonstrating the risk of
installing an untrusted local MCP. It launches an isolated Chromium browser,
waits for an authorized Okta sign-in, reads the resulting session cookies
through the Chrome DevTools Protocol, and validates the session against
`/api/v1/users/me`.

This mode handles live session credentials. Use only disposable test accounts,
keep the collector bound to loopback, and revoke the session after testing.

Enable the lab explicitly:

```bash
okta-workspace-mcp init \
  --org-url "https://your-org.okta.com" \
  --client-id "your-client-id" \
  --security-lab \
  --proof
```

Start the local evidence collector:

```bash
okta-workspace-mcp collector
```

The lab-only tools then become available:

- `session-check`
- `session-validate`
- `session-export`
- `session-history`

The collector listens on loopback:

```text
http://127.0.0.1:8765/
http://127.0.0.1:8765/v1/cookie-proofs
http://127.0.0.1:8765/v1/lab-events
```

By default, cookie proof records contain names, metadata, lengths, and SHA-256
hashes. `display_value` is `null`, and raw cookie jars are not persisted.

For a controlled replay experiment, both behaviors require explicit flags:

```bash
okta-workspace-mcp init \
  --org-url "https://your-org.okta.com" \
  --client-id "your-client-id" \
  --security-lab \
  --proof \
  --persist-cookie-jars \
  --include-cookie-values
```

That configuration creates and transmits replayable credential material. Never
use it with production identities or include its values in screenshots,
recordings, issues, or commits.

For a local end-to-end lab test:

```bash
npm run e2e:session-check -- 300
```

Complete the Okta sign-in in the isolated browser opened by the test.

To convert the latest loopback proof into Cookie-Editor's native JSON-array
format for the controlled replay scene:

```bash
npm run lab:cookie-editor-export -- --org-host "your-org.okta.com"
```

The adapter accepts loopback collector URLs only, verifies that every cookie
belongs to the expected test tenant, writes a new timestamped file under
`collector-output`, and never prints values to the terminal. It requires a proof
created with `--include-cookie-values`. Open the exact Okta tenant in the clean
lab browser before using Cookie-Editor's import function.

### Important distinction

Normal OIDC startup authentication and `session-check` are separate flows. The
OIDC flow uses the system browser and receives OAuth tokens. The lab tool opens a
fresh CDP-controlled browser and observes the cookies created in that browser.

## Commands

```text
okta-workspace-mcp init
okta-workspace-mcp serve
okta-workspace-mcp collector
okta-workspace-mcp config
okta-workspace-mcp config-path
okta-workspace-mcp reset
```

Developer commands:

```text
npm run build
npm run serve
npm run launch
npm run collector
npm run e2e:session-check -- 300
```

## Cleanup

1. Stop the MCP and local collector.
2. Run `okta-workspace-mcp reset` to remove configuration and cached OAuth
   tokens.
3. Delete any lab cookie jars under `~/.okta-workspace-mcp/cookies`.
4. Delete local collector records under `collector-output`.
5. Revoke the test user's Okta sessions and refresh tokens.

The `reset` command deliberately does not delete lab evidence automatically.

## Detection research

Useful Okta System Log pivots include:

- first-seen or unsanctioned OAuth client IDs
- localhost redirect URIs
- `offline_access` and unusual `okta.*` scopes
- token grants from unapproved AI tooling
- session use from a new IP, ASN, device, or browser shortly after sign-in
- administrative activity following session replay

See [RESEARCH_DEMONSTRATION.md](RESEARCH_DEMONSTRATION.md) for the lab threat
model and publication guidance.

## Status and limitations

- Community research project; not an official Okta integration
- Source installation only; no npm release is currently published
- Session-lab browser discovery currently targets standard Windows Edge and
  Chrome installation paths
- Organization APIs depend on tenant configuration, granted scopes, and roles
- Pagination is intentionally limited in the current PoC

## License

MIT. See [LICENSE](LICENSE).
