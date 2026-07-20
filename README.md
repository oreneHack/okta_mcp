# Okta Workspace MCP

Okta Workspace MCP is one local stdio MCP server with a guided authentication
choice:

- **Browser Session** opens an isolated browser and publishes valid JSON cookie
  objects with every value replaced by `[REDACTED]`.
- **OIDC / OAuth** uses Authorization Code with PKCE for identity and optional
  read-only Okta organization tools.

The server is a community security-research project and is not affiliated with
or endorsed by Okta. Use only organizations and identities you are authorized
to test.

## Canonical startup

There is one MCP entrypoint:

```text
node scripts/okta-mcp.mjs
```

On Windows, the equivalent wrapper is:

```text
scripts\start-okta-mcp.cmd
```

An MCP client launches this command over stdio. On first use, when the user
asks to start or configure Okta, the client calls `okta-start`. The MCP then
uses form elicitation to ask:

1. **Browser Session** or **OIDC / OAuth**.
2. The exact authorized Okta organization URL.
3. The same tenant URL again (or its exact hostname). Selecting **Continue**
   explicitly confirms authorization.
4. OIDC client settings only when OIDC was selected.

Later `okta-start` calls reuse the saved mode and tenant without reopening the
form. Use `reconfigure=true` only to deliberately change the setup.

Do not launch MCP Inspector for normal startup. Inspector is a development
debugger and is not this MCP's configuration or authentication experience.

## Install from source

Requirements:

- Node.js 20 or newer for OIDC mode
- Node.js 22 or newer for Browser Session mode
- Edge or Chrome for Browser Session mode
- An MCP client supporting local stdio servers

```powershell
npm ci
npm run build
```

## Connect an MCP client

### Codex

Register the source checkout once with its absolute entrypoint:

```powershell
npm run setup:codex
```

The setup script writes the `okta-workspace` entry through `codex mcp add` and
checks that Codex retained the exact absolute path. A checked-in relative
`cwd` is intentionally not used: desktop Codex processes may resolve an MCP
working directory from the application directory instead of the repository.

Verify the registration at any time with:

```powershell
npm run check:codex
```

Restart Codex once after registration. Then ask:

```text
Start Okta MCP
```

Codex reads the server instructions and calls `okta-start`; it should not open
Inspector.

### Visual Studio Code

The checked-in `.vscode/mcp.json` starts the same canonical entrypoint. Reload
VS Code, start `okta-workspace` from **MCP: List Servers**, and ask the client to
start Okta MCP.

### Other MCP clients

Use a stdio configuration equivalent to:

```json
{
  "type": "stdio",
  "command": "node",
  "args": ["C:\\absolute\\path\\to\\scripts\\okta-mcp.mjs"]
}
```

Running the command directly in an ordinary terminal only leaves it waiting for
MCP JSON-RPC input. Configuration forms are presented by the attached MCP
client after it calls `okta-start`.

## Browser Session mode

Browser mode asks only for the Okta tenant; it does not require an OIDC client
ID. After confirmation, it:

1. Starts the loopback-only collector on `127.0.0.1:8765` if needed.
2. Opens Edge or Chrome with a temporary isolated profile.
3. Lets the user authenticate directly on the configured Okta origin.
4. Verifies the session with same-origin `/api/v1/users/me`.
5. Exports browser cookie objects as valid JSON with every `value` exactly
   `[REDACTED]`.
6. Keeps the visible isolated browser alive so the user and MCP can work in the
   same authenticated session.
7. Publishes a new redacted proof every five minutes, after authentication or
   reauthentication, and when authenticated session material rotates.
8. Closes the browser and deletes its temporary profile on explicit close, MCP
   shutdown, manual browser close, or 30 minutes of inactivity. The collector
   retains only the newest proof by default.

Endpoints:

```text
http://127.0.0.1:8765/
http://127.0.0.1:8765/v1/cookie-proofs
```

Cookie metadata can include name, domain, path, expiry, size, HttpOnly, Secure,
SameSite, session, priority, source scheme, and source port. The collector
rejects the entire POST if any cookie `value` is not `[REDACTED]`.

The live worker communicates with the MCP through private child-process IPC;
it does not expose a browser-control HTTP port. Browser tools are intentionally
read-only: they provide sanitized page snapshots, same-tenant navigation, and
credentialed `GET` requests limited to `/api/v1/`. Cross-origin navigation,
arbitrary JavaScript, form filling, clicks, and state-changing requests are not
available in this first version.

## OIDC / OAuth mode

OIDC mode additionally asks for:

- Public Okta Native OIDC client ID
- Authorization server (`org` by default, or a custom server ID)
- OAuth scopes
- Loopback callback host and port

The default identity scopes are:

```text
openid profile email offline_access
```

The default callback is:

```text
http://localhost:8749/callback
```

Okta treats `localhost` and `127.0.0.1` as different redirect URIs. Register the
exact URI selected in `okta-start`.

The OAuth proof uses the same in-memory bearer token for two read-only UserInfo
requests and publishes only a SHA-256 fingerprint and response metadata:

```text
http://127.0.0.1:8765/v1/oauth-token-proofs
```

Base64 is not used because it is reversible. Raw access, refresh, and ID token
values are never returned by MCP tools or sent to the collector.

### Create the Native OIDC application

This setup is required only for OIDC mode:

1. In Okta Admin, create an **OIDC - OpenID Connect** integration.
2. Choose **Native Application**.
3. Enable **Authorization Code** and **Refresh Token**.
4. Register the exact loopback redirect URI.
5. Keep client authentication set to **None**.
6. Assign only authorized users or groups.
7. Copy the public client ID into the `okta-start` form.

For organization-read tools, an administrator must also grant the requested
`okta.*` scopes to the application. The signed-in user must separately have an
appropriate Okta role or custom resource assignment.

## MCP tools

### Setup and evidence

| Tool | Purpose |
| --- | --- |
| `okta-start` | Choose Browser or OIDC, collect relevant configuration, save it, and begin authentication |
| `okta-status` | Show selected mode, tenant, connection state, collector state, and latest redacted proofs |
| `okta-browser-session-proof` | Open or reuse the live isolated Browser Session |
| `okta-browser-status` | Show live-session, identity, page, timeout, and proof-refresh state |
| `okta-browser-snapshot` | Return sanitized visible page structure without input values or credentials |
| `okta-browser-navigate` | Navigate to a URL or path on the configured Okta origin only |
| `okta-browser-read` | Run a same-origin, read-only `GET` under `/api/v1/` using the browser session |
| `okta-browser-refresh-proof` | Publish a redacted proof immediately |
| `okta-browser-close` | Close the browser and delete its temporary profile |
| `okta-oauth-login` | Repeat PKCE authentication when OIDC mode is selected |
| `okta-oauth-reuse-proof` | Produce the redacted two-use OAuth fingerprint proof |

### OIDC identity and read tools

| Tool | Requirement |
| --- | --- |
| `whoami`, `userinfo`, `token-details` | Connected OIDC authorization |
| `my-groups` | Optional `groups` ID-token claim |
| `my-apps`, `list-users`, `get-user`, `search-users` | `okta.users.read` and suitable Okta authorization |
| `list-groups` | `okta.groups.read` and suitable Okta authorization |
| `list-apps` | `okta.apps.read` and suitable Okta authorization |

## Saved configuration

The current OS user's configuration directory is
`~/.okta-workspace-mcp` (`%USERPROFILE%\.okta-workspace-mcp` on Windows):

- `startup.json` stores the selected authentication mode and tenant.
- `config.json` stores OIDC client configuration only when OIDC is selected.
- `tokens.json` stores live OAuth credentials only after OIDC authentication.

The live Browser Session is deliberately not saved here. Its authenticated
temporary profile exists only while its browser worker is running.

Normal `okta-start` calls reuse these settings. To change modes or settings,
call `okta-start` with `reconfigure=true`; the MCP presents the choice again
and overwrites only the relevant configuration.

The CLI remains available for OIDC maintenance and automation:

```powershell
okta-workspace-mcp configure
okta-workspace-mcp login
okta-workspace-mcp status
okta-workspace-mcp logout
```

## Verification

```powershell
npm run smoke
node scripts/collector-startup-test.mjs
node scripts/lab-mcp-smoke.mjs
```

The smoke tests verify MCP-native mode elicitation, browser-only configuration
without a client ID, OIDC configuration, PKCE behavior, token-value exclusion,
cookie-value rejection, retention, and package contents.

See [SECURITY.md](SECURITY.md) and
[RESEARCH_DEMONSTRATION.md](RESEARCH_DEMONSTRATION.md) for operational and
publication guidance.

## License

MIT. See [LICENSE](LICENSE).
