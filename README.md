# Okta Workspace MCP

Okta MCP server research PoC — combines OAuth/OIDC identity and org-management
tools with a Cookie-Bite-style session-cookie capture tool, built for
authorized SSO/session security research and detection engineering.

Use only with tenants, apps, users, and tokens you are authorized to test.

## Authentication

This server has **two distinct, independent authentication mechanisms**. Which
one runs depends on which tool is called.

### 1. OAuth 2.0 / OIDC Authorization Code + PKCE (identity & org tools)

Backs `whoami`, `userinfo`, `token-details`, `my-groups`, `my-apps`,
`list-users`, `get-user`, `search-users`, `list-groups`, `list-apps`.

1. The MCP opens the Okta hosted sign-in page in the system browser.
2. The user authenticates normally against the org's configured factors.
3. Okta redirects to `http://localhost:8749/callback` with an authorization code.
4. The MCP exchanges the code (with the PKCE `code_verifier`) for an
   `access_token` / `id_token` / `refresh_token`.
5. Tokens are cached under the user's profile and silently renewed via the
   refresh-token grant when they expire.

This is a normal, standards-based OIDC client flow — no credentials or
cookies are captured, only a token scoped to what the app registration and
user's role allow.

### 2. Browser session-cookie capture (session tools)

Backs `session-check`, `session-validate`, `session-export`, `session-history`.

1. `session-check` launches Edge/Chrome with `--remote-debugging-port` and
   drives it over the Chrome DevTools Protocol (CDP).
2. It waits for the user to complete Okta sign-in in that browser, then polls
   `Storage.getCookies` until an authenticated Okta session cookie
   (`sid` / `idx` / `JSESSIONID` / `DT`) appears.
3. The captured cookie jar is validated against `/api/v1/users/me` and stored
   locally.
4. `session-export` can re-emit that jar as raw JSON, a Netscape cookie file,
   or a `Cookie:` header string — i.e. material that can be loaded into a
   browser or HTTP client to replay the session.

This is deliberately a **session-hijack-style capture**, not a health check —
it demonstrates the same primitive as the
[Cookie-Bite](https://www.varonis.com/blog/cookie-bite-entra-id) technique,
applied to Okta SSO sessions. Treat any exported jar as live credential
material — do not share or commit it.

## Product Flow

Intended user experience for the OAuth/OIDC tools:

```text
VS Code starts MCP
-> MCP reads C:\Users\<user>\.okta-workspace-mcp\config.json
-> MCP connects over stdio
-> browser opens Okta SSO
-> user authenticates
-> Okta redirects to localhost:8749/callback
-> MCP exchanges code with PKCE
-> tokens are cached under the user's profile
-> Okta tools work in VS Code
```

## Install (from this repository)

Clone and build from source — this is not published to a package registry:

```bash
git clone https://github.com/oreneHack/okta_mcp.git
cd okta_mcp
npm install
npm run build
npm link
```

After `npm link`, the command is available on your PATH as:

```bash
okta-workspace-mcp
```

(On Windows, run these from Git Bash/WSL or PowerShell equivalently — `npm
link` works the same way.)

## Initialize

Run:

```bash
okta-workspace-mcp init
```

It asks for:

- Okta org URL, for example `https://your-org.okta.com`
- Okta OIDC client ID
- Whether to enable admin/org-management scopes
- Whether browser auth should open when the MCP starts
- Whether to enable the local proof/evidence collector

Config is saved here:

```text
C:\Users\<user>\.okta-workspace-mcp\config.json
```

Token cache is saved here:

```text
C:\Users\<user>\.okta-workspace-mcp\tokens.json
```

Do not share or commit `tokens.json`.

If proof mode is enabled, `session-check` posts a cookie proof record
to the local collector:

```text
http://127.0.0.1:8765/v1/cookie-proofs
```

By default, raw cookie jars are not persisted locally in proof mode. To keep
local cookie artifacts too, initialize with `--persist-cookie-jars`.
The local collector record includes `display_value` values that mirror the
extracted cookie JSON exactly, so treat `collector-output\cookie-proof-*.json`
as live credential material.

## Okta App Setup

Create an OIDC app in the authorized Okta tenant:

1. Application type: Single-Page Application
2. Grant type: Authorization Code
3. Sign-in redirect URI: `http://localhost:8749/callback`
4. Scopes for first test: `openid profile email offline_access`
5. Assign the authorized test user
6. Copy the client ID into `okta-workspace-mcp init`

For org-management API tools, choose org-management scopes during `init`.
Those scopes still require matching Okta admin roles.

## VS Code MCP Config

After `npm link`, add this to your VS Code MCP configuration:

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

Okta settings live in the user-level config created by `init`, not in this
file.

If you're running from the cloned repo without `npm link`, the checked-in
[.vscode/mcp.json](.vscode/mcp.json) in this repository uses a
workspace-relative path (`${workspaceFolder}/build/cli.js`) so it works for
any clone location, not just the original author's machine.

## Simulate In VS Code

1. Start or reload VS Code after adding the MCP config.
2. VS Code launches `okta-workspace-mcp serve`.
3. The browser opens to Okta if `authOnStart` is enabled.
4. Authenticate with the authorized test user.
5. Ask the assistant to use an Okta tool, for example:

```text
Use the Okta MCP and tell me who I am.
```

Useful tools:

- `whoami`
- `userinfo`
- `token-details`
- `my-groups`
- `my-apps`
- `list-users`
- `get-user`
- `search-users`
- `list-groups`
- `list-apps`
- `session-check`
- `session-validate`
- `session-export`
- `session-history`

Org-management tools require org auth server, `okta.*` scopes, and admin roles.

## Lab Evidence Collector

If you enabled proof evidence during `init`, start the collector before starting
VS Code:

```bash
okta-workspace-mcp collector
```

For local repo development:

```bash
npm run collector
```

Proof files are written to:

```text
collector-output\lab-event-*.json
collector-output\cookie-proof-*.json
```

Proof mode exports token hashes, lengths, and JWT claims. It does not export
usable token values.

Cookie proof export includes cookie metadata, per-cookie hashes, and a
`display_value` field that mirrors the extracted cookie JSON exactly. Treat
cookie proof records as sensitive and do not share or commit them.

## Config Commands

```bash
okta-workspace-mcp init
okta-workspace-mcp serve
okta-workspace-mcp config
okta-workspace-mcp config-path
okta-workspace-mcp reset
```

Optional proof-focused init flags:

```bash
okta-workspace-mcp init --proof
okta-workspace-mcp init --proof --cookie-proof-url "http://127.0.0.1:8765/v1/cookie-proofs"
okta-workspace-mcp init --proof --persist-cookie-jars
```

## Detection Notes

In Okta System Log, compare the simulation time against:

- `app.oauth2.authorize.code`
- `user.authentication.sso`
- `app.oauth2.as.token.grant.access_token`
- `app.oauth2.as.token.grant.refresh_token`
- `app.oauth2.as.token.grant.id_token`
- `user.consent.grant`, if consent is enabled

Useful detection pivots:

- first-seen or unsanctioned OAuth `client_id`
- localhost redirect URI
- `offline_access`
- `okta.*` scopes
- MCP/client user agent patterns
- token grants from a client not in the approved app inventory

For the session-cookie capture path specifically, also watch for:

- session cookie use from a new device/user-agent shortly after a
  `user.authentication.sso` event on a different device
- `user.session.access_admin_app` or admin-console access immediately
  following a session cookie replay
- IP/geovelocity anomalies between the original sign-in and subsequent
  session use
