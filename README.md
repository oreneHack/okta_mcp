# Okta MCP Security Lab

Authorized MCP proof-of-concept for Okta browser SSO, MCP-based Okta tools,
and detection research around OAuth clients used by AI assistants.

Use only with tenants, apps, users, and tokens you are authorized to test.

## Product Flow

This is the intended user experience:

1. The assistant recommends the MCP.
2. The user approves install.
3. The assistant runs `okta-mcp-security-lab init`.
4. The user provides only the Okta org URL and OIDC client ID.
5. The assistant adds the MCP server to VS Code `mcp.json`.
6. VS Code starts the MCP server.
7. The MCP opens the Okta browser sign-in.
8. The user authenticates normally.
9. The MCP receives the localhost callback and tools become available.

```text
VS Code starts MCP
-> MCP reads C:\Users\<user>\.okta-mcp-security-lab\config.json
-> MCP connects over stdio
-> browser opens Okta SSO
-> user authenticates
-> Okta redirects to localhost:8749/callback
-> MCP exchanges code with PKCE
-> tokens are cached under the user's profile
-> Okta tools work in VS Code
```

## Install

For local development from this repo:

```powershell
cd "C:\Users\Oren\Documents\Okta related\okta-mcp-steal"
npm install
npm run build
npm link
```

After `npm link`, the command is available as:

```powershell
okta-mcp-security-lab
```

## Initialize

Run:

```powershell
okta-mcp-security-lab init
```

It asks for:

- Okta org URL, for example `https://integrator-8282270.okta.com`
- Okta OIDC client ID
- Whether to enable admin/org-management scopes
- Whether browser auth should open when the MCP starts
- Whether to enable local proof evidence for the security lab

Config is saved here:

```text
C:\Users\<user>\.okta-mcp-security-lab\config.json
```

Token cache is saved here:

```text
C:\Users\<user>\.okta-mcp-security-lab\tokens.json
```

Do not share or commit `tokens.json`.

If proof mode is enabled, `cookie-login` posts a cookie proof record
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
6. Copy the client ID into `okta-mcp-security-lab init`

For org-management API tools, choose org-management scopes during `init`.
Those scopes still require matching Okta admin roles.

## VS Code MCP Config

Add this to your VS Code MCP configuration:

```json
{
  "servers": {
    "okta-security-lab": {
      "command": "okta-mcp-security-lab",
      "args": ["serve"]
    }
  }
}
```

That is all VS Code needs. Okta settings live in the user-level config created
by `init`.

For local testing without `npm link`, use:

```json
{
  "servers": {
    "okta-security-lab": {
      "command": "node",
      "args": [
        "C:/Users/Oren/Documents/Okta related/okta-mcp-steal/build/cli.js",
        "serve"
      ]
    }
  }
}
```

## Simulate In VS Code

1. Start or reload VS Code after adding the MCP config.
2. VS Code launches `okta-mcp-security-lab serve`.
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

Org-management tools require org auth server, `okta.*` scopes, and admin roles.

## Lab Evidence Collector

If you enabled proof evidence during `init`, start the collector before starting
VS Code:

```powershell
okta-mcp-security-lab collector
```

For local repo development:

```powershell
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

```powershell
okta-mcp-security-lab init
okta-mcp-security-lab serve
okta-mcp-security-lab config
okta-mcp-security-lab config-path
okta-mcp-security-lab reset
```

Optional proof-focused init flags:

```powershell
okta-mcp-security-lab init --proof
okta-mcp-security-lab init --proof --cookie-proof-url "http://127.0.0.1:8765/v1/cookie-proofs"
okta-mcp-security-lab init --proof --persist-cookie-jars
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
