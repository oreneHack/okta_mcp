# Okta MCP Token Steal

A security research PoC demonstrating how a malicious MCP (Model Context Protocol) server can silently exfiltrate Okta session cookies and OAuth tokens from an authenticated admin session.

This work extends the [Cookie-Bite](https://www.varonis.com/blog/cookie-bite) research, showing that MCP clients introduce a new attack surface for identity theft: a single user sign-in grants the MCP server access to both session cookies and bearer tokens for every assigned OIDC application, bypassing `detect_client_roaming` protections on the token side.

## Attack Chain

```
User installs MCP server
        |
        v
okta-start --> opens isolated browser
        |
        v
User authenticates to Okta (normal sign-in)
        |
        v
Session cookies captured --> POST /v1/cookie-proofs
        |
        v
Silent OAuth harvest (prompt=none + PKCE)
  - Enumerates all assigned OIDC apps via /api/v1/apps
  - Filters to public clients (SPA, token_endpoint_auth_method=none)
  - For each app: silent authorize --> CDP Fetch intercept --> code exchange
        |
        v
Access tokens + ID tokens --> POST /v1/tokens
        |
        v
Attacker retrieves tokens from collector
  - No IP binding on tokens
  - No MFA re-prompt (prompt=none)
  - Works from any network location
```

## Key Findings

1. **`detect_client_roaming` protects sessions but NOT tokens** - Okta's client roaming detection binds admin sessions (cookies) to the original IP, but OAuth bearer tokens obtained from that session have no IP binding and can be used from anywhere.

2. **`prompt=none` bypasses MFA** - Once the user has an active Okta session, silent OAuth flows (`prompt=none`) never trigger MFA step-up challenges. The session is sufficient.

3. **Public OIDC clients (SPAs) are vulnerable** - Applications using `token_endpoint_auth_method: "none"` don't require a client secret for the PKCE code exchange. The MCP can harvest tokens from any assigned public client.

4. **Confidential clients are protected** - Web applications using `client_secret_basic` or `client_secret_post` require a server-side secret for code exchange, which the MCP cannot extract from the Okta admin API.

5. **Single sign-in, dual exfiltration** - One user authentication yields both session cookies (for session hijacking) and OAuth tokens (for API access to downstream apps).

## Architecture

```
+------------------+       stdio/JSON-RPC        +------------------+
|   MCP Client     | <-------------------------> |   MCP Server     |
|  (Claude, etc.)  |                              |  (lab-mcp.mjs)   |
+------------------+                              +--------+---------+
                                                           |
                                                    IPC    |
                                                           v
                                            +-----------------------------+
                                            |  Browser Session Worker     |
                                            |  (browser-session-worker)   |
                                            |                             |
                                            |  - Opens isolated Chrome    |
                                            |  - CDP control via WebSocket|
                                            |  - Cookie capture           |
                                            |  - Silent OAuth harvest     |
                                            |  - Window minimize/restore  |
                                            +-------------+---------------+
                                                          |
                                                   HTTP   |
                                                          v
                                            +-----------------------------+
                                            |  Collector (127.0.0.1:8765) |
                                            |                             |
                                            |  POST /v1/cookie-proofs     |
                                            |  POST /v1/tokens            |
                                            |  GET  /v1/tokens/latest     |
                                            |  GET  /v1/cookie-proofs     |
                                            +-----------------------------+
```

### Components

| Component | File | Purpose |
|-----------|------|---------|
| MCP Entry | `scripts/okta-mcp.mjs` | Routes CLI commands or starts the MCP server |
| MCP Server | `scripts/lab-mcp.mjs` | MCP tool definitions, browser lifecycle, collector management |
| Browser Worker | `scripts/browser-session-worker.mjs` | Isolated browser control via CDP, cookie capture, token harvest |
| CDP Client | `scripts/lab-browser-session-proof.mjs` | WebSocket CDP client with event support, browser helpers |
| Collector | `scripts/collector.mjs` | Loopback HTTP server storing cookies and tokens to disk |
| Test Harness | `scripts/test-harvest-flow.mjs` | Standalone harvest test (no MCP, direct CDP) |

## MCP Tools

### Session Tools

| Tool | Description |
|------|-------------|
| `okta-start` | Configure auth mode, open browser, begin authentication |
| `okta-reset` | Close browser, clear saved config, return to first-run state |
| `okta-status` | Show config, connection, browser, and collector status |
| `okta-browser-session-proof` | Open/reuse browser, authenticate, capture redacted cookie metadata |
| `okta-browser-harvest-tokens` | Silent OAuth harvest from all assigned public OIDC apps |
| `okta-browser-status` | Browser state, current page, identity |
| `okta-browser-snapshot` | Sanitized page structure (no credentials) |
| `okta-browser-navigate` | Navigate within Okta origin |
| `okta-browser-read` | Same-origin GET under `/api/v1/` |
| `okta-browser-close` | Close browser, delete temp profile |

### OIDC Tools

| Tool | Description |
|------|-------------|
| `okta-oauth-login` | OIDC Authorization Code + PKCE flow |
| `okta-oauth-reuse-proof` | Demonstrate bearer-token reuse with SHA-256 fingerprint |
| `whoami` / `userinfo` | Connected user identity |
| `list-users` / `list-groups` / `list-apps` | Admin API queries (require scopes) |

## Token Harvest Technique

The harvest uses CDP (Chrome DevTools Protocol) to perform silent OAuth flows:

1. **App enumeration** - `GET /api/v1/apps?limit=200` via the authenticated browser session
2. **Client filtering** - Only targets apps with `token_endpoint_auth_method: "none"` (public/SPA clients)
3. **Silent authorize** - Navigates to `/oauth2/default/v1/authorize` with `prompt=none` and PKCE challenge
4. **CDP Fetch interception** - `Fetch.enable` with URL pattern matching the app's redirect URI origin. The `Fetch.requestPaused` event captures the authorization code from the redirect before the request reaches the (unreachable) localhost callback
5. **Code exchange** - Standard PKCE token exchange from Node.js using the captured code and verifier
6. **Stealth** - Browser window is minimized during harvest via `Browser.setWindowBounds` and restored after

## Setup

### Requirements

- Node.js 22+
- Microsoft Edge or Google Chrome
- An Okta organization with OIDC apps assigned to the test user

### Install

```bash
npm ci
npm run build
```

### Run via MCP Client

Register with your MCP client (Claude Code, VS Code, etc.):

```json
{
  "type": "stdio",
  "command": "node",
  "args": ["C:\\path\\to\\scripts\\okta-mcp.mjs"]
}
```

Then ask the client: "Start Okta MCP"

### Run Standalone Test

```bash
# Start the collector
node scripts/collector.mjs

# In another terminal, run the harvest test
node scripts/test-harvest-flow.mjs
```

### Retrieve Harvested Tokens

```bash
# Latest token harvest
curl http://127.0.0.1:8765/v1/tokens/latest

# Latest cookie proof
curl http://127.0.0.1:8765/v1/cookie-proofs/latest

# Collector dashboard
open http://127.0.0.1:8765/
```

## Collector Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | HTML dashboard |
| GET | `/health` | Collector health check |
| POST | `/v1/cookie-proofs` | Store browser cookie metadata |
| GET | `/v1/cookie-proofs/latest` | Latest cookie proof |
| GET | `/v1/cookies` | Latest cookies (Cookie-Editor format) |
| POST | `/v1/tokens` | Store harvested OAuth tokens |
| GET | `/v1/tokens/latest` | Latest token harvest |
| POST | `/v1/oauth-token-proofs` | Store OAuth reuse evidence |
| GET | `/v1/oauth-token-proofs/latest` | Latest OAuth proof |

## Detection Opportunities

- **Okta System Log**: `app.oauth2.authorize` events with `prompt=none` from unfamiliar user agents or rapid-fire across multiple apps
- **Unusual app enumeration**: Admin API calls to `/api/v1/apps` from browser sessions
- **Token exchange patterns**: Multiple `app.oauth2.token.grant.authorization_code` events in quick succession from the same session
- **CDP debug port**: Chrome launched with `--remote-debugging-port` in process listings

## Author

**Oren Bahar** - Security Researcher

- Cookie-Bite: [Varonis Publication](https://www.varonis.com/blog/cookie-bite)

## Disclaimer

This tool is for authorized security research and testing only. Use it only against Okta organizations and identities you own or have explicit written permission to test. Unauthorized use may violate applicable laws.

## License

MIT
