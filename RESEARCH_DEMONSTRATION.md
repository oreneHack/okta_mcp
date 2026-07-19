# Okta MCP Security Demonstration

## Purpose

This research demonstrates how an MCP server can become a sensitive identity
execution point on a user's local machine.

The core point is not that Okta is uniquely broken. The point is that MCP servers
run with local process capabilities, can open browsers, can receive localhost
callbacks, can cache data, and can appear to the user as a helpful AI tool. That
creates identity-security risks that are different from classic web phishing,
browser extensions, or server-side OAuth abuse.

## Research Question

What can an untrusted or insufficiently reviewed MCP server do when a user adds it
to an AI client such as VS Code, Claude Desktop, Cursor, or another MCP-capable
assistant?

Specifically:

- Can the MCP initiate an authentication flow that looks normal to the user?
- Can the MCP receive OAuth tokens through a localhost callback?
- What does Okta log when this happens?
- What should defenders monitor to distinguish expected MCP use from risky or
  unsanctioned identity access?

## Demonstration Paths

### 1. OAuth Client Path

This is the current implemented lab.

The MCP is configured as an OAuth/OIDC client. When the user invokes an Okta MCP
tool, or when auth-on-start is enabled, the MCP opens the browser to Okta. The
user authenticates normally. Okta redirects to the MCP's localhost callback. The
MCP exchanges the authorization code with PKCE and receives tokens for that user.

Flow:

```text
User adds MCP to VS Code
-> VS Code launches MCP server
-> MCP opens Okta browser authentication
-> user authenticates normally
-> Okta redirects to localhost:8749/callback
-> MCP exchanges code for tokens
-> MCP caches tokens locally
-> MCP tools can call Okta APIs as the authenticated user
```

What this proves:

- MCP servers can legitimately receive Okta OAuth tokens.
- The token flow looks like a normal OAuth grant to Okta.
- The user may experience this as ordinary setup for a useful AI tool.
- Detection should focus on OAuth client governance: client inventory, scopes,
  redirect URI, consent, first-seen clients, and unusual token grants.

What this does not prove:

- It does not bypass Okta authentication.
- It does not bypass app registration requirements.
- It does not silently steal credentials.

### 2. Local Credential-Prompt Path

This is a separate threat model, not the same as OAuth.

An MCP server can run local code, open a browser, host a localhost page, or guide
the user through an authentication-looking moment. If abused, that local position
could be used for credential phishing.

For ethical and safety reasons, this repository should not collect real Okta
passwords or MFA material. A safe lab should use a mock identity page and dummy
credentials only.

Safe simulation flow:

```text
User adds MCP to VS Code
-> MCP opens a mock local identity prompt
-> user enters dummy lab credentials
-> collector records that a local process could solicit secrets
-> article explains detection and prevention controls
```

What this proves:

- MCP servers can create convincing local authentication moments.
- The risk is local execution plus user trust, not an Okta OAuth flaw.
- Okta may see nothing until stolen credentials are later used.
- Detection shifts from Okta-only logs to endpoint and MCP governance.

What this should not do:

- It should not capture real Okta credentials.
- It should not proxy or clone the real Okta login page.
- It should not collect passwords, MFA codes, push approvals, recovery factors,
  cookies, or session material.

## Why Client ID Matters In The OAuth Path

OAuth is always a relationship between a user and an application.

The Okta user proves who is signing in. The client ID identifies which app is
requesting tokens.

Okta uses the client ID to decide:

- which redirect URIs are allowed
- which scopes can be requested
- whether refresh tokens are allowed
- whether consent is required
- whether PKCE is required
- which users or groups are assigned
- which policies apply
- which OAuth client appears in System Log

This means the OAuth-path demonstration requires a registered app or an allowed
dynamic-registration process. If dynamic client registration is disabled and no
app is registered, this path is blocked by design.

That limitation is useful for the publication: it separates OAuth-client risk
from local credential-prompt risk.

## Detection Surface

### Okta System Log Signals

For the OAuth-client path, review:

- `app.oauth2.authorize.code`
- `user.authentication.sso`
- `app.oauth2.as.token.grant.access_token`
- `app.oauth2.as.token.grant.refresh_token`
- `app.oauth2.as.token.grant.id_token`
- `user.consent.grant`, when consent is enabled

Detection pivots:

- first-seen OAuth client ID
- localhost redirect URI
- `offline_access`
- `okta.*` management scopes
- unusual client assignment
- consent granted to an unsanctioned client
- token grants from unmanaged AI tooling

### Endpoint And MCP Governance Signals

For the local credential-prompt path, review:

- new MCP server added to VS Code or another AI client
- MCP server process spawning a browser
- local HTTP listeners on uncommon ports
- browser navigation to localhost during "authentication"
- MCP package provenance and install source
- unexpected local credential prompts
- files written under user profile MCP/plugin directories

## Defensive Recommendations

- Maintain an approved MCP server inventory.
- Require review for MCPs that open browsers, host localhost callbacks, or
  request identity scopes.
- Inventory Okta OAuth clients and alert on first-seen clients.
- Alert on localhost redirect URIs for unsanctioned apps.
- Monitor `offline_access` and `okta.*` scopes.
- Educate users that MCP install prompts are equivalent to installing local code.
- Prefer signed, reviewed, centrally managed MCP packages.
- For sensitive Okta apps, use short token lifetimes, refresh token rotation,
  DPoP where available, and strict client assignment.

## Publication Claim

A concise claim for the article:

```text
MCP servers move identity risk into the local AI-tooling layer. A sanctioned or
malicious MCP can initiate browser authentication, receive OAuth tokens through a
localhost callback, and operate as the user through normal-looking OAuth grants.
If OAuth registration is blocked, the separate risk is local credential-prompt
abuse: the MCP can still create authentication-looking moments that are visible
primarily to endpoint and MCP governance controls, not to Okta's OAuth logs.
```

