# Okta MCP Security Demonstration

## Purpose

This lab examines an identity-security boundary introduced by locally installed
MCP servers. An MCP can provide useful Okta tools while also having the local
process capabilities needed to open browsers, receive callbacks, cache tokens,
and—if intentionally built to do so—observe authentication artifacts created in
a browser it controls.

The research does not claim an Okta authentication bypass. It demonstrates how
trust in local AI tooling can place bearer tokens and browser sessions at risk.

Use only isolated tenants, applications, accounts, tokens, and sessions you are
authorized to test.

## Capability tiers

### 1. Core identity

The normal MCP path uses OAuth 2.0 Authorization Code with PKCE. The user signs
in on the hosted Okta page, Okta redirects to a localhost callback, and the MCP
receives scoped OAuth tokens.

```text
MCP starts
-> hosted Okta authentication opens
-> user completes authentication and MFA
-> Okta redirects to localhost:8749/callback
-> MCP exchanges the authorization code with PKCE
-> scoped tokens are cached locally
-> identity tools operate as the user
```

This path is enabled in a normal installation. It does not read browser cookies,
but it does receive and locally cache bearer tokens granted to the OAuth client.

### 2. Optional organization read

Read-only directory and application tools request explicit `okta.*` scopes and
still depend on the user's Okta role or resource-set authorization. These scopes
are not part of the default setup.

### 3. Session-security lab

The session lab is disabled by default. When explicitly enabled, `session-check`
launches a fresh Edge or Chrome profile with the Chrome DevTools Protocol,
waits for the user to authenticate to the configured Okta organization, reads
the cookies created in that controlled profile, and validates them against
`/api/v1/users/me`.

```text
Authorized researcher invokes session-check
-> MCP launches an isolated Chromium profile
-> user authenticates on the real Okta page
-> MCP observes the resulting session cookies through CDP
-> MCP validates the session against /api/v1/users/me
-> redacted evidence is posted to a loopback collector
```

The default proof contains cookie names, metadata, lengths, hashes, and the
validated identity. Replayable values and local cookie jars require separate,
explicit flags.

## Important implementation distinction

Startup OIDC authentication and the session lab are currently separate browser
flows. Startup authentication uses the system browser and receives OAuth tokens.
`session-check` uses a new CDP-controlled browser and observes that browser's
session cookies.

Do not edit a demonstration in a way that implies the current implementation
secretly captures cookies during the normal OIDC callback. A future integrated
lab flow must remain explicitly gated and documented.

## Demonstration claim

A precise publication claim is:

> MCP servers move identity risk into the local AI-tooling layer. A useful MCP
> can legitimately initiate browser authentication and receive OAuth tokens.
> A malicious or compromised MCP with browser-control capability could instead
> observe the authenticated session created after the user completes MFA and
> transmit replayable session material. Defenders therefore need MCP provenance,
> OAuth-client governance, endpoint visibility, and session-replay detection.

## Safe recording controls

- Use a disposable Okta tenant and dedicated test identity.
- Keep collectors on `127.0.0.1` for the publication lab.
- Record hashes, names, timestamps, and successful validation—not raw values.
- Use obvious `VICTIM` and `REPLAY` labels when demonstrating session reuse.
- Avoid destructive or write-capable administrative actions.
- Revoke sessions and refresh tokens immediately after recording.
- Delete browser profiles, cookie jars, token caches, and collector output.
- Never upload raw proof files to an issue, repository, editing service, or
  shared drive.

## Detection surface

### OAuth and client-governance signals

- first-seen or unsanctioned OAuth client ID
- localhost redirect URI
- `offline_access`
- unexpected `okta.*` scopes
- unusual client assignments or consent grants
- token grants associated with unmanaged AI tooling

Relevant Okta events can include:

- `app.oauth2.authorize.code`
- `user.authentication.sso`
- `app.oauth2.as.token.grant.access_token`
- `app.oauth2.as.token.grant.refresh_token`
- `app.oauth2.as.token.grant.id_token`
- `user.consent.grant`, when consent is enabled

### Session-replay signals

- session use from a new IP or ASN shortly after authentication
- a browser or device fingerprint inconsistent with the original sign-in
- activity from a session without a corresponding authentication event
- administrative access immediately following suspected replay
- impossible travel or geovelocity anomalies
- reuse after explicit user logout or incident-response action

### Endpoint and MCP-governance signals

- a new MCP server added to an AI client configuration
- package installation from an unreviewed source
- an MCP process spawning Edge or Chrome with remote debugging enabled
- local HTTP callbacks and evidence collectors
- token or cookie artifacts written under user-profile directories
- AI tooling making outbound requests to previously unseen destinations

## Defensive recommendations

- Maintain an approved MCP inventory and pin reviewed versions.
- Treat MCP installation as local code installation, not as a simple API link.
- Review servers that open browsers, host callbacks, or request identity scopes.
- Inventory OAuth clients and alert on first-seen clients and unusual scopes.
- Prefer least-privilege roles, short lifetimes, refresh-token rotation, and
  device-bound controls where supported.
- Monitor endpoint process trees and outbound destinations for AI tooling.
- Revoke both OAuth grants and browser sessions during incident response.
