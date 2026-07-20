# Security Policy

## Scope

Okta Workspace MCP is one local stdio MCP server with explicit Browser Session
and OIDC/OAuth modes. Browser mode publishes redacted cookie metadata. OIDC mode
handles access and refresh tokens for the organization explicitly configured by
the user and uses Authorization Code with PKCE.

The default permission set is identity-only. Organization-read access must be
enabled explicitly and remains subject to the OIDC application's Okta API scope
grants and the signed-in user's Okta roles/resource assignments.

An Okta administrator grants requested `okta.*` management scopes to the OIDC
application in advance. The hosted login might not show an interactive consent
screen for those app grants, so operators must review the exact scope list
reported by `okta-start`, `okta-status`, and `okta-oauth-login` before
authentication.

## Operational guidance

- Review and pin the source revision before installing the server.
- Register only the required loopback redirect URI
  (`http://localhost:8749/callback` by default) on the Okta application.
- Assign the OIDC application to the smallest practical set of users or groups.
- Start with `openid profile email offline_access`; add individual `okta.*`
  read scopes only when their tools are needed.
- Add the optional `groups` identity scope only when `my-groups` is needed, and
  configure the corresponding ID-token `groups` claim on the Okta application.
- Keep local configuration and token files readable only by the current OS
  user. The token cache is a local JSON file containing live bearer credentials,
  not an OS credential-vault entry. Never commit, upload, or paste it into an
  AI chat.
- Verify the hosted sign-in page uses the exact configured Okta origin before
  entering credentials or MFA values.
- Run `okta-workspace-mcp logout` and revoke the OIDC grant in Okta when access
  is no longer required.
- In `stdio` mode, write protocol messages only to `stdout`; send diagnostics to
  `stderr` so logging cannot corrupt the MCP connection.
- Browser Session mode must remain explicit, loopback-only, and redacted. Its
  proof may record cookie objects and HttpOnly metadata, but every
  `value` must be exactly `[REDACTED]`. Its OAuth proof may record a one-way
  token fingerprint and controlled request results but never raw tokens,
  replayable Cookie-Editor files, Netscape jars, cookie headers, or
  authorization headers. The collector keeps one proof of each type by default
  and rejects credential-bearing fields.
- A live Browser Session uses a temporary isolated profile owned by a child
  worker. Raw cookies remain inside that worker/browser boundary. Control uses
  private process IPC, not an HTTP control service. The current tool surface is
  limited to sanitized snapshots, same-origin navigation, and same-origin
  read-only `GET` requests under `/api/v1/`; it exposes no arbitrary JavaScript
  or write-capable browser action.
- Redacted Browser Session proofs are refreshed after authentication or
  reauthentication, on detected session rotation, every five minutes while
  authenticated, and once more during an orderly close. The temporary profile
  is deleted on explicit close, MCP shutdown, manual browser close, or the
  30-minute inactivity timeout.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's private
vulnerability-reporting feature. Do not open a public issue containing access
tokens, refresh tokens, authorization codes, tenant details, user data, or other
live credentials.

Include a minimal reproduction using dummy values or an isolated test tenant.
Immediately revoke any credential accidentally exposed during testing.

## Supported versions

Until tagged releases are available, only the latest commit on `main` is
maintained. Pin the exact revision you review and run.
