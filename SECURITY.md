# Security and data-handling policy

## Application scope

Okta Workspace MCP is a local stdio integration with Browser Session and
OIDC/OAuth authentication modes. It is designed for organizations and user
identities that the operator is permitted to access.

Browser Session mode opens a temporary isolated browser and publishes redacted
session metadata to a loopback-only local service. OIDC/OAuth mode uses
Authorization Code with PKCE and can access identity information and optional
read-only Okta organization APIs.

The default OIDC scope set is limited to identity data. Read-only organization
access must be selected explicitly and remains subject to both the OIDC
application's granted scopes and the signed-in user's Okta roles or resource
assignments.

## Data boundaries

- Raw browser cookie values remain inside the isolated browser worker.
- Cookie metadata records set every `value` field to `[REDACTED]`.
- Raw OAuth access tokens, refresh tokens, and ID tokens are not returned by MCP
  tools or sent to the local metadata service.
- OAuth metadata may include a one-way SHA-256 token fingerprint and read-only
  request status information.
- The metadata service listens only on `127.0.0.1` and retains one record of
  each type by default.
- Browser control uses private child-process IPC rather than an HTTP control
  interface.
- Browser tools support sanitized snapshots, same-origin navigation, and
  read-only `GET` requests under `/api/v1/` only.

## Local files

The application stores configuration under the current user's
`.okta-workspace-mcp` directory:

- `startup.json` contains the selected mode and Okta organization.
- `config.json` contains public OIDC client settings.
- `tokens.json` contains the local OAuth token cache.

Restrict these files to the current OS user. The token cache is a local JSON
file rather than an operating-system credential-vault entry. Do not commit,
upload, copy into issue reports, or paste its contents into chat systems.

The Browser Session uses a temporary profile managed by a child process. The
profile is removed on explicit close, MCP shutdown, manual browser close, or
the 30-minute inactivity timeout.

## Recommended configuration

- Review and pin the source revision before installation.
- Register only the required loopback redirect URI. The default is
  `http://localhost:8749/callback`.
- Assign the OIDC application only to the intended users or groups.
- Begin with `openid profile email offline_access`.
- Add individual `okta.*` read scopes only for tools that require them.
- Add the optional `groups` scope only when `my-groups` is needed, and configure
  the corresponding ID-token claim in Okta.
- Review the organization, client ID, scopes, and callback shown by
  `okta-start` or `okta-status` before authenticating.
- Confirm that the browser sign-in page uses the configured Okta origin before
  entering credentials or MFA information.
- Run `okta-workspace-mcp logout` when OIDC access is no longer needed.
- Use `okta-reset` when saved MCP authentication settings should be removed.
- Keep protocol output on `stdout` and diagnostics on `stderr` when operating
  in stdio mode.

## Browser Session lifecycle

The local service refreshes redacted Browser Session metadata:

- After successful authentication.
- After reauthentication or a detected session change.
- Every five minutes while the session remains authenticated.
- During an orderly browser close when the session is still available.

The local service rejects records containing non-redacted cookie values or
fields intended to carry raw credentials.

## Reporting a problem

Report security or privacy issues privately through GitHub's private
vulnerability-reporting feature. Do not include tokens, authorization codes,
tenant-specific user data, cookies, or other credentials in a public issue.

Use dummy values or a dedicated development organization in reproduction
steps. If a credential is included accidentally, revoke it immediately and
replace it before continuing.

## Supported versions

Until tagged releases are available, only the latest commit on `main` is
maintained. Pin the exact revision used for a deployment.
