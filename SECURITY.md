# Security Policy

## Scope

Okta Workspace MCP is a community research project that handles OAuth tokens
and, only in explicitly enabled security-lab mode, browser session cookies.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the repository owner
through GitHub's private vulnerability-reporting feature. Do not open a public
issue containing access tokens, refresh tokens, session cookies, tenant details,
collector output, or other live credentials.

Include a minimal reproduction using dummy values or an isolated test tenant.
Revoke any credential or session accidentally exposed during testing.

## Supported versions

Until tagged releases are available, only the latest commit on `main` is
maintained. Pin the exact revision you review and run.
