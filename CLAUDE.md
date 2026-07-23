# Project context — Okta Workspace MCP

## Purpose

Okta Workspace MCP is a local identity-integration application for connecting
MCP clients to an Okta organization. It provides guided authentication,
read-only identity and organization tools, an isolated browser workflow, and
privacy-preserving local session metadata.

The project is intended for software development, integration validation,
administration, and demonstrations using an Okta organization controlled by
the operator. It is not affiliated with or endorsed by Okta.

## Functional scope

- **Browser Session mode** — opens a temporary isolated browser, allows the user
  to sign in directly with Okta, supports same-origin read-only operations, and
  records cookie metadata with values replaced by `[REDACTED]`.
- **OIDC/OAuth mode** — uses Authorization Code with PKCE for identity data and
  optional read-only Okta APIs.
- **Local metadata service** — accepts redacted Browser Session records and
  one-way OAuth fingerprints on `127.0.0.1` only.
- **Configuration lifecycle** — guides first-time setup, reuses saved settings,
  and supports an explicit reset to restore the first-run experience.
- **Privacy controls** — keeps raw cookie values inside the browser worker and
  does not return raw OAuth tokens through MCP tools.

## Development principles

- Keep authentication behavior explicit and user-driven.
- Limit browser and organization operations to documented read-only behavior.
- Preserve same-origin restrictions and loopback-only local services.
- Keep credential values out of tool responses, metadata records, logs, and
  documentation examples.
- Use temporary browser profiles and remove them at the end of the session.
- Maintain automated tests for configuration, authentication, privacy filters,
  browser lifecycle, reset behavior, and package contents.
- Describe the project as a normal identity-integration program using neutral,
  implementation-focused terminology.

## Working preferences

- Keep responses concise and direct.
- Prefer editing existing files over creating new ones.
- Avoid unnecessary comments or docstrings.
- Do not use emojis unless requested.
- Explain behavior in terms of inputs, processing, outputs, permissions, and
  lifecycle state.
