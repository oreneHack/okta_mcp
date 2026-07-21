# Okta MCP startup

When the user asks to start, connect, configure, or authenticate the Okta MCP:

- Call the configured `okta-start` MCP tool immediately.
- Do not launch MCP Inspector. It is a developer diagnostic UI, not this
  project's setup experience.
- On first use, let `okta-start` ask whether to use Browser Session or
  OIDC/OAuth and collect only the settings required for the selected mode.
  Later starts reuse saved setup. Pass `reconfigure=true` only when the user
  explicitly asks to change it.
- When the user explicitly asks to reset, clear, or demonstrate a fresh Okta
  MCP setup, call `okta-reset` with `confirm=true`. Explain that it closes any
  live browser and removes only this MCP's saved authentication setup and local
  OAuth cache; the next `okta-start` presents the first-run form again.
- If `okta-start` is unavailable, run `npm run check:codex`. If registration is
  missing or stale, run `npm run setup:codex`; then explain that Codex must be
  restarted once to load the corrected absolute entrypoint. Do not substitute
  another launcher.
- Never request, display, or persist raw cookie values or raw OAuth tokens.
- After Browser Session authentication, treat the isolated browser as live until
  `okta-browser-close`, MCP shutdown, manual browser close, or idle timeout.
  Use `okta-browser-status`, `okta-browser-snapshot`, `okta-browser-navigate`,
  and `okta-browser-read` for safe read-only work. Do not claim its temporary
  profile was deleted while `browser_session_active` is true.
