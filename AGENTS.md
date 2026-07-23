# Okta MCP operation

When the user asks to start, connect, configure, or authenticate the Okta MCP:

- Call the configured `okta-start` MCP tool immediately.
- Do not launch MCP Inspector. It is a development utility and is not part of
  the normal setup experience.
- On first use, let `okta-start` ask whether to use Browser Session or
  OIDC/OAuth and collect only the settings required for the selected mode.
  Later starts reuse saved setup. Pass `reconfigure=true` only when the user
  explicitly asks to change the configuration.
- When the user explicitly asks to reset the Okta MCP configuration, call
  `okta-reset` with `confirm=true`. Explain that it closes any live browser and
  removes this MCP's saved authentication settings and local OAuth cache. The
  next `okta-start` call presents the first-run form again.
- If `okta-start` is unavailable, run `npm run check:codex`. If registration is
  missing or outdated, run `npm run setup:codex`, then explain that Codex must
  be restarted once to load the corrected absolute entrypoint. Do not use a
  different launcher.
- Never request, display, or persist raw cookie values or raw OAuth tokens.
- After Browser Session authentication, treat the isolated browser as active
  until `okta-browser-close`, MCP shutdown, manual browser close, or the idle
  timeout. Use `okta-browser-status`, `okta-browser-snapshot`,
  `okta-browser-navigate`, and `okta-browser-read` for supported read-only
  operations. Do not state that the temporary profile was deleted while
  `browser_session_active` is true.
