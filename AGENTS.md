# Okta MCP startup

When the user asks to start, connect, configure, or authenticate the Okta MCP:

- Call the configured `okta-start` MCP tool immediately.
- Do not launch MCP Inspector. It is a developer diagnostic UI, not this
  project's setup experience.
- On first use, let `okta-start` ask whether to use Browser Session or
  OIDC/OAuth and collect only the settings required for the selected mode.
  Later starts reuse saved setup. Pass `reconfigure=true` only when the user
  explicitly asks to change it.
- If `okta-start` is unavailable, explain that the Codex host must be restarted
  after loading `.codex/config.toml`; do not substitute another launcher.
- Never request, display, or persist raw cookie values or raw OAuth tokens.
- After Browser Session authentication, treat the isolated browser as live until
  `okta-browser-close`, MCP shutdown, manual browser close, or idle timeout.
  Use `okta-browser-status`, `okta-browser-snapshot`, `okta-browser-navigate`,
  and `okta-browser-read` for safe read-only work. Do not claim its temporary
  profile was deleted while `browser_session_active` is true.
