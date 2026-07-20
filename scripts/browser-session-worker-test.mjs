const option = (name) => {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
};

const organization = new URL(option("org-url")).origin;
const state = {
  session_id: "mock-live-browser-session",
  status: "authenticated",
  organization,
  started_at: new Date().toISOString(),
  authenticated_at: new Date().toISOString(),
  last_activity_at: new Date().toISOString(),
  last_proof_at: new Date().toISOString(),
  last_proof_reason: "initial_authentication",
  proof_interval_seconds: 300,
  idle_timeout_seconds: 1800,
  current_url: `${organization}/app/UserHome`,
  page_title: "Okta Dashboard",
  user_login: "authorized-browser@example.test",
  user_id: "00u-mock-browser",
  cookie_values_exposed: false,
  last_error: null,
};

function send(message) {
  if (process.send && process.connected) process.send(message);
}

send({ type: "event", event: "ready", state });

process.on("message", (message) => {
  if (!message || message.type !== "command") return;
  let result;
  if (message.command === "status") result = state;
  else if (message.command === "snapshot") {
    result = {
      url: state.current_url,
      title: state.page_title,
      headings: ["Dashboard"],
      controls: [{ tag: "a", text: "People", href: `${organization}/admin/users` }],
      visible_text: "Authorized test dashboard",
    };
  } else if (message.command === "navigate") {
    state.current_url = new URL(message.payload.url).origin + new URL(message.payload.url).pathname;
    result = { navigated: true, current_url: state.current_url, restricted_to_origin: organization };
  } else if (message.command === "read") {
    result = {
      ok: true,
      status: 200,
      content_type: "application/json",
      body: [{ id: "00u-mock-browser", profile: { login: "authorized-browser@example.test" } }],
      method: "GET",
      same_origin_only: true,
      cookie_values_exposed: false,
    };
  } else if (message.command === "refresh_proof") {
    result = {
      posted: true,
      reason: "manual_refresh",
      cookie_count: 4,
      cookie_values_exposed: false,
    };
  } else if (message.command === "close") {
    result = { closing: true, session_id: state.session_id };
  } else {
    send({ type: "response", id: message.id, ok: false, error: "Unsupported mock command" });
    return;
  }

  send({ type: "response", id: message.id, ok: true, result });
  if (message.command === "close") {
    state.status = "closed";
    state.close_reason = "explicit_close";
    send({ type: "event", event: "closed", state });
    process.disconnect();
  }
});
