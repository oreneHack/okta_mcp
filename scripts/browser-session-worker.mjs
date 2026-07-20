import crypto from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  CdpClient,
  browserSessionProbe,
  delay,
  ensureCollector,
  findBrowser,
  freePort,
  matchingBrowserCookies,
  nextBrowserProofReason,
  postProof,
  redactedCookieInventory,
  stopBrowser,
  validateEndpoint,
  validateOrgUrl,
  waitForTarget,
} from "./lab-browser-session-proof.mjs";

const DEFAULT_PROOF_INTERVAL_MS = 5 * 60 * 1000;
const DEFAULT_IDLE_TIMEOUT_MS = 30 * 60 * 1000;
const DEFAULT_POLL_INTERVAL_MS = 2_000;
const MIN_ROTATION_PROOF_INTERVAL_MS = 30_000;
const MAX_TEXT_RESULT = 64 * 1024;

function option(name) {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return undefined;
  const value = process.argv[index + 1];
  return value && !value.startsWith("--") ? value : undefined;
}

function durationFromEnvironment(name, fallback, minimum) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < minimum) {
    throw new Error(`${name} must be an integer of at least ${minimum} milliseconds.`);
  }
  return value;
}

function send(message) {
  if (typeof process.send === "function" && process.connected) {
    process.send(message);
  }
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function disconnectIpc() {
  if (process.connected) process.disconnect();
}

function safeUrl(value, expectedOrigin) {
  try {
    const parsed = new URL(value, expectedOrigin);
    if (parsed.origin !== expectedOrigin) return null;
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return null;
  }
}

function redactString(value) {
  return String(value)
    .replace(
      /("(?:access[_-]?token|refresh[_-]?token|id[_-]?token|cookie|authorization|password|secret|credential)"\s*:\s*")[^"]*(")/gi,
      "$1[REDACTED]$2"
    )
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED_JWT]")
    .slice(0, MAX_TEXT_RESULT);
}

function redactSensitive(value, depth = 0) {
  if (depth > 8) return "[TRUNCATED]";
  if (typeof value === "string") return redactString(value);
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    return value.slice(0, 200).map((item) => redactSensitive(item, depth + 1));
  }
  const result = {};
  for (const [key, item] of Object.entries(value).slice(0, 300)) {
    if (/token|cookie|authorization|password|secret|credential|session.?id/i.test(key)) {
      result[key] = "[REDACTED]";
    } else {
      result[key] = redactSensitive(item, depth + 1);
    }
  }
  return result;
}

function normalizeNavigationTarget(value, orgUrl) {
  const parsed = new URL(String(value || ""), orgUrl);
  if (
    parsed.origin !== orgUrl ||
    parsed.username ||
    parsed.password ||
    !["https:"].includes(parsed.protocol)
  ) {
    throw new Error(`Navigation is restricted to ${orgUrl}.`);
  }
  return parsed.toString();
}

function normalizeApiTarget(value, orgUrl) {
  const parsed = new URL(String(value || ""), orgUrl);
  if (
    parsed.origin !== orgUrl ||
    parsed.username ||
    parsed.password ||
    !parsed.pathname.startsWith("/api/v1/")
  ) {
    throw new Error(`Read requests are restricted to ${orgUrl}/api/v1/.`);
  }
  return parsed.toString();
}

function authMaterialFingerprint(cookies) {
  const candidates = cookies.filter((cookie) =>
    cookie.httpOnly === true ||
    /(?:^|[_-])(sid|session|idx|auth|okta)(?:$|[_-])/i.test(String(cookie.name || ""))
  );
  const selected = candidates.length ? candidates : cookies.filter((cookie) => cookie.secure === true);
  const material = selected
    .map((cookie) => `${cookie.domain}\0${cookie.path}\0${cookie.name}\0${cookie.value}`)
    .sort()
    .join("\n");
  return crypto.createHash("sha256").update(material).digest("hex");
}

const orgUrl = validateOrgUrl(option("org-url"));
const endpoint = validateEndpoint(option("endpoint"));
const proofIntervalMs = durationFromEnvironment(
  "OKTA_MCP_BROWSER_PROOF_INTERVAL_MS",
  DEFAULT_PROOF_INTERVAL_MS,
  process.env.NODE_ENV === "test" ? 50 : 60_000
);
const idleTimeoutMs = durationFromEnvironment(
  "OKTA_MCP_BROWSER_IDLE_TIMEOUT_MS",
  DEFAULT_IDLE_TIMEOUT_MS,
  process.env.NODE_ENV === "test" ? 250 : 60_000
);
const pollIntervalMs = durationFromEnvironment(
  "OKTA_MCP_BROWSER_POLL_INTERVAL_MS",
  DEFAULT_POLL_INTERVAL_MS,
  process.env.NODE_ENV === "test" ? 25 : 250
);

const state = {
  session_id: crypto.randomUUID(),
  status: "starting",
  organization: orgUrl,
  started_at: new Date().toISOString(),
  authenticated_at: null,
  last_activity_at: new Date().toISOString(),
  last_proof_at: null,
  last_proof_reason: null,
  proof_interval_seconds: Math.round(proofIntervalMs / 1000),
  idle_timeout_seconds: Math.round(idleTimeoutMs / 1000),
  current_url: null,
  page_title: null,
  user_login: null,
  user_id: null,
  cookie_values_exposed: false,
  last_error: null,
};

let browser;
let cdp;
let profileDir;
let closing = false;
let cleanupPromise;
let proofPromise;
let lastAuthenticated = false;
let everAuthenticated = false;
let lastFingerprint = null;
let lastObservedUrl = null;
let commandChain = Promise.resolve();

function publicState() {
  return { ...state };
}

function emitState(event = "state") {
  send({ type: "event", event, state: publicState() });
}

function touchActivity() {
  state.last_activity_at = new Date().toISOString();
}

async function evaluate(expression) {
  const result = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) {
    throw new Error(
      result.exceptionDetails.exception?.description ||
      result.exceptionDetails.text ||
      "The browser page rejected the operation."
    );
  }
  return result.result?.value;
}

async function updatePageState() {
  const page = await evaluate(`(() => ({ url: location.href, title: document.title }))()`);
  const nextUrl = safeUrl(page?.url, orgUrl);
  state.current_url = nextUrl || "outside_configured_origin";
  state.page_title = redactString(page?.title || "").slice(0, 300);
  if (nextUrl && nextUrl !== lastObservedUrl) {
    lastObservedUrl = nextUrl;
    touchActivity();
  }
}

async function captureProof(reason, probe, rawCookies, sessionActive = true) {
  if (proofPromise) return proofPromise;
  proofPromise = (async () => {
    const cookies = await redactedCookieInventory(cdp, orgUrl, rawCookies);
    const posted = await postProof(endpoint, orgUrl, probe, cookies, {
      captureReason: reason,
      browserProfile: sessionActive
        ? "temporary_isolated_profile_active"
        : "temporary_isolated_profile_deleted_after_capture",
      sessionActive,
    });
    state.last_proof_at = new Date().toISOString();
    state.last_proof_reason = reason;
    state.last_error = null;
    emitState("proof_posted");
    return {
      posted: true,
      reason,
      captured_at: state.last_proof_at,
      cookie_count: cookies.length,
      deleted_old_count: posted.deleted_old_count,
      retained_count: posted.retained_count,
      cookie_values_exposed: false,
    };
  })().finally(() => {
    proofPromise = null;
  });
  return proofPromise;
}

async function requireAuthenticatedProbe() {
  const probe = await browserSessionProbe(cdp);
  if (!probe?.ok || probe.status !== 200 || probe.origin !== orgUrl) {
    throw new Error("The live browser is not currently authenticated to the configured Okta tenant.");
  }
  return probe;
}

async function snapshot() {
  await requireAuthenticatedProbe();
  const result = await evaluate(`(() => {
    const visible = element => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
    };
    const text = value => String(value || '').replace(/\\s+/g, ' ').trim().slice(0, 500);
    const controls = Array.from(document.querySelectorAll('a,button,input,select,textarea,[role="button"],[role="link"]'))
      .filter(visible)
      .slice(0, 150)
      .map(element => {
        let href;
        if (element instanceof HTMLAnchorElement && element.href) {
          try {
            const parsed = new URL(element.href, location.href);
            if (parsed.origin === location.origin) href = parsed.origin + parsed.pathname;
          } catch {}
        }
        return {
          tag: element.tagName.toLowerCase(),
          role: element.getAttribute('role') || undefined,
          type: element.getAttribute('type') || undefined,
          text: text(element.innerText || element.getAttribute('aria-label') || element.getAttribute('title') || element.getAttribute('placeholder') || element.getAttribute('name')),
          href,
          disabled: element.matches(':disabled') || element.getAttribute('aria-disabled') === 'true'
        };
      });
    return {
      url: location.origin + location.pathname,
      title: document.title,
      headings: Array.from(document.querySelectorAll('h1,h2,h3,[role="heading"]')).filter(visible).slice(0, 50).map(element => text(element.innerText)),
      controls,
      visible_text: text(document.body && document.body.innerText).slice(0, 12000)
    };
  })()`);
  return redactSensitive(result);
}

async function navigate(target) {
  const url = normalizeNavigationTarget(target, orgUrl);
  await cdp.send("Page.navigate", { url });
  await delay(750);
  await updatePageState();
  return {
    navigated: true,
    current_url: state.current_url,
    page_title: state.page_title,
    restricted_to_origin: orgUrl,
  };
}

async function readApi(target) {
  await requireAuthenticatedProbe();
  const url = normalizeApiTarget(target, orgUrl);
  const result = await evaluate(`(() => {
    if (location.origin !== ${JSON.stringify(orgUrl)}) {
      throw new Error('The active page is outside the configured Okta origin.');
    }
    return fetch(${JSON.stringify(url)}, {
      method: 'GET',
      credentials: 'include',
      redirect: 'error',
      headers: { Accept: 'application/json' }
    }).then(async response => ({
      ok: response.ok,
      status: response.status,
      contentType: response.headers.get('content-type') || '',
      text: (await response.text()).slice(0, ${MAX_TEXT_RESULT}),
      truncated: Number(response.headers.get('content-length') || 0) > ${MAX_TEXT_RESULT}
    }));
  })()`);
  let body = redactString(result?.text || "");
  if (String(result?.contentType || "").toLowerCase().includes("json")) {
    try {
      body = redactSensitive(JSON.parse(body));
    } catch {
      // A truncated or non-standard response remains redacted text.
    }
  }
  return {
    ok: result?.ok === true,
    status: result?.status,
    content_type: result?.contentType,
    body,
    truncated: result?.truncated === true || String(result?.text || "").length >= MAX_TEXT_RESULT,
    method: "GET",
    same_origin_only: true,
    cookie_values_exposed: false,
  };
}

async function monitor() {
  while (!closing) {
    try {
      await updatePageState();
      const probe = await browserSessionProbe(cdp);
      const authenticated = Boolean(
        probe?.ok && probe.status === 200 && probe.origin === orgUrl
      );
      if (authenticated) {
        const rawCookies = await matchingBrowserCookies(cdp, orgUrl);
        const fingerprint = authMaterialFingerprint(rawCookies);
        const proofReason = nextBrowserProofReason({
          lastAuthenticated,
          everAuthenticated,
          lastFingerprint,
          currentFingerprint: fingerprint,
          lastProofAt: state.last_proof_at,
          proofIntervalMs,
          rotationMinimumMs: MIN_ROTATION_PROOF_INTERVAL_MS,
        });

        state.status = "authenticated";
        state.authenticated_at ||= new Date().toISOString();
        state.user_login = probe.user_login || null;
        state.user_id = probe.user_id || null;
        lastAuthenticated = true;
        everAuthenticated = true;
        lastFingerprint = fingerprint;
        if (proofReason) await captureProof(proofReason, probe, rawCookies);
      } else {
        const changed = lastAuthenticated;
        lastAuthenticated = false;
        lastFingerprint = null;
        state.status = everAuthenticated
          ? "awaiting_reauthentication"
          : "awaiting_authentication";
        state.user_login = null;
        state.user_id = null;
        if (changed) emitState("authentication_lost");
      }
      state.last_error = null;
    } catch (error) {
      state.last_error = errorMessage(error);
    }

    if (Date.now() - Date.parse(state.last_activity_at) >= idleTimeoutMs) {
      await cleanup("idle_timeout");
      return;
    }
    await delay(pollIntervalMs);
  }
}

async function executeCommand(command, payload) {
  touchActivity();
  if (command === "status") {
    await updatePageState().catch(() => {});
    return publicState();
  }
  if (command === "snapshot") return snapshot();
  if (command === "navigate") return navigate(payload?.url);
  if (command === "read") return readApi(payload?.path);
  if (command === "refresh_proof") {
    const probe = await requireAuthenticatedProbe();
    const rawCookies = await matchingBrowserCookies(cdp, orgUrl);
    lastFingerprint = authMaterialFingerprint(rawCookies);
    return captureProof("manual_refresh", probe, rawCookies);
  }
  if (command === "close") return { closing: true, session_id: state.session_id };
  throw new Error(`Unsupported live-browser command: ${command}`);
}

async function cleanup(reason) {
  if (cleanupPromise) return cleanupPromise;
  cleanupPromise = (async () => {
    closing = true;
    state.status = "closing";
    emitState("closing");
    if (cdp && lastAuthenticated) {
      try {
        const probe = await requireAuthenticatedProbe();
        const rawCookies = await matchingBrowserCookies(cdp, orgUrl);
        await captureProof("browser_session_closed", probe, rawCookies, false);
      } catch {
        // A browser closed manually may no longer be available for a final proof.
      }
    }
    cdp?.close();
    if (browser) stopBrowser(browser);
    await delay(500);
    if (profileDir) {
      try {
        fs.rmSync(profileDir, { recursive: true, force: true });
      } catch (error) {
        state.last_error = `Temporary profile cleanup warning: ${errorMessage(error)}`;
      }
    }
    state.status = "closed";
    state.closed_at = new Date().toISOString();
    state.close_reason = reason;
    state.current_url = null;
    state.page_title = null;
    state.user_login = null;
    state.user_id = null;
    emitState("closed");
  })();
  return cleanupPromise;
}

process.on("message", (message) => {
  if (!message || message.type !== "command" || !message.id) return;
  commandChain = commandChain.then(async () => {
    try {
      const result = await executeCommand(message.command, message.payload);
      send({ type: "response", id: message.id, ok: true, result });
      if (message.command === "close") {
        await cleanup("explicit_close");
        process.exitCode = 0;
        disconnectIpc();
      }
    } catch (error) {
      send({ type: "response", id: message.id, ok: false, error: errorMessage(error) });
    }
  });
});

process.once("disconnect", () => {
  cleanup("mcp_disconnected").finally(() => {
    process.exitCode = 0;
  });
});
process.once("SIGTERM", () => {
  cleanup("mcp_shutdown").finally(() => {
    process.exitCode = 0;
    disconnectIpc();
  });
});
process.once("SIGINT", () => {
  cleanup("mcp_shutdown").finally(() => {
    process.exitCode = 0;
    disconnectIpc();
  });
});

async function start() {
  if (typeof WebSocket !== "function") {
    throw new Error("Live Browser Session mode requires Node.js 22 or newer.");
  }
  await ensureCollector(endpoint);
  const browserPath = findBrowser();
  const debugPort = await freePort();
  profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "okta-mcp-live-browser-"));
  browser = spawn(
    browserPath,
    [
      `--user-data-dir=${profileDir}`,
      `--remote-debugging-port=${debugPort}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--new-window",
      `${orgUrl}/`,
    ],
    { detached: false, stdio: "ignore" }
  );
  browser.once("exit", () => {
    if (!closing) {
      cleanup("browser_closed_by_user").finally(() => {
        process.exitCode = 0;
        disconnectIpc();
      });
    }
  });
  const target = await waitForTarget(debugPort, orgUrl);
  cdp = new CdpClient(target.webSocketDebuggerUrl);
  await cdp.ready;
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  state.status = "awaiting_authentication";
  await updatePageState().catch(() => {});
  emitState("ready");
  await monitor();
  disconnectIpc();
}

try {
  await start();
} catch (error) {
  state.status = "error";
  state.last_error = errorMessage(error);
  emitState("error");
  await cleanup("startup_error").catch(() => {});
  process.exitCode = 1;
  disconnectIpc();
}
