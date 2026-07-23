import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);
const DEFAULT_ENDPOINT = "http://127.0.0.1:8765/v1/cookie-proofs";
const POLL_INTERVAL_MS = 1_500;
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

export function nextBrowserProofReason({
  lastAuthenticated,
  everAuthenticated,
  lastFingerprint,
  currentFingerprint,
  lastProofAt,
  now = Date.now(),
  proofIntervalMs = 5 * 60 * 1000,
  rotationMinimumMs = 30_000,
}) {
  if (!lastAuthenticated) {
    return everAuthenticated
      ? "browser_reauthentication"
      : "initial_authentication";
  }
  const elapsed = lastProofAt ? now - Date.parse(lastProofAt) : Infinity;
  if (
    lastFingerprint &&
    currentFingerprint !== lastFingerprint &&
    elapsed >= rotationMinimumMs
  ) {
    return "reauthentication_or_session_rotation";
  }
  return elapsed >= proofIntervalMs ? "periodic_5_minutes" : null;
}

function option(name) {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return undefined;
  const value = process.argv[index + 1];
  return value && !value.startsWith("--") ? value : undefined;
}

export function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function validateOrgUrl(value) {
  const raw = String(value || "").trim().replace(/\/+$/, "");
  const normalized = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  const parsed = new URL(normalized);
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error(
      "The lab organization URL must be an exact HTTPS origin without credentials, path, query, or fragment."
    );
  }
  return parsed.origin;
}

export function validateEndpoint(value) {
  const endpoint = new URL(value);
  if (
    endpoint.protocol !== "http:" ||
    endpoint.hostname !== "127.0.0.1" ||
    !endpoint.port ||
    endpoint.pathname !== "/v1/cookie-proofs" ||
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash
  ) {
    throw new Error(
      "The lab collector must be exactly http://127.0.0.1:<port>/v1/cookie-proofs."
    );
  }
  return endpoint;
}

function validateTimeout(value) {
  if (value === undefined) return DEFAULT_TIMEOUT_MS;
  const seconds = Number(value);
  if (!Number.isInteger(seconds) || seconds < 30 || seconds > 900) {
    throw new Error("--timeout-seconds must be an integer from 30 to 900.");
  }
  return seconds * 1000;
}

function browserCandidates() {
  const explicit = process.env.OKTA_MCP_LAB_BROWSER?.trim();
  const candidates = explicit ? [explicit] : [];
  if (process.platform === "win32") {
    candidates.push(
      "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
      "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
    );
  } else if (process.platform === "darwin") {
    candidates.push(
      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    );
  } else {
    candidates.push(
      "/usr/bin/microsoft-edge",
      "/usr/bin/microsoft-edge-stable",
      "/usr/bin/google-chrome",
      "/usr/bin/google-chrome-stable",
      "/usr/bin/chromium",
      "/usr/bin/chromium-browser"
    );
  }
  return [...new Set(candidates)];
}

export function findBrowser() {
  const browser = browserCandidates().find((candidate) => fs.existsSync(candidate));
  if (!browser) {
    throw new Error(
      "Edge or Chrome was not found. Set OKTA_MCP_LAB_BROWSER to its executable path."
    );
  }
  return browser;
}

export async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Could not allocate a browser debugging port."));
        return;
      }
      server.close(() => resolve(address.port));
    });
  });
}

async function collectorHealth(endpoint) {
  const healthUrl = new URL("/health", endpoint);
  try {
    const response = await fetch(healthUrl, { redirect: "error" });
    if (!response.ok) return null;
    const body = await response.json();
    return body.service === "okta-mcp-redacted-lab-collector" ? body : null;
  } catch {
    return null;
  }
}

export async function ensureCollector(endpoint) {
  const existing = await collectorHealth(endpoint);
  if (existing?.live_browser_proofs === true) return { started: false };
  if (existing) {
    throw new Error(
      "An older Okta proof collector is already using this port. Stop that collector once, then start Okta MCP again so collector version 2 can launch."
    );
  }

  const collectorScript = path.join(rootDir, "scripts", "collector.mjs");
  const child = spawn(process.execPath, [collectorScript], {
    cwd: rootDir,
    env: {
      ...process.env,
      OKTA_MCP_COLLECTOR_HOST: "127.0.0.1",
      OKTA_MCP_COLLECTOR_PORT: endpoint.port,
      OKTA_MCP_PROOF_RETENTION:
        process.env.OKTA_MCP_PROOF_RETENTION || "1",
    },
    detached: true,
    stdio: "ignore",
    windowsHide: true,
  });
  child.unref();

  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    if (await collectorHealth(endpoint)) {
      return { started: true, pid: child.pid };
    }
    await delay(150);
  }
  throw new Error(
    `The redacted collector did not become healthy at ${new URL("/health", endpoint)}.`
  );
}

async function cdpTargets(port) {
  const response = await fetch(`http://127.0.0.1:${port}/json/list`, {
    redirect: "error",
  });
  if (!response.ok) throw new Error(`Browser CDP returned HTTP ${response.status}.`);
  return response.json();
}

export async function waitForTarget(port, expectedOrigin, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const targets = await cdpTargets(port);
      const target = targets.find((candidate) => {
        if (candidate.type !== "page" || !candidate.webSocketDebuggerUrl) return false;
        try {
          return new URL(candidate.url).origin === expectedOrigin;
        } catch {
          return false;
        }
      });
      if (target) return target;
    } catch {
      // Browser startup is still in progress.
    }
    await delay(200);
  }
  throw new Error("The isolated browser did not expose the configured Okta page.");
}

export class CdpClient {
  constructor(webSocketUrl) {
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
    this.socket = new WebSocket(webSocketUrl);
    this.ready = new Promise((resolve, reject) => {
      this.socket.addEventListener("open", resolve, { once: true });
      this.socket.addEventListener(
        "error",
        () => reject(new Error("Could not connect to the isolated browser.")),
        { once: true }
      );
    });
    this.socket.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data));
      if (message.id !== undefined) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.pending.delete(message.id);
        if (message.error) pending.reject(new Error(message.error.message));
        else pending.resolve(message.result);
      } else if (message.method) {
        const handlers = this.listeners.get(message.method);
        if (handlers) for (const h of handlers) h(message.params);
      }
    });
    this.socket.addEventListener("close", () => {
      for (const pending of this.pending.values()) {
        pending.reject(new Error("The isolated browser was closed."));
      }
      this.pending.clear();
    });
  }

  async send(method, params = {}) {
    await this.ready;
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  on(method, handler) {
    if (!this.listeners.has(method)) this.listeners.set(method, new Set());
    this.listeners.get(method).add(handler);
  }

  off(method, handler) {
    const handlers = this.listeners.get(method);
    if (handlers) handlers.delete(handler);
  }

  close() {
    this.socket.close();
  }
}

export function stopBrowser(child) {
  if (!child.pid) return;
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/F", "/T", "/PID", String(child.pid)], {
      stdio: "ignore",
      windowsHide: true,
    });
  } else {
    try {
      child.kill("SIGTERM");
    } catch {
      // Browser already closed.
    }
  }
}

export async function browserSessionProbe(client) {
  const expression = `(() => fetch('/api/v1/users/me', {
    credentials: 'include',
    redirect: 'manual',
    headers: { Accept: 'application/json' }
  }).then(async response => {
    let user = {};
    if (response.ok) {
      try { user = await response.json(); } catch {}
    }
    return {
      ok: response.status === 200,
      status: response.status,
      origin: location.origin,
      user_login: user && user.profile ? user.profile.login : undefined,
      user_id: user ? user.id : undefined,
      script_visible_cookie_names: document.cookie
        .split(';')
        .map(part => {
          const separator = part.indexOf('=');
          return (separator >= 0 ? part.slice(0, separator) : part).trim();
        })
        .filter(Boolean)
    };
  }).catch(error => ({
    ok: false,
    status: 0,
    origin: location.origin,
    error: String(error && error.message || error)
  })))()`;

  const result = await client.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) return null;
  return result.result?.value || null;
}

function cookieDomainMatchesHost(domain, hostname) {
  const normalizedDomain = String(domain || "")
    .trim()
    .replace(/^\./, "")
    .toLowerCase();
  const normalizedHost = hostname.toLowerCase();
  return (
    normalizedDomain &&
    (normalizedHost === normalizedDomain ||
      normalizedHost.endsWith(`.${normalizedDomain}`))
  );
}

export function adminHostname(orgUrl) {
  const hostname = new URL(orgUrl).hostname;
  const parts = hostname.split(".");
  if (parts.length >= 3 && !parts[0].endsWith("-admin")) {
    parts[0] += "-admin";
    return parts.join(".");
  }
  return null;
}

export function adminOrigin(orgUrl) {
  const admin = adminHostname(orgUrl);
  return admin ? `https://${admin}` : null;
}

export function isOrgOrigin(origin, orgUrl) {
  if (origin === orgUrl) return true;
  const admin = adminOrigin(orgUrl);
  return admin !== null && origin === admin;
}

export async function matchingBrowserCookies(client, orgUrl) {
  const hostname = new URL(orgUrl).hostname;
  const admin = adminHostname(orgUrl);
  const urls = [`https://${hostname}/`];
  if (admin) urls.push(`https://${admin}/`);
  const result = await client.send("Network.getCookies", { urls });
  const cookies = Array.isArray(result.cookies) ? result.cookies : [];
  const seen = new Set();
  return cookies.filter((cookie) => {
    const key = `${cookie.domain}\0${cookie.path}\0${cookie.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return (
      cookieDomainMatchesHost(cookie.domain, hostname) ||
      (admin && cookieDomainMatchesHost(cookie.domain, admin))
    );
  });
}

function cdpSameSiteToCookieEditor(value) {
  if (value === "None") return "no_restriction";
  if (value === "Lax") return "lax";
  if (value === "Strict") return "strict";
  return "lax";
}

export async function redactedCookieInventory(client, orgUrl, suppliedCookies) {
  const cookies = suppliedCookies || await matchingBrowserCookies(client, orgUrl);
  return cookies
    .map((cookie) => {
      const domain = String(cookie.domain || "");
      const isSession = cookie.session === true;
      const sameSite = cdpSameSiteToCookieEditor(cookie.sameSite);
      const entry = { domain };
      if (!isSession && Number.isFinite(cookie.expires) && cookie.expires > 0) {
        entry.expirationDate = cookie.expires;
      }
      entry.hostOnly = !domain.startsWith(".");
      entry.httpOnly = cookie.httpOnly === true;
      entry.name = String(cookie.name || "");
      entry.path = String(cookie.path || "/");
      entry.sameSite = sameSite;
      entry.secure = cookie.secure === true;
      entry.session = isSession;
      entry.storeId = null;
      entry.value = String(cookie.value || "");
      return entry;
    })
    .sort((left, right) =>
      `${left.domain}\0${left.path}\0${left.name}`.localeCompare(
        `${right.domain}\0${right.path}\0${right.name}`
      )
    );
}

export async function postProof(
  endpoint,
  _orgUrl,
  _probe,
  cookies,
  _options = {}
) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(cookies),
    redirect: "error",
  });
  const body = await response.json();
  if (!response.ok) {
    throw new Error(`Collector rejected the proof: ${JSON.stringify(body)}`);
  }
  return body;
}

async function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log(`Usage: node scripts/lab-browser-session-proof.mjs [options]

Options:
  --org-url URL          Authorized test Okta HTTPS origin (prompted if omitted)
  --endpoint URL         Loopback collector endpoint (default: ${DEFAULT_ENDPOINT})
  --timeout-seconds N    Authentication timeout from 30 to 900 (default: 300)
  -h, --help             Show this help

The operator must type the exact tenant hostname before the isolated browser opens.
Cookie objects are exported as valid JSON with every value set to [REDACTED].
Raw cookie values and OAuth tokens are never posted or persisted.`);
    return;
  }
  if (typeof WebSocket !== "function") {
    throw new Error(
      "The standalone browser lab requires Node.js 22 or newer; the production MCP still supports Node.js 20."
    );
  }

  const endpoint = validateEndpoint(option("endpoint") || DEFAULT_ENDPOINT);
  const timeoutMs = validateTimeout(option("timeout-seconds"));
  const confirmedHost = option("confirm-host");
  const readline = confirmedHost
    ? null
    : createInterface({ input: process.stdin, output: process.stdout });
  let orgUrl;
  try {
    const supplied = option("org-url");
    if (!supplied && !readline) {
      throw new Error("--org-url is required with non-interactive confirmation.");
    }
    const answer = supplied
      ? supplied
      : await readline.question(
          "Authorized test Okta organization URL (for example https://example.okta.com): "
        );
    orgUrl = validateOrgUrl(answer);

    console.log("\nAUTHORIZED LAB ONLY");
    console.log(`Organization: ${orgUrl}`);
    console.log(`Collector: ${endpoint}`);
    console.log(
      "The browser will use a temporary profile and validate /api/v1/users/me inside that browser."
    );
    console.log(
      "Cookie objects will be exported with every value replaced by [REDACTED]."
    );
    const confirmation = confirmedHost
      ? confirmedHost
      : await readline.question(
          `Type the exact hostname "${new URL(orgUrl).host}" to confirm authorization: `
        );
    if (confirmation.trim().toLowerCase() !== new URL(orgUrl).host.toLowerCase()) {
      throw new Error("Lab authorization was not confirmed.");
    }
  } finally {
    readline?.close();
  }

  const collector = await ensureCollector(endpoint);
  if (collector.started) {
    console.log(`Started redacted collector (PID ${collector.pid}).`);
  } else {
    console.log("Reusing the active redacted collector.");
  }

  const browserPath = findBrowser();
  const debugPort = await freePort();
  const profileDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "okta-mcp-authorized-lab-")
  );
  const browser = spawn(
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

  let cdp;
  try {
    const target = await waitForTarget(debugPort, orgUrl);
    cdp = new CdpClient(target.webSocketDebuggerUrl);
    await cdp.ready;
    await cdp.send("Network.enable");
    console.log(
      `Complete authentication in the isolated browser. Waiting up to ${Math.round(
        timeoutMs / 1000
      )} seconds...`
    );

    const deadline = Date.now() + timeoutMs;
    let probe;
    while (Date.now() < deadline) {
      try {
        probe = await browserSessionProbe(cdp);
        if (probe?.ok && probe.status === 200 && isOrgOrigin(probe.origin, orgUrl)) break;
      } catch {
        // Navigation can replace the current JavaScript execution context.
      }
      await delay(POLL_INTERVAL_MS);
    }
    if (!probe?.ok || probe.status !== 200 || !isOrgOrigin(probe.origin, orgUrl)) {
      throw new Error(
        "Timed out before the isolated browser produced an authenticated same-origin session proof."
      );
    }

    // Allow admin redirect to complete and admin-domain cookies to set
    await delay(5000);
    try {
      const settled = await browserSessionProbe(cdp);
      if (settled?.ok && settled.status === 200 && isOrgOrigin(settled.origin, orgUrl)) {
        probe = settled;
      }
    } catch {
      // Navigation may temporarily break the execution context during redirect
    }

    const cookies = await redactedCookieInventory(cdp, orgUrl);
    const posted = await postProof(endpoint, orgUrl, probe, cookies);
    console.log("Authenticated browser session validated.");
    console.log(`Redacted cookie objects exported: ${cookies.length}`);
    console.log(`Validated user: ${probe.user_login || probe.user_id || "unknown"}`);
    console.log(`Proof endpoint: ${endpoint}`);
    console.log(`Dashboard: ${new URL("/", endpoint)}`);
    console.log(`Older records deleted: ${posted.deleted_old_count}`);
    console.log(`Retained records: ${posted.retained_count}`);
  } finally {
    cdp?.close();
    stopBrowser(browser);
    await delay(500);
    try {
      fs.rmSync(profileDir, { recursive: true, force: true });
    } catch {
      console.error(
        `Warning: the temporary browser profile could not be removed immediately: ${profileDir}`
      );
    }
  }
}

const invokedDirectly = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  try {
    await main();
  } catch (error) {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
