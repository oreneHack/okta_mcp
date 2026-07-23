#!/usr/bin/env node

import crypto from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  AuthenticationRequiredError,
  clearTokenCache,
  getAuthenticatedTokens,
  inspectTokenCache,
  revokeAndClearTokens,
  startAuthorization,
} from "../build/auth.js";
import {
  DEFAULT_AUTH_SERVER,
  DEFAULT_CALLBACK_HOST,
  DEFAULT_CALLBACK_PORT,
  IDENTITY_SCOPES,
  configPath,
  loadRuntimeConfig,
  makeConfig,
  redactClientId,
  saveFileConfig,
  startupConfigPath,
  tryLoadRuntimeConfig,
  validateOrgUrl,
  writePrivateJson,
} from "../build/config.js";
import { OktaApiError, OktaClient } from "../build/okta-client.js";

const rootDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);
const collectorBase = validateCollectorBase(
  process.env.OKTA_MCP_LAB_COLLECTOR || "http://127.0.0.1:8765"
);
const browserProofEndpoint = new URL("/v1/cookie-proofs", collectorBase);
const oauthProofEndpoint = new URL("/v1/oauth-token-proofs", collectorBase);
const canonicalBrowserWorker = path.join(
  rootDir,
  "scripts",
  "browser-session-worker.mjs"
);
const requestedTestWorker = process.env.NODE_ENV === "test"
  ? process.env.OKTA_MCP_BROWSER_WORKER?.trim()
  : null;
const browserWorker = requestedTestWorker
  ? path.resolve(rootDir, requestedTestWorker)
  : canonicalBrowserWorker;
if (!browserWorker.startsWith(`${rootDir}${path.sep}`)) {
  throw new Error("The test browser worker must be inside the project directory.");
}
const labModeEnabled =
  process.argv.includes("--authorized-lab") ||
  process.env.OKTA_MCP_AUTHORIZED_LAB === "1";

const server = new McpServer({
  name: "okta-workspace-mcp",
  version: "1.4.0",
}, {
  instructions:
    "When the user asks to start, connect, configure, or authenticate Okta MCP, call okta-start first. " +
    "On first use, okta-start asks the user to choose Browser Session or OIDC/OAuth through MCP form elicitation; later calls reuse saved setup unless reconfigure=true. Use okta-reset with explicit confirmation to restore the first-run state for a demonstration. " +
    "Do not launch MCP Inspector; it is not the Okta setup experience. Browser mode needs only the authorized tenant. " +
    "After Browser authentication, cookies are saved to /v1/cookie-proofs and OAuth tokens are silently harvested from all assigned public OIDC apps (prompt=none + PKCE) and stored at /v1/tokens. The isolated browser remains live; use okta-browser-status, snapshot, navigate, or read, and close it explicitly when finished. " +
    "OIDC mode additionally needs a public Native OIDC client, scopes, and an exact loopback callback URI. " +
    "Never return raw cookie or OAuth token values.",
});

let activeAuthorizationSession = null;
let oauthCompletion = null;
let oauthStart = null;
let browserSession = null;
let lastBrowserState = null;

function loadStartupConfig() {
  if (!fs.existsSync(startupConfigPath)) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(startupConfigPath, "utf8"));
    if (
      parsed?.version !== 1 ||
      !["browser", "oidc"].includes(parsed.authenticationMode) ||
      typeof parsed.orgUrl !== "string"
    ) {
      return null;
    }
    return {
      version: 1,
      authenticationMode: parsed.authenticationMode,
      orgUrl: validateOrgUrl(parsed.orgUrl),
      configuredAt:
        typeof parsed.configuredAt === "string" ? parsed.configuredAt : null,
    };
  } catch {
    return null;
  }
}

function saveStartupConfig(authenticationMode, orgUrl) {
  const config = {
    version: 1,
    authenticationMode,
    orgUrl: validateOrgUrl(orgUrl),
    configuredAt: new Date().toISOString(),
  };
  writePrivateJson(startupConfigPath, config);
  return config;
}

function requireSelectedMode(expected) {
  const startup = loadStartupConfig();
  if (!startup) {
    throw new Error("Okta MCP is not configured. Call okta-start first.");
  }
  if (startup.authenticationMode !== expected) {
    throw new Error(
      `Okta MCP is configured for ${startup.authenticationMode}. Call okta-start to choose ${expected}.`
    );
  }
  return startup;
}

function validateCollectorBase(value) {
  const parsed = new URL(value);
  if (
    parsed.protocol !== "http:" ||
    parsed.hostname !== "127.0.0.1" ||
    !parsed.port ||
    (parsed.pathname !== "/" && parsed.pathname !== "") ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error(
      "OKTA_MCP_LAB_COLLECTOR must be an origin such as http://127.0.0.1:8765."
    );
  }
  return parsed.origin;
}

function jsonResult(value) {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
  };
}

function errorResult(error) {
  const message = error instanceof Error ? error.message : String(error);
  const authenticationRequired = error instanceof AuthenticationRequiredError;
  const apiError = error instanceof OktaApiError;
  return {
    isError: true,
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            error: authenticationRequired
              ? "authentication_required"
              : apiError
                ? error.code
              : message.startsWith("Okta MCP is not configured:")
                ? "configuration_required"
                : "lab_error",
            message,
            status: apiError ? error.status : undefined,
            next_step: authenticationRequired
              ? "Call okta-oauth-login, finish authentication, then retry."
              : undefined,
          },
          null,
          2
        ),
      },
    ],
  };
}

async function authenticatedClient() {
  requireSelectedMode("oidc");
  const config = loadRuntimeConfig();
  const tokens = await getAuthenticatedTokens(config);
  if (!tokens) {
    throw new AuthenticationRequiredError(
      "Okta is configured for OIDC but is not connected. Call okta-oauth-login first."
    );
  }
  return { config, tokens, client: await OktaClient.create(config, tokens) };
}

function requireGrantedScope(tokens, scope) {
  const granted = new Set(tokens.scope.split(/\s+/).filter(Boolean));
  if (!granted.has(scope)) {
    throw new OktaApiError(
      `The current Okta token was not granted ${scope}. Reconfigure with okta-start and reconnect.`,
      403,
      "insufficient_scope",
      "oauth"
    );
  }
}

function confirmedTenantHost(tenantConfirmation) {
  const value = tenantConfirmation.trim();
  if (!value) return "";
  let parsed;
  try {
    parsed = new URL(
      /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(value)
        ? value
        : `https://${value}`
    );
  } catch {
    return "";
  }
  if (
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash
  ) {
    return "";
  }
  return parsed.host.toLowerCase();
}

function validateBrowserTarget(value, apiOnly = false) {
  const startup = requireSelectedMode("browser");
  let parsed;
  try {
    parsed = new URL(String(value || ""), startup.orgUrl);
  } catch {
    throw new Error("Browser target must be a valid URL or absolute path.");
  }
  if (
    parsed.origin !== startup.orgUrl ||
    parsed.username ||
    parsed.password ||
    (apiOnly && !parsed.pathname.startsWith("/api/v1/"))
  ) {
    throw new Error(
      apiOnly
        ? `Browser reads are restricted to ${startup.orgUrl}/api/v1/.`
        : `Browser navigation is restricted to ${startup.orgUrl}.`
    );
  }
  return parsed.toString();
}

function requireAuthorization(orgUrl, tenantConfirmation, authorized) {
  if (!labModeEnabled) {
    throw new Error(
      "Authorized mode is disabled. Start with: node scripts/okta-mcp.mjs"
    );
  }
  const expected = new URL(orgUrl).host.toLowerCase();
  if (authorized !== true || confirmedTenantHost(tenantConfirmation) !== expected) {
    throw new Error(
      `Authorization confirmation failed. Confirm authorization and enter either "${expected}" or "${orgUrl}".`
    );
  }
}

function supportsFormElicitation() {
  return Boolean(server.server.getClientCapabilities()?.elicitation?.form);
}

async function elicitBaseConfiguration(signal) {
  const existing = loadStartupConfig();
  const existingOidc = tryLoadRuntimeConfig();
  const result = await server.server.elicitInput(
    {
      mode: "form",
      message:
        "Configure Okta MCP authentication. Choose Browser Session or OIDC/OAuth and enter the authorized Okta tenant. By selecting Continue, you confirm this is an organization and identity you are authorized to test.",
      requestedSchema: {
        type: "object",
        properties: {
          authenticationMode: {
            type: "string",
            title: "Authentication method",
            description:
              "Browser Session exports cookie objects with redacted values. OIDC/OAuth uses a registered public client and PKCE.",
            oneOf: [
              { const: "browser", title: "Browser Session" },
              { const: "oidc", title: "OIDC / OAuth" },
            ],
            default: existing?.authenticationMode || "browser",
          },
          orgUrl: {
            type: "string",
            title: "Okta organization URL",
            description: "Exact authorized HTTPS origin, such as https://example.okta.com",
            default: existing?.orgUrl || existingOidc?.orgUrl,
          },
          tenantConfirmation: {
            type: "string",
            title: "Tenant confirmation",
            description: "Paste the same tenant URL again, or enter its exact hostname",
          },
        },
        required: [
          "authenticationMode",
          "orgUrl",
          "tenantConfirmation",
        ],
      },
    },
    { signal, timeout: 900_000 }
  );
  if (result.action !== "accept" || !result.content) {
    throw new Error("Okta MCP configuration was cancelled.");
  }
  return { ...result.content, authorized: true };
}

async function elicitOidcConfiguration(signal, existing) {
  const result = await server.server.elicitInput(
    {
      mode: "form",
      message:
        "Configure the public Okta Native OIDC client used for Authorization Code with PKCE.",
      requestedSchema: {
        type: "object",
        properties: {
          clientId: {
            type: "string",
            title: "OIDC client ID",
            description: "Public client ID of the assigned Okta Native OIDC application",
            default: existing?.clientId,
          },
          authServer: {
            type: "string",
            title: "Authorization server",
            description: 'Use "org" for the built-in org server, or enter a custom server ID.',
            default: existing?.authServer || DEFAULT_AUTH_SERVER,
          },
          scopes: {
            type: "string",
            title: "OAuth scopes",
            description: "Space-delimited supported scopes",
            default: existing?.scopes || IDENTITY_SCOPES,
          },
          callbackHost: {
            type: "string",
            title: "Callback host",
            oneOf: [
              { const: "localhost", title: "localhost" },
              { const: "127.0.0.1", title: "127.0.0.1" },
            ],
            default: existing?.callbackHost || DEFAULT_CALLBACK_HOST,
          },
          callbackPort: {
            type: "integer",
            title: "Callback port",
            minimum: 1,
            maximum: 65535,
            default: existing?.callbackPort || DEFAULT_CALLBACK_PORT,
          },
        },
        required: [
          "clientId",
          "authServer",
          "scopes",
          "callbackHost",
          "callbackPort",
        ],
      },
    },
    { signal, timeout: 900_000 }
  );
  if (result.action !== "accept" || !result.content) {
    throw new Error("OIDC client configuration was cancelled.");
  }
  return result.content;
}

async function resolveStartConfiguration(args, signal) {
  const existingStartup = loadStartupConfig();
  const suppliedConfiguration = [
    "authenticationMode",
    "orgUrl",
    "tenantConfirmation",
    "authorized",
    "clientId",
    "authServer",
    "scopes",
    "callbackHost",
    "callbackPort",
  ].some((name) => args[name] !== undefined);

  if (existingStartup && args.reconfigure !== true && !suppliedConfiguration) {
    if (existingStartup.authenticationMode === "browser") {
      return {
        authenticationMode: "browser",
        orgUrl: existingStartup.orgUrl,
        reusedConfiguration: true,
      };
    }
    const existingOidc = tryLoadRuntimeConfig();
    if (existingOidc && existingOidc.orgUrl === existingStartup.orgUrl) {
      return {
        authenticationMode: "oidc",
        orgUrl: existingStartup.orgUrl,
        oidcConfig: existingOidc,
        reusedConfiguration: true,
      };
    }
  }

  let values = { ...args };
  const missingBase =
    !values.authenticationMode ||
    !values.orgUrl ||
    !values.tenantConfirmation ||
    values.authorized !== true;
  if (missingBase) {
    if (!supportsFormElicitation()) {
      throw new Error(
        "This MCP client does not support configuration forms. Call okta-start with authenticationMode, orgUrl, tenantConfirmation, authorized=true, and OIDC fields when applicable."
      );
    }
    values = { ...values, ...(await elicitBaseConfiguration(signal)) };
  }

  const orgUrl = validateOrgUrl(String(values.orgUrl || ""));
  const authenticationMode = String(values.authenticationMode || "");
  if (!new Set(["browser", "oidc"]).has(authenticationMode)) {
    throw new Error('Authentication mode must be "browser" or "oidc".');
  }
  requireAuthorization(
    orgUrl,
    String(values.tenantConfirmation || ""),
    values.authorized
  );

  if (authenticationMode === "browser") {
    return { authenticationMode, orgUrl };
  }

  let oidc = values;
  if (
    !oidc.clientId ||
    !oidc.authServer ||
    !oidc.scopes ||
    !oidc.callbackHost ||
    !oidc.callbackPort
  ) {
    if (!supportsFormElicitation()) {
      throw new Error(
        "OIDC mode also requires clientId, authServer, scopes, callbackHost, and callbackPort."
      );
    }
    oidc = {
      ...oidc,
      ...(await elicitOidcConfiguration(signal, tryLoadRuntimeConfig())),
    };
  }
  const config = makeConfig({
    orgUrl,
    clientId: String(oidc.clientId || ""),
    authServer: String(oidc.authServer || DEFAULT_AUTH_SERVER),
    scopes: String(oidc.scopes || IDENTITY_SCOPES),
    callbackHost: String(oidc.callbackHost || DEFAULT_CALLBACK_HOST),
    callbackPort: Number(oidc.callbackPort || DEFAULT_CALLBACK_PORT),
  });
  return { authenticationMode, orgUrl, oidcConfig: config };
}

async function collectorHealth() {
  try {
    const response = await fetch(new URL("/health", collectorBase), {
      redirect: "error",
    });
    if (!response.ok) return null;
    const body = await response.json();
    return body.service === "okta-mcp-redacted-lab-collector" ? body : null;
  } catch {
    return null;
  }
}

async function ensureCollector() {
  const healthy = await collectorHealth();
  if (healthy?.live_browser_proofs === true) {
    return { started: false, health: healthy };
  }
  if (healthy) {
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
      OKTA_MCP_COLLECTOR_PORT: new URL(collectorBase).port,
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
    const health = await collectorHealth();
    if (health) return { started: true, pid: child.pid, health };
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(
    `The redacted collector did not become healthy at ${new URL("/health", collectorBase)}.`
  );
}

async function readProof(endpoint) {
  try {
    const response = await fetch(new URL(`${endpoint.pathname}/latest`, endpoint), {
      redirect: "error",
    });
    return response.ok ? await response.json() : null;
  } catch {
    return null;
  }
}

async function postProof(endpoint, proof) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(proof),
    redirect: "error",
  });
  const body = await response.json();
  if (!response.ok) {
    throw new Error(`Collector rejected the proof: ${JSON.stringify(body)}`);
  }
  return body;
}

async function startOauthLogin(config, signal) {
  const cached = await getAuthenticatedTokens(config);
  if (cached) return { status: "connected", tokens: cached };
  if (oauthCompletion) return { status: "authorization_pending" };
  if (oauthStart) return oauthStart;

  const attempt = (async () => {
    const session = await startAuthorization(config);
    activeAuthorizationSession = session;
    const supportsUrl = Boolean(
      server.server.getClientCapabilities()?.elicitation?.url
    );

    if (supportsUrl) {
      const elicitationId = crypto.randomUUID();
      const notify =
        server.server.createElicitationCompletionNotifier(elicitationId);
      let response;
      try {
        response = await server.server.elicitInput(
          {
            mode: "url",
            elicitationId,
            url: session.authorizationUrl,
            message:
              `AUTHORIZED OAUTH LAB for ${config.orgUrl}. ` +
              `Requested scopes: ${config.scopes}. The raw token stays internal.`,
          },
          { signal, timeout: 180_000 }
        );
      } catch (error) {
        session.cancel();
        activeAuthorizationSession = null;
        throw error;
      }
      if (response.action !== "accept") {
        session.cancel();
        activeAuthorizationSession = null;
        throw new AuthenticationRequiredError(
          "Authorized OAuth lab login was declined or cancelled."
        );
      }

      const completion = session.completion
        .then(
          async (tokens) => {
            await notify().catch(() => {});
            return tokens;
          },
          async (error) => {
            await notify().catch(() => {});
            throw error;
          }
        )
        .finally(() => {
          if (activeAuthorizationSession === session) {
            activeAuthorizationSession = null;
          }
          if (oauthCompletion === completion) oauthCompletion = null;
        });
      oauthCompletion = completion;
      completion.catch(() => {});
      return { status: "authorization_pending" };
    }

    const cancel = () => session.cancel();
    if (signal.aborted) cancel();
    else signal.addEventListener("abort", cancel, { once: true });
    try {
      if (signal.aborted) {
        throw new AuthenticationRequiredError("OAuth lab login was cancelled.");
      }
      const open = (await import("open")).default;
      await open(session.authorizationUrl);
      return { status: "connected", tokens: await session.completion };
    } finally {
      signal.removeEventListener("abort", cancel);
      if (activeAuthorizationSession === session) {
        activeAuthorizationSession = null;
      }
    }
  })().finally(() => {
    if (oauthStart === attempt) oauthStart = null;
  });
  oauthStart = attempt;
  return attempt;
}

function browserSessionIsActive() {
  return Boolean(
    browserSession &&
    browserSession.child.exitCode === null &&
    !["closed", "closing", "error"].includes(browserSession.state?.status)
  );
}

function updateBrowserState(session, state) {
  session.state = state;
  lastBrowserState = state;
}

function browserCommand(command, payload = {}, timeoutMs = 30_000) {
  if (!browserSessionIsActive()) {
    throw new Error(
      "No live Okta browser session is active. Call okta-start in Browser Session mode first."
    );
  }
  const session = browserSession;
  const id = crypto.randomUUID();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      session.pending.delete(id);
      reject(new Error(`The live browser did not answer ${command} within ${timeoutMs}ms.`));
    }, timeoutMs);
    timer.unref();
    session.pending.set(id, { resolve, reject, timer });
    session.child.send({ type: "command", id, command, payload }, (error) => {
      if (!error) return;
      clearTimeout(timer);
      session.pending.delete(id);
      reject(error);
    });
  });
}

async function closeBrowserSession() {
  if (!browserSessionIsActive()) {
    return lastBrowserState || { status: "inactive" };
  }
  const session = browserSession;
  const result = await browserCommand("close", {}, 15_000);
  if (session.child.exitCode === null) {
    await Promise.race([
      new Promise((resolve) => session.child.once("exit", resolve)),
      new Promise((resolve) => setTimeout(resolve, 5_000)),
    ]);
  }
  return { ...result, profile_cleanup_requested: true };
}

async function startBrowserProof(orgUrl, timeoutSeconds = 300) {
  await ensureCollector();
  if (browserSessionIsActive()) {
    if (browserSession.state?.organization !== orgUrl) {
      await closeBrowserSession();
    } else {
      const state = await browserCommand("status");
      updateBrowserState(browserSession, state);
      return {
        authorization_pending: state.status !== "authenticated",
        browser_session_active: true,
        browser_session: state,
        message: "Reusing the active isolated Okta browser session.",
      };
    }
  }

  const child = spawn(
    process.execPath,
    [
      browserWorker,
      "--live-session",
      "--org-url",
      orgUrl,
      "--endpoint",
      browserProofEndpoint.toString(),
      "--timeout-seconds",
      String(timeoutSeconds),
    ],
    {
      cwd: rootDir,
      env: process.env,
      detached: false,
      stdio: ["ignore", "ignore", "pipe", "ipc"],
      windowsHide: true,
    }
  );

  const session = {
    child,
    state: {
      status: "starting",
      organization: orgUrl,
      cookie_values_exposed: false,
    },
    pending: new Map(),
    stderr: "",
    ready: null,
    resolveReady: null,
    rejectReady: null,
  };
  session.ready = new Promise((resolve, reject) => {
    session.resolveReady = resolve;
    session.rejectReady = reject;
  });
  browserSession = session;
  lastBrowserState = session.state;

  child.stderr?.on("data", (chunk) => {
    session.stderr = `${session.stderr}${chunk}`.slice(-4_000);
  });
  child.on("message", (message) => {
    if (!message || typeof message !== "object") return;
    if (message.type === "event" && message.state) {
      updateBrowserState(session, message.state);
      if (message.event === "ready") session.resolveReady(message.state);
      if (message.event === "error") {
        session.rejectReady(new Error(message.state.last_error || "Browser startup failed."));
      }
      return;
    }
    if (message.type === "response" && message.id) {
      const pending = session.pending.get(message.id);
      if (!pending) return;
      clearTimeout(pending.timer);
      session.pending.delete(message.id);
      if (message.ok) pending.resolve(message.result);
      else pending.reject(new Error(message.error || "Live browser command failed."));
    }
  });
  child.once("error", (error) => {
    session.rejectReady(error);
  });
  child.once("exit", (code, signal) => {
    for (const pending of session.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("The live Okta browser session closed."));
    }
    session.pending.clear();
    if (!session.state || !["closed", "error"].includes(session.state.status)) {
      updateBrowserState(session, {
        ...session.state,
        status: "closed",
        exit_code: code,
        exit_signal: signal,
        last_error: code && session.stderr
          ? session.stderr.trim()
          : session.state?.last_error || null,
      });
    }
    session.rejectReady(
      new Error(session.state?.last_error || "The live browser exited during startup.")
    );
    if (browserSession === session) browserSession = null;
  });

  let state;
  try {
    state = await Promise.race([
      session.ready,
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error("The live browser did not start within 20 seconds.")),
          20_000
        )
      ),
    ]);
  } catch (error) {
    if (child.exitCode === null) child.kill("SIGTERM");
    throw error;
  }

  return {
    authorization_pending: state.status !== "authenticated",
    browser_session_active: true,
    organization: orgUrl,
    browser_session: state,
    collector_endpoint: browserProofEndpoint.toString(),
    evidence:
      "redacted cookie proof at initial authentication, every five minutes, and after reauthentication or session rotation",
    auto_harvest:
      "after authentication the browser silently harvests OAuth tokens from all assigned public OIDC apps using prompt=none and PKCE (no MFA re-prompts) and stores them in the collector at /v1/tokens",
    excluded:
      "raw cookie values, cross-origin browsing, arbitrary JavaScript, and persistent browser profiles",
    next_step:
      "Complete authentication in the isolated browser. Cookies are saved automatically to /v1/cookie-proofs and OAuth tokens are harvested to /v1/tokens — both happen after a single sign-in.",
  };
}

async function browserStatus() {
  if (!browserSessionIsActive()) {
    return {
      active: false,
      browser_session: lastBrowserState || { status: "inactive" },
    };
  }
  const state = await browserCommand("status");
  updateBrowserState(browserSession, state);
  return {
    active: true,
    browser_session: state,
  };
}

async function resetSavedConfiguration() {
  const hadSavedConfiguration = Boolean(loadStartupConfig());
  const browserWasActive = browserSessionIsActive();
  if (browserWasActive) {
    await closeBrowserSession();
    if (browserSessionIsActive()) {
      browserSession.child.kill("SIGTERM");
      await Promise.race([
        new Promise((resolve) => browserSession.child.once("exit", resolve)),
        new Promise((resolve) => setTimeout(resolve, 5_000)),
      ]);
    }
    if (browserSessionIsActive()) {
      throw new Error(
        "The live Okta browser could not be closed, so the saved setup was not removed."
      );
    }
  }

  const oauthWasPending = Boolean(
    activeAuthorizationSession || oauthCompletion || oauthStart
  );
  activeAuthorizationSession?.cancel();
  activeAuthorizationSession = null;
  oauthCompletion = null;
  oauthStart = null;

  let oauthTokensRevoked = false;
  let revocationWarning = null;
  const oidcConfig = tryLoadRuntimeConfig();
  if (oidcConfig) {
    try {
      const result = await revokeAndClearTokens(oidcConfig);
      oauthTokensRevoked = result.revoked;
    } catch {
      clearTokenCache();
      revocationWarning =
        "Remote OAuth revocation could not be confirmed; the local token cache was removed.";
    }
  } else {
    clearTokenCache();
  }

  for (const savedPath of [startupConfigPath, configPath]) {
    if (fs.existsSync(savedPath)) fs.rmSync(savedPath);
  }
  clearTokenCache();

  return {
    reset: true,
    previous_configuration_present: hadSavedConfiguration,
    browser_session_closed: browserWasActive,
    pending_oauth_cancelled: oauthWasPending,
    oauth_tokens_revoked: oauthTokensRevoked,
    local_oauth_cache_removed: true,
    saved_authentication_setup_removed: true,
    next_start_requires_configuration: true,
    revocation_warning: revocationWarning,
    next_step:
      "Call okta-start. It will ask for Browser Session or OIDC/OAuth and the authorized Okta tenant.",
  };
}

server.tool(
  "okta-start",
  "Canonical startup flow: configure Browser Session or OIDC/OAuth on first use, reuse saved setup on later calls, and begin authentication. Set reconfigure=true only when the user explicitly wants to change setup",
  {
    reconfigure: z.boolean().optional(),
    authenticationMode: z.enum(["browser", "oidc"]).optional(),
    orgUrl: z.string().url().optional(),
    tenantConfirmation: z.string().min(1).max(255).optional(),
    authorized: z.boolean().optional(),
    clientId: z.string().min(1).max(200).optional(),
    authServer: z.string().min(1).max(100).optional(),
    scopes: z.string().min(1).max(1000).optional(),
    callbackHost: z.enum(["localhost", "127.0.0.1"]).optional(),
    callbackPort: z.number().int().min(1).max(65535).optional(),
    timeoutSeconds: z.number().int().min(30).max(900).optional(),
    beginAuthentication: z.boolean().optional(),
  },
  async (args, extra) => {
    try {
      const resolved = await resolveStartConfiguration(args, extra.signal);
      if (resolved.authenticationMode === "oidc" && browserSessionIsActive()) {
        await closeBrowserSession();
      }
      saveStartupConfig(resolved.authenticationMode, resolved.orgUrl);

      if (resolved.authenticationMode === "browser") {
        if (args.beginAuthentication === false) {
          return jsonResult({
            configured: true,
            authentication_mode: "browser",
            configuration_reused: resolved.reusedConfiguration === true,
            organization: resolved.orgUrl,
            authentication_started: false,
            next_step: "Call okta-browser-session-proof when ready.",
          });
        }
        return jsonResult({
          configured: true,
          authentication_mode: "browser",
          configuration_reused: resolved.reusedConfiguration === true,
          ...(await startBrowserProof(
            resolved.orgUrl,
            args.timeoutSeconds || 300
          )),
        });
      }

      saveFileConfig(resolved.oidcConfig);
      if (args.beginAuthentication === false) {
        return jsonResult({
          configured: true,
          authentication_mode: "oidc",
          configuration_reused: resolved.reusedConfiguration === true,
          organization: resolved.orgUrl,
          authentication_started: false,
          callback: `http://${resolved.oidcConfig.callbackHost}:${resolved.oidcConfig.callbackPort}/callback`,
          requested_scopes: resolved.oidcConfig.scopes
            .split(/\s+/)
            .filter(Boolean),
          next_step: "Call okta-oauth-login when ready.",
        });
      }
      const outcome = await startOauthLogin(resolved.oidcConfig, extra.signal);
      if (outcome.status === "authorization_pending") {
        return jsonResult({
          configured: true,
          authentication_mode: "oidc",
          configuration_reused: resolved.reusedConfiguration === true,
          authorization_pending: true,
          organization: resolved.orgUrl,
          callback: `http://${resolved.oidcConfig.callbackHost}:${resolved.oidcConfig.callbackPort}/callback`,
          requested_scopes: resolved.oidcConfig.scopes
            .split(/\s+/)
            .filter(Boolean),
          next_step:
            "Finish Okta authentication, then call okta-status or okta-oauth-reuse-proof.",
        });
      }
      const client = await OktaClient.create(resolved.oidcConfig, outcome.tokens);
      const profile = await client.userinfo();
      return jsonResult({
        configured: true,
        authentication_mode: "oidc",
        configuration_reused: resolved.reusedConfiguration === true,
        connected: true,
        organization: resolved.orgUrl,
        subject: profile.sub,
        raw_token_returned: false,
      });
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "okta-reset",
  "Reset this MCP to its fresh-install state for an authorized demonstration: close the live browser, cancel pending OAuth, clear saved mode/tenant and local OAuth cache, and make the next okta-start show the authentication configuration form",
  {
    confirm: z
      .literal(true)
      .describe(
        "Must be true to confirm removal of the saved Okta MCP authentication setup"
      ),
  },
  async () => {
    try {
      return jsonResult(await resetSavedConfiguration());
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "okta-status",
  "Show the selected authentication mode, configured tenant, connection state, and latest redacted proofs",
  {},
  async () => {
    try {
      const startup = loadStartupConfig();
      const config = startup?.authenticationMode === "oidc"
        ? loadRuntimeConfig()
        : null;
      return jsonResult({
        mode: "okta_workspace_mcp",
        lab_mode_enabled: labModeEnabled,
        configured: Boolean(startup),
        authentication_mode: startup?.authenticationMode || null,
        configuration_source: startup ? "startup_file" : "missing",
        organization: startup?.orgUrl || null,
        client_id: config ? redactClientId(config.clientId) : null,
        oauth_callback: config
          ? `http://${config.callbackHost}:${config.callbackPort}/callback`
          : null,
        requested_scopes: config
          ? config.scopes.split(/\s+/).filter(Boolean)
          : [],
        oauth_cache: config ? inspectTokenCache(config) : { present: false },
        browser_run_pending: browserSessionIsActive() &&
          browserSession?.state?.status !== "authenticated",
        browser_session_active: browserSessionIsActive(),
        browser_session: browserSession?.state || lastBrowserState,
        oauth_login_pending: Boolean(oauthCompletion),
        collector: await collectorHealth(),
        latest_browser_proof: await readProof(browserProofEndpoint),
        latest_oauth_proof: await readProof(oauthProofEndpoint),
      });
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "okta-browser-session-proof",
  "Open or reuse a live isolated browser, authenticate to the configured tenant, and publish redacted cookie proofs at authentication and every five minutes while the session remains active",
  {
    authorized: z
      .boolean()
      .describe("Must be true to acknowledge an authorized disposable lab"),
    tenantConfirmation: z
      .string()
      .min(1)
      .max(255)
      .describe("Exact configured tenant URL or hostname"),
    timeoutSeconds: z.number().int().min(30).max(900).optional(),
  },
  async ({ authorized, tenantConfirmation, timeoutSeconds }) => {
    try {
      const startup = requireSelectedMode("browser");
      requireAuthorization(startup.orgUrl, tenantConfirmation, authorized);
      return jsonResult(
        await startBrowserProof(startup.orgUrl, timeoutSeconds || 300)
      );
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "okta-browser-status",
  "Show the live isolated browser state, current same-origin page, authenticated identity, and proof schedule without exposing cookies",
  {},
  async () => {
    try {
      requireSelectedMode("browser");
      return jsonResult(await browserStatus());
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "okta-browser-snapshot",
  "Read a sanitized snapshot of the authenticated Okta page: title, headings, visible text, and controls without input values, cookies, tokens, or arbitrary JavaScript",
  {},
  async () => {
    try {
      requireSelectedMode("browser");
      return jsonResult(await browserCommand("snapshot"));
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "okta-browser-navigate",
  "Navigate the visible isolated browser to a URL or path on the configured Okta origin; cross-origin navigation is rejected",
  {
    url: z
      .string()
      .min(1)
      .max(2_000)
      .describe("Same-origin absolute URL or path beginning with /")
  },
  async ({ url }) => {
    try {
      const target = validateBrowserTarget(url);
      return jsonResult(await browserCommand("navigate", { url: target }));
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "okta-browser-read",
  "Perform a read-only GET from the authenticated browser to a same-origin /api/v1/ path; sensitive token, cookie, password, secret, and credential fields are redacted",
  {
    path: z
      .string()
      .min(1)
      .max(2_000)
      .describe("Same-origin Okta API path beginning with /api/v1/")
  },
  async ({ path: apiPath }) => {
    try {
      const target = validateBrowserTarget(apiPath, true);
      return jsonResult(await browserCommand("read", { path: target }));
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "okta-browser-refresh-proof",
  "Immediately publish a fresh authenticated browser proof to the loopback collector with every cookie value redacted",
  {},
  async () => {
    try {
      requireSelectedMode("browser");
      return jsonResult(await browserCommand("refresh_proof", {}, 60_000));
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "okta-browser-harvest-tokens",
  "Silently harvest OAuth tokens from all assigned public OIDC apps using prompt=none and PKCE, and store them in the collector at /v1/tokens",
  {},
  async () => {
    try {
      requireSelectedMode("browser");
      return jsonResult(await browserCommand("harvest_tokens", {}, 120_000));
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "okta-browser-close",
  "Close the live isolated Okta browser and delete its temporary profile",
  {},
  async () => {
    try {
      requireSelectedMode("browser");
      return jsonResult(await closeBrowserSession());
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "okta-oauth-login",
  "AUTHORIZED LAB: authenticate through the configured Okta OIDC client with Authorization Code and PKCE",
  {
    authorized: z.boolean(),
    tenantConfirmation: z
      .string()
      .min(1)
      .max(255)
      .describe("Exact configured tenant URL or hostname"),
  },
  async ({ authorized, tenantConfirmation }, extra) => {
    try {
      requireSelectedMode("oidc");
      const config = loadRuntimeConfig();
      requireAuthorization(config.orgUrl, tenantConfirmation, authorized);
      const outcome = await startOauthLogin(config, extra.signal);
      if (outcome.status === "authorization_pending") {
        return jsonResult({
          authorization_pending: true,
          organization: config.orgUrl,
          requested_scopes: config.scopes.split(/\s+/).filter(Boolean),
          next_step:
            "Finish Okta authentication, wait for completion, then call okta-oauth-reuse-proof.",
        });
      }
      const client = await OktaClient.create(config, outcome.tokens);
      const profile = await client.userinfo();
      return jsonResult({
        connected: true,
        organization: config.orgUrl,
        subject: profile.sub,
        client_id: redactClientId(config.clientId),
        granted_scopes: outcome.tokens.scope.split(/\s+/).filter(Boolean),
        raw_token_returned: false,
      });
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "okta-oauth-reuse-proof",
  "AUTHORIZED LAB: demonstrate bearer-token reuse with two read-only UserInfo calls and publish only a SHA-256 token fingerprint",
  {
    authorized: z.boolean(),
    tenantConfirmation: z
      .string()
      .min(1)
      .max(255)
      .describe("Exact configured tenant URL or hostname"),
  },
  async ({ authorized, tenantConfirmation }) => {
    try {
      requireSelectedMode("oidc");
      const config = loadRuntimeConfig();
      requireAuthorization(config.orgUrl, tenantConfirmation, authorized);
      const tokens = await getAuthenticatedTokens(config);
      if (!tokens) {
        throw new AuthenticationRequiredError(
          "No refreshable OAuth authorization is available for the lab."
        );
      }

      const firstClient = await OktaClient.create(config, tokens);
      const first = await firstClient.userinfo();
      const secondClient = await OktaClient.create(config, tokens);
      const second = await secondClient.userinfo();
      if (
        typeof first.sub !== "string" ||
        !first.sub ||
        first.sub !== second.sub
      ) {
        throw new Error(
          "The two controlled UserInfo requests did not return the same subject."
        );
      }

      await ensureCollector();
      const fingerprint = crypto
        .createHash("sha256")
        .update(tokens.access_token)
        .digest("hex");
      const issuer =
        config.authServer === "org"
          ? config.orgUrl
          : `${config.orgUrl}/oauth2/${config.authServer}`;
      const proof = {
        evidence_version: 1,
        evidence_type: "oauth_bearer_reuse",
        authorization_notice: "explicit_local_lab",
        captured_at: new Date().toISOString(),
        org_host: new URL(config.orgUrl).host,
        issuer,
        client_id_redacted: redactClientId(config.clientId),
        granted_scopes: tokens.scope.split(/\s+/).filter(Boolean),
        expires_at: new Date(
          tokens.obtained_at + tokens.expires_in * 1000
        ).toISOString(),
        subject: first.sub,
        token_fingerprint_sha256: fingerprint,
        reuse_attempts: [
          { sequence: 1, status: 200, subject: first.sub },
          { sequence: 2, status: 200, subject: second.sub },
        ],
      };
      const posted = await postProof(oauthProofEndpoint, proof);
      return jsonResult({
        demonstrated: true,
        organization: config.orgUrl,
        client_id: redactClientId(config.clientId),
        subject: first.sub,
        token_fingerprint_sha256: fingerprint,
        reuse_attempts: proof.reuse_attempts,
        collector_endpoint: oauthProofEndpoint.toString(),
        raw_token_returned: false,
        raw_token_sent_to_collector: false,
        deleted_old_count: posted.deleted_old_count,
      });
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "whoami",
  "Show the connected OIDC user's verified Okta identity and granted scopes",
  {},
  async () => {
    try {
      const { client } = await authenticatedClient();
      return jsonResult(await client.whoami());
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "userinfo",
  "Fetch the connected OIDC user's profile from Okta UserInfo",
  {},
  async () => {
    try {
      const { client } = await authenticatedClient();
      return jsonResult(await client.userinfo());
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "token-details",
  "Show safe token metadata without returning bearer values",
  {},
  async () => {
    try {
      const { client } = await authenticatedClient();
      return jsonResult(client.tokenDetails());
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "my-groups",
  "Show group names from the verified ID-token groups claim when configured",
  {},
  async () => {
    try {
      const { client } = await authenticatedClient();
      return jsonResult(client.myGroups());
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "my-apps",
  "List application links assigned to the connected user (requires okta.users.read)",
  {},
  async () => {
    try {
      const { client, tokens } = await authenticatedClient();
      requireGrantedScope(tokens, "okta.users.read");
      return jsonResult(await client.myAppLinks());
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "list-users",
  "List users visible to the connected Okta administrator (requires okta.users.read)",
  { limit: z.number().int().min(1).max(200).optional() },
  async ({ limit }) => {
    try {
      const { client, tokens } = await authenticatedClient();
      requireGrantedScope(tokens, "okta.users.read");
      return jsonResult(await client.listUsers(limit));
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "get-user",
  "Get one user visible to the connected Okta administrator (requires okta.users.read)",
  { userId: z.string().min(1).max(200) },
  async ({ userId }) => {
    try {
      const { client, tokens } = await authenticatedClient();
      requireGrantedScope(tokens, "okta.users.read");
      return jsonResult(await client.getUser(userId));
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "search-users",
  "Search users visible to the connected Okta administrator (requires okta.users.read)",
  { query: z.string().min(1).max(500) },
  async ({ query }) => {
    try {
      const { client, tokens } = await authenticatedClient();
      requireGrantedScope(tokens, "okta.users.read");
      return jsonResult(await client.searchUsers(query));
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "list-groups",
  "List groups visible to the connected Okta administrator (requires okta.groups.read)",
  { limit: z.number().int().min(1).max(200).optional() },
  async ({ limit }) => {
    try {
      const { client, tokens } = await authenticatedClient();
      requireGrantedScope(tokens, "okta.groups.read");
      return jsonResult(await client.listGroups(limit));
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "list-apps",
  "List applications visible to the connected Okta administrator (requires okta.apps.read)",
  { limit: z.number().int().min(1).max(200).optional() },
  async ({ limit }) => {
    try {
      const { client, tokens } = await authenticatedClient();
      requireGrantedScope(tokens, "okta.apps.read");
      return jsonResult(await client.listApps(limit));
    } catch (error) {
      return errorResult(error);
    }
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);

async function shutdownBrowserSession() {
  activeAuthorizationSession?.cancel();
  if (!browserSessionIsActive()) return;
  try {
    await closeBrowserSession();
  } catch {
    if (browserSession?.child.exitCode === null) {
      browserSession.child.kill("SIGTERM");
    }
  }
}

process.stdin.once("end", () => {
  void shutdownBrowserSession();
});
process.once("SIGTERM", () => {
  void shutdownBrowserSession().finally(() => process.exit(0));
});
process.once("SIGINT", () => {
  void shutdownBrowserSession().finally(() => process.exit(0));
});
