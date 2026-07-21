#!/usr/bin/env node

import fs from "node:fs";
import { stdin as input, stdout as output } from "node:process";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";
import {
  browserAuth,
  clearTokenCache,
  discoverOidcMetadata,
  getAuthenticatedTokens,
  inspectTokenCache,
  revokeAndClearTokens,
  startAuthorization,
} from "./auth.js";
import {
  configDir,
  configPath,
  configSource,
  DEFAULT_AUTH_SERVER,
  DEFAULT_CALLBACK_HOST,
  DEFAULT_CALLBACK_PORT,
  IDENTITY_SCOPES,
  loadFileConfig,
  loadRuntimeConfig,
  makeConfig,
  redactClientId,
  saveFileConfig,
  startupConfigPath,
  tokenCachePath,
  type OktaMcpConfig,
} from "./config.js";

function yes(value: string): boolean {
  return ["y", "yes", "true", "1"].includes(value.trim().toLowerCase());
}

async function ask(
  readline: ReturnType<typeof createInterface>,
  prompt: string,
  fallback = ""
): Promise<string> {
  const suffix = fallback ? ` [${fallback}]` : "";
  const answer = await readline.question(`${prompt}${suffix}: `);
  return answer.trim() || fallback;
}

function parsePort(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("--callback-port must be an integer from 1 to 65535.");
  }
  return port;
}

function configureOptions() {
  return parseArgs({
    args: process.argv.slice(3),
    strict: true,
    allowPositionals: false,
    options: {
      "org-url": { type: "string" },
      "client-id": { type: "string" },
      "auth-server": { type: "string" },
      scopes: { type: "string" },
      "callback-port": { type: "string" },
      "callback-host": { type: "string" },
      "org-read": { type: "boolean", default: false },
      "identity-only": { type: "boolean", default: false },
      "no-verify": { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  }).values;
}

function printConfigurationSummary(config: OktaMcpConfig): void {
  console.log("\nConfiguration:");
  console.log(`  Organization: ${config.orgUrl}`);
  console.log(
    `  Issuer: ${
      config.authServer === "org"
        ? config.orgUrl
        : `${config.orgUrl}/oauth2/${config.authServer}`
    }`
  );
  console.log(`  Client ID: ${redactClientId(config.clientId)}`);
  console.log(`  Scopes: ${config.scopes}`);
  console.log(
    `  Redirect URI: http://${config.callbackHost}:${config.callbackPort}/callback`
  );
}

async function configure(): Promise<void> {
  const values = configureOptions();
  if (values.help) {
    console.log(`Usage: okta-workspace-mcp configure [options]

Options:
  --org-url URL          Exact HTTPS origin of the Okta organization
  --client-id ID         Client ID of a public Okta Native OIDC app
  --org-read             Request read-only users, groups, and apps scopes
  --identity-only        Reset to the default identity-only scopes
  --auth-server ID       Authorization server ID (default: org)
  --scopes "..."         Explicit space-delimited OAuth scopes
  --callback-host HOST   Loopback host: localhost or 127.0.0.1 (default: localhost)
  --callback-port PORT   Loopback callback port (default: 8749)
  --no-verify            Save without checking OIDC discovery
  -h, --help             Show this help
`);
    return;
  }

  const existing = loadFileConfig();
  const hasCliValues = Boolean(
    values["org-url"] ||
      values["client-id"] ||
      values["auth-server"] ||
      values.scopes ||
      values["callback-host"] ||
      values["callback-port"] ||
      values["org-read"] ||
      values["identity-only"]
  );

  let config: OktaMcpConfig;
  if (hasCliValues) {
    const organizationRead = Boolean(values["org-read"]);
    if (organizationRead && values["identity-only"]) {
      throw new Error("--org-read and --identity-only cannot be used together.");
    }
    if (values.scopes && (organizationRead || values["identity-only"])) {
      throw new Error(
        "--scopes cannot be combined with --org-read or --identity-only. Choose one scope mode."
      );
    }
    const orgUrl = values["org-url"] || existing.orgUrl || "";
    const clientId = values["client-id"] || existing.clientId || "";
    if (!orgUrl || !clientId) {
      throw new Error(
        "--org-url and --client-id are both required for first-time non-interactive configuration."
      );
    }
    const oidcApplicationChanged = Boolean(
      existing.orgUrl &&
        (orgUrl.replace(/\/+$/, "") !== existing.orgUrl ||
          clientId !== existing.clientId)
    );

    config = makeConfig({
      orgUrl,
      clientId,
      authServer:
        values["auth-server"] ||
        (organizationRead
          ? DEFAULT_AUTH_SERVER
          : oidcApplicationChanged
            ? DEFAULT_AUTH_SERVER
            : existing.authServer || DEFAULT_AUTH_SERVER),
      scopes:
        values.scopes ||
        (values["identity-only"]
          ? IDENTITY_SCOPES
          : organizationRead
            ? undefined
            : oidcApplicationChanged
              ? IDENTITY_SCOPES
              : existing.scopes || IDENTITY_SCOPES),
      callbackPort: parsePort(
        values["callback-port"],
        existing.callbackPort || DEFAULT_CALLBACK_PORT
      ),
      callbackHost:
        values["callback-host"] ||
        existing.callbackHost ||
        DEFAULT_CALLBACK_HOST,
      organizationRead,
    });
  } else {
    if (!input.isTTY) {
      throw new Error(
        "Interactive configuration requires a terminal. Pass --org-url and --client-id instead."
      );
    }
    const readline = createInterface({ input, output });
    try {
      const orgUrl = await ask(
        readline,
        "Okta organization URL",
        existing.orgUrl || ""
      );
      const clientId = await ask(
        readline,
        "Okta Native OIDC client ID",
        existing.clientId || ""
      );
      const existingOrgRead = (existing.scopes || "")
        .split(/\s+/)
        .some((scope) => scope.startsWith("okta."));
      const oidcApplicationChanged = Boolean(
        existing.orgUrl &&
          (orgUrl.replace(/\/+$/, "") !== existing.orgUrl ||
            clientId !== existing.clientId)
      );
      const organizationRead = yes(
        await ask(
          readline,
          "Enable read-only organization tools? y/N",
          existingOrgRead && !oidcApplicationChanged ? "Y" : "N"
        )
      );
      const callbackPort = parsePort(
        await ask(
          readline,
          "OAuth callback port",
          String(existing.callbackPort || DEFAULT_CALLBACK_PORT)
        ),
        DEFAULT_CALLBACK_PORT
      );

      config = makeConfig({
        orgUrl,
        clientId,
        authServer: organizationRead
          ? DEFAULT_AUTH_SERVER
          : oidcApplicationChanged
            ? DEFAULT_AUTH_SERVER
            : existing.authServer || DEFAULT_AUTH_SERVER,
        callbackPort,
        callbackHost: existing.callbackHost || DEFAULT_CALLBACK_HOST,
        organizationRead,
      });
      printConfigurationSummary(config);
      const confirmed = await ask(readline, "Save this configuration? Y/n", "Y");
      if (["n", "no", "false", "0"].includes(confirmed.toLowerCase())) {
        console.log("Configuration was not changed.");
        return;
      }
    } finally {
      readline.close();
    }
  }

  printConfigurationSummary(config);
  if (!values["no-verify"]) {
    process.stderr.write(`Verifying OIDC discovery at ${config.orgUrl}...\n`);
    await discoverOidcMetadata(config, { force: true });
  }
  const authorizationContextChanged = Boolean(
    existing.orgUrl &&
      (existing.orgUrl !== config.orgUrl ||
        existing.clientId !== config.clientId ||
        (existing.authServer || DEFAULT_AUTH_SERVER) !== config.authServer ||
        (existing.scopes || IDENTITY_SCOPES) !== config.scopes)
  );
  if (authorizationContextChanged) {
    try {
      const previousConfig = makeConfig({
        orgUrl: existing.orgUrl || "",
        clientId: existing.clientId || "",
        authServer: existing.authServer || DEFAULT_AUTH_SERVER,
        scopes: existing.scopes || IDENTITY_SCOPES,
        callbackPort: existing.callbackPort || DEFAULT_CALLBACK_PORT,
        callbackHost: existing.callbackHost || DEFAULT_CALLBACK_HOST,
      });
      const previousTokens = inspectTokenCache(previousConfig);
      if (previousTokens.present) {
        throw new Error(
          'A cached Okta authorization still exists. Run "okta-workspace-mcp logout" before changing the tenant, client, authorization server, or scopes.'
        );
      }
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.startsWith("A cached Okta authorization")
      ) {
        throw error;
      }
      // An incomplete legacy configuration has no usable authorization context.
    }
  }
  saveFileConfig(config);
  if (authorizationContextChanged) clearTokenCache();
  console.log(`\nSaved configuration: ${configPath}`);
  if (authorizationContextChanged) {
    console.log("Cleared the cached authorization because the tenant, app, or scopes changed.");
  }
  console.log('Next: run "okta-workspace-mcp login".');
}

function loginOptions() {
  return parseArgs({
    args: process.argv.slice(3),
    strict: true,
    allowPositionals: false,
    options: {
      "no-open": { type: "boolean", default: false },
      force: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  }).values;
}

async function login(): Promise<void> {
  const values = loginOptions();
  if (values.help) {
    console.log(`Usage: okta-workspace-mcp login [--force] [--no-open]

  --force    Discard the cached authorization and sign in again
  --no-open  Print the authorization URL instead of opening a browser
`);
    return;
  }

  const config = loadRuntimeConfig();
  if (values.force) await revokeAndClearTokens(config);
  const cached = await getAuthenticatedTokens(config);
  if (cached) {
    console.log(`Already connected to ${config.orgUrl}.`);
    return;
  }

  printConfigurationSummary(config);
  if (values["no-open"]) {
    const session = await startAuthorization(config);
    console.log("\nOpen this URL in a browser to continue:");
    console.log(session.authorizationUrl);
    await session.completion;
  } else {
    await browserAuth(config);
  }
  console.log(`Connected to ${config.orgUrl}.`);
}

function status(): void {
  let config: OktaMcpConfig;
  try {
    config = loadRuntimeConfig();
  } catch (error) {
    console.log(
      JSON.stringify(
        {
          configured: false,
          configurationSource: configSource(),
          configPath,
          message: error instanceof Error ? error.message : String(error),
        },
        null,
        2
      )
    );
    process.exitCode = 1;
    return;
  }

  const tokenCache = inspectTokenCache(config);
  const connectionState =
    tokenCache.present && tokenCache.contextMatches && !tokenCache.expired
      ? "ready"
      : tokenCache.contextMatches && tokenCache.refreshTokenAvailable
        ? "refreshable"
        : "login_required";
  console.log(
    JSON.stringify(
      {
        configured: true,
        configurationSource: configSource(),
        configPath,
        tokenCachePath,
        organization: config.orgUrl,
        clientId: redactClientId(config.clientId),
        authServer: config.authServer,
        scopes: config.scopes.split(/\s+/),
        redirectUri: `http://${config.callbackHost}:${config.callbackPort}/callback`,
        connectionState,
        tokenCache,
      },
      null,
      2
    )
  );
}

async function logout(): Promise<void> {
  const values = parseArgs({
    args: process.argv.slice(3),
    strict: true,
    allowPositionals: false,
    options: {
      "local-only": { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  }).values;

  if (values.help) {
    console.log(`Usage: okta-workspace-mcp logout [--local-only]

  --local-only  Remove the local cache without calling Okta's revocation endpoint
`);
    return;
  }

  if (values["local-only"]) {
    clearTokenCache();
    console.log("Removed the local Okta token cache.");
    return;
  }

  const config = loadRuntimeConfig();
  const result = await revokeAndClearTokens(config);
  console.log(
    result.revoked
      ? "Revoked the cached authorization and removed the local token cache."
      : "Removed the local token cache; no revocable cached authorization was found."
  );
}

async function reset(): Promise<void> {
  try {
    const config = loadRuntimeConfig();
    await revokeAndClearTokens(config);
  } catch (error) {
    clearTokenCache();
    const message = error instanceof Error ? error.message : String(error);
    if (!message.startsWith("Okta MCP is not configured:")) {
      process.stderr.write(
        `Warning: remote token revocation could not be confirmed: ${message}\n`
      );
    }
  }
  for (const savedPath of [startupConfigPath, configPath]) {
    if (fs.existsSync(savedPath)) fs.rmSync(savedPath);
  }
  console.log(
    `Removed saved startup mode, local configuration, and token cache from ${configDir}.`
  );
}

function help(): void {
  console.log(`okta-workspace-mcp

Commands:
  configure   Configure the Okta organization, OIDC client, and scopes
  setup       Alias for configure
  login       Authenticate to the configured Okta organization with PKCE
  status      Show configuration and connection status without credentials
  logout      Revoke cached OAuth credentials and remove the local cache
  stdio       Start the MCP stdio server
  serve       Alias for stdio
  config-path Print the saved configuration path
  reset       Remove local configuration and cached OAuth credentials
  help        Show this help
`);
}

async function serve(): Promise<void> {
  // Use the same canonical server as npm start, Codex, and VS Code. The dynamic
  // URL avoids a second public MCP entrypoint while keeping CLI maintenance
  // commands in this compiled file.
  process.argv.splice(2, 1);
  await import(new URL("../scripts/okta-mcp.mjs", import.meta.url).href);
}

const command = process.argv[2] || "stdio";

try {
  if (command === "configure" || command === "setup" || command === "init") {
    await configure();
  } else if (command === "login") {
    await login();
  } else if (command === "status" || command === "config") {
    status();
  } else if (command === "logout") {
    await logout();
  } else if (command === "stdio" || command === "serve") {
    await serve();
  } else if (command === "config-path") {
    console.log(configPath);
  } else if (command === "reset") {
    await reset();
  } else if (command === "help" || command === "--help" || command === "-h") {
    help();
  } else {
    help();
    process.exitCode = 1;
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`Error: ${message}\n`);
  process.exitCode = 1;
}
