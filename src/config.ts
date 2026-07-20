import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const CONFIG_VERSION = 2;
export const DEFAULT_AUTH_SERVER = "org";
export const DEFAULT_CALLBACK_PORT = 8749;
export const DEFAULT_CALLBACK_HOST = "localhost";
export const IDENTITY_SCOPES = "openid profile email offline_access";
export const ORGANIZATION_READ_SCOPES =
  `${IDENTITY_SCOPES} okta.users.read okta.groups.read okta.apps.read`;
export const SUPPORTED_SCOPES = new Set([
  "openid",
  "profile",
  "email",
  "offline_access",
  "groups",
  "okta.users.read",
  "okta.groups.read",
  "okta.apps.read",
]);

export interface OktaMcpConfig {
  configVersion: number;
  orgUrl: string;
  clientId: string;
  authServer: string;
  scopes: string;
  callbackHost: "localhost" | "127.0.0.1";
  callbackPort: number;
}

const configuredDirectory = process.env.OKTA_MCP_CONFIG_DIR?.trim();
export const configDir = configuredDirectory
  ? path.resolve(configuredDirectory)
  : path.join(os.homedir(), ".okta-workspace-mcp");
export const configPath = path.join(configDir, "config.json");
export const tokenCachePath = path.join(configDir, "tokens.json");

function allowInsecureLoopbackHttp(): boolean {
  return ["1", "true", "yes"].includes(
    (process.env.OKTA_MCP_ALLOW_INSECURE_HTTP || "").toLowerCase()
  );
}

function isLiteralLoopback(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "[::1]";
}

export function normalizeOrgUrl(value: string): string {
  const trimmed = value.trim().replace(/\/+$/, "");
  if (!trimmed) return "";
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

export function validateOrgUrl(value: string): string {
  const normalized = normalizeOrgUrl(value);
  let parsed: URL;

  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error("Okta org URL must be a valid absolute URL.");
  }

  const insecureLoopback =
    parsed.protocol === "http:" &&
    allowInsecureLoopbackHttp() &&
    isLiteralLoopback(parsed.hostname);
  if (parsed.protocol !== "https:" && !insecureLoopback) {
    throw new Error("Okta org URL must use HTTPS.");
  }
  if (!parsed.hostname) {
    throw new Error("Okta org URL must include a hostname.");
  }
  if (parsed.username || parsed.password) {
    throw new Error("Okta org URL must not include a username or password.");
  }
  if (parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error(
      "Okta org URL must be an origin only, without a path, query, or fragment."
    );
  }
  if (parsed.port && !insecureLoopback) {
    throw new Error("Okta org URL must not include a custom port.");
  }

  return parsed.origin;
}

export function validateClientId(value: string): string {
  const clientId = value.trim();
  if (!clientId || clientId.length > 200 || /\s/.test(clientId)) {
    throw new Error(
      "Okta OIDC client ID is required and must not contain whitespace."
    );
  }
  return clientId;
}

export function validateAuthServer(value: string | undefined): string {
  const authServer = (value || DEFAULT_AUTH_SERVER).trim();
  if (authServer === "org") return authServer;
  if (!/^[A-Za-z0-9._-]{1,100}$/.test(authServer)) {
    throw new Error(
      'Authorization server must be "org" or a valid Okta authorization-server ID.'
    );
  }
  return authServer;
}

export function normalizeScopes(value: string | undefined): string {
  const raw = (value || IDENTITY_SCOPES).trim();
  const scopes = [...new Set(raw.split(/\s+/).filter(Boolean))];

  if (!scopes.includes("openid")) {
    throw new Error('OIDC scopes must include "openid".');
  }
  const unsupported = scopes.filter((scope) => !SUPPORTED_SCOPES.has(scope));
  if (unsupported.length > 0) {
    throw new Error(
      `Unsupported OAuth scope${unsupported.length === 1 ? "" : "s"}: ${unsupported.join(
        ", "
      )}. This MCP accepts only its documented identity and read-only Okta scopes.`
    );
  }
  return scopes.join(" ");
}

function parseCallbackPort(value: string | number | undefined): number {
  if (value === undefined || value === "") return DEFAULT_CALLBACK_PORT;
  const port = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("OAuth callback port must be an integer from 1 to 65535.");
  }
  return port;
}

export function validateCallbackHost(
  value: string | undefined
): "localhost" | "127.0.0.1" {
  const host = (value || DEFAULT_CALLBACK_HOST).trim().toLowerCase();
  if (host !== "localhost" && host !== "127.0.0.1") {
    throw new Error('OAuth callback host must be "localhost" or "127.0.0.1".');
  }
  return host;
}

function validateConfig(config: Partial<OktaMcpConfig>): OktaMcpConfig {
  const authServer = validateAuthServer(config.authServer);
  const scopes = normalizeScopes(config.scopes);

  if (authServer !== "org" && scopes.split(" ").some((scope) => scope.startsWith("okta."))) {
    throw new Error(
      'Okta API scopes require the org authorization server (authServer: "org").'
    );
  }

  return {
    configVersion: CONFIG_VERSION,
    orgUrl: validateOrgUrl(config.orgUrl || ""),
    clientId: validateClientId(config.clientId || ""),
    authServer,
    scopes,
    callbackHost: validateCallbackHost(config.callbackHost),
    callbackPort: parseCallbackPort(config.callbackPort),
  };
}

export function loadFileConfig(): Partial<OktaMcpConfig> {
  if (!fs.existsSync(configPath)) return {};

  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Could not read ${configPath}: ${detail}`);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Invalid configuration in ${configPath}: expected a JSON object.`);
  }
  return parsed as Partial<OktaMcpConfig>;
}

export function writePrivateJson(filePath: string, value: unknown): void {
  const directory = path.dirname(filePath);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporaryPath = path.join(
    directory,
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomUUID()}.tmp`
  );

  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(temporaryPath, "wx", 0o600);
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporaryPath, filePath);
    try {
      fs.chmodSync(filePath, 0o600);
    } catch {
      // Windows may not implement POSIX modes; the user profile ACL still applies.
    }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (fs.existsSync(temporaryPath)) fs.rmSync(temporaryPath);
  }
}

export function saveFileConfig(config: OktaMcpConfig): void {
  writePrivateJson(configPath, validateConfig(config));
}

export function loadRuntimeConfig(): OktaMcpConfig {
  try {
    let file: Partial<OktaMcpConfig> = {};
    try {
      file = loadFileConfig();
    } catch (error) {
      const completeEnvironment = Boolean(
        process.env.OKTA_ORG_URL?.trim() && process.env.OKTA_CLIENT_ID?.trim()
      );
      if (!completeEnvironment) throw error;
      // A complete managed environment is authoritative and can recover from
      // an unrelated or corrupt per-user file.
    }

    const merged: Partial<OktaMcpConfig> = {
      ...file,
      orgUrl: process.env.OKTA_ORG_URL?.trim() || file.orgUrl,
      clientId: process.env.OKTA_CLIENT_ID?.trim() || file.clientId,
      authServer: process.env.OKTA_AUTH_SERVER?.trim() || file.authServer,
      scopes: process.env.OKTA_SCOPES?.trim() || file.scopes,
      callbackHost:
        process.env.OKTA_OAUTH_CALLBACK_HOST?.trim() || file.callbackHost,
      callbackPort:
        process.env.OKTA_OAUTH_CALLBACK_PORT?.trim() || file.callbackPort,
    } as Partial<OktaMcpConfig>;

    return validateConfig(merged);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Okta MCP is not configured: ${detail} Run "okta-workspace-mcp configure" ` +
        `or set OKTA_ORG_URL and OKTA_CLIENT_ID in the MCP client.`
    );
  }
}

export function tryLoadRuntimeConfig(): OktaMcpConfig | null {
  try {
    return loadRuntimeConfig();
  } catch {
    return null;
  }
}

export function configSource(): "environment" | "file" | "missing" {
  if (process.env.OKTA_ORG_URL?.trim() || process.env.OKTA_CLIENT_ID?.trim()) {
    return "environment";
  }
  return fs.existsSync(configPath) ? "file" : "missing";
}

export function redactClientId(clientId: string): string {
  if (clientId.length <= 8) return `${clientId.slice(0, 2)}...`;
  return `${clientId.slice(0, 6)}...${clientId.slice(-2)}`;
}

export function makeConfig(options: {
  orgUrl: string;
  clientId: string;
  authServer?: string;
  scopes?: string;
  callbackHost?: string;
  callbackPort?: number;
  organizationRead?: boolean;
}): OktaMcpConfig {
  return validateConfig({
    configVersion: CONFIG_VERSION,
    orgUrl: options.orgUrl,
    clientId: options.clientId,
    authServer: options.authServer || DEFAULT_AUTH_SERVER,
    scopes:
      options.scopes ||
      (options.organizationRead ? ORGANIZATION_READ_SCOPES : IDENTITY_SCOPES),
    callbackHost: validateCallbackHost(options.callbackHost),
    callbackPort: options.callbackPort || DEFAULT_CALLBACK_PORT,
  });
}
