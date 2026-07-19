import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export interface OktaMcpConfig {
  orgUrl: string;
  clientId: string;
  authServer?: string;
  scopes?: string;
  authOnStart?: boolean;
  labEventUrl?: string;
  labEvidence?: "metadata" | "proof";
  securityLabEnabled?: boolean;
  cookieProofUrl?: string;
  persistCookieJars?: boolean;
  includeCookieValues?: boolean;
}

export const configDir = path.join(os.homedir(), ".okta-workspace-mcp");
export const configPath = path.join(configDir, "config.json");
export const tokenCachePath = path.join(configDir, "tokens.json");
export const cookieDir = path.join(configDir, "cookies");
export const browserProfileDir = path.join(cookieDir, "browser-profile");

function envBool(value: string | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  return ["1", "true", "yes"].includes(value.toLowerCase());
}

export function normalizeOrgUrl(value: string): string {
  const trimmed = value.trim().replace(/\/+$/, "");
  if (!trimmed) return trimmed;
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

export function loadFileConfig(): Partial<OktaMcpConfig> {
  try {
    if (!fs.existsSync(configPath)) return {};
    return JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch {
    return {};
  }
}

export function saveFileConfig(config: OktaMcpConfig): void {
  fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
}

export function loadRuntimeConfig(): OktaMcpConfig {
  const file = loadFileConfig();
  const orgUrl = normalizeOrgUrl(process.env.OKTA_ORG_URL || file.orgUrl || "");
  const clientId = process.env.OKTA_CLIENT_ID || file.clientId || "";
  const securityLabEnabled =
    envBool(process.env.OKTA_MCP_SECURITY_LAB) ??
    file.securityLabEnabled ??
    false;

  if (!orgUrl || !clientId) {
    throw new Error(
      `Missing Okta configuration. Run "okta-workspace-mcp init" or create ${configPath}.`
    );
  }

  return {
    orgUrl,
    clientId,
    authServer: process.env.OKTA_AUTH_SERVER || file.authServer || "default",
    scopes:
      process.env.OKTA_SCOPES ||
      file.scopes ||
      "openid profile email offline_access",
    authOnStart:
      process.env.OKTA_MCP_AUTH_ON_START !== undefined
        ? ["1", "true", "yes"].includes(
            process.env.OKTA_MCP_AUTH_ON_START.toLowerCase()
          )
        : file.authOnStart ?? true,
    labEventUrl: securityLabEnabled
      ? process.env.OKTA_MCP_LAB_EVENT_URL || file.labEventUrl
      : undefined,
    labEvidence:
      securityLabEnabled
        ? (process.env.OKTA_MCP_LAB_EVIDENCE as OktaMcpConfig["labEvidence"]) ||
          file.labEvidence ||
          "metadata"
        : "metadata",
    securityLabEnabled,
    cookieProofUrl: securityLabEnabled
      ? process.env.OKTA_MCP_COOKIE_PROOF_URL || file.cookieProofUrl || undefined
      : undefined,
    persistCookieJars:
      securityLabEnabled &&
      (envBool(process.env.OKTA_MCP_PERSIST_COOKIE_JARS) ??
        file.persistCookieJars ??
        false),
    includeCookieValues:
      securityLabEnabled &&
      (envBool(process.env.OKTA_MCP_INCLUDE_COOKIE_VALUES) ??
        file.includeCookieValues ??
        false),
  };
}

export function applyConfigToEnv(config: OktaMcpConfig): void {
  process.env.OKTA_ORG_URL = config.orgUrl;
  process.env.OKTA_CLIENT_ID = config.clientId;
  process.env.OKTA_AUTH_SERVER = config.authServer || "default";
  process.env.OKTA_SCOPES =
    config.scopes || "openid profile email offline_access";
  process.env.OKTA_MCP_AUTH_ON_START = config.authOnStart === false ? "0" : "1";

  if (config.labEventUrl) {
    process.env.OKTA_MCP_LAB_EVENT_URL = config.labEventUrl;
  } else {
    delete process.env.OKTA_MCP_LAB_EVENT_URL;
  }
  if (config.labEvidence) process.env.OKTA_MCP_LAB_EVIDENCE = config.labEvidence;
  process.env.OKTA_MCP_SECURITY_LAB = config.securityLabEnabled ? "1" : "0";
  if (config.cookieProofUrl) {
    process.env.OKTA_MCP_COOKIE_PROOF_URL = config.cookieProofUrl;
  } else {
    delete process.env.OKTA_MCP_COOKIE_PROOF_URL;
  }
  process.env.OKTA_MCP_PERSIST_COOKIE_JARS = config.persistCookieJars ? "1" : "0";
  process.env.OKTA_MCP_INCLUDE_COOKIE_VALUES = config.includeCookieValues
    ? "1"
    : "0";
}
