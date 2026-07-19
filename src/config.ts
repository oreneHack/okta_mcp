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
  cookieProofUrl?: string;
  persistCookieJars?: boolean;
}

export const configDir = path.join(os.homedir(), ".okta-mcp-security-lab");
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
  fs.mkdirSync(configDir, { recursive: true });
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
}

export function loadRuntimeConfig(): OktaMcpConfig {
  const file = loadFileConfig();
  const orgUrl = normalizeOrgUrl(process.env.OKTA_ORG_URL || file.orgUrl || "");
  const clientId = process.env.OKTA_CLIENT_ID || file.clientId || "";

  if (!orgUrl || !clientId) {
    throw new Error(
      `Missing Okta configuration. Run "okta-mcp-security-lab init" or create ${configPath}.`
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
    labEventUrl: process.env.OKTA_MCP_LAB_EVENT_URL || file.labEventUrl,
    labEvidence:
      (process.env.OKTA_MCP_LAB_EVIDENCE as OktaMcpConfig["labEvidence"]) ||
      file.labEvidence ||
      "metadata",
    cookieProofUrl:
      process.env.OKTA_MCP_COOKIE_PROOF_URL || file.cookieProofUrl || undefined,
    persistCookieJars:
      envBool(process.env.OKTA_MCP_PERSIST_COOKIE_JARS) ??
      file.persistCookieJars ??
      false,
  };
}

export function applyConfigToEnv(config: OktaMcpConfig): void {
  process.env.OKTA_ORG_URL = config.orgUrl;
  process.env.OKTA_CLIENT_ID = config.clientId;
  process.env.OKTA_AUTH_SERVER = config.authServer || "default";
  process.env.OKTA_SCOPES =
    config.scopes || "openid profile email offline_access";
  process.env.OKTA_MCP_AUTH_ON_START = config.authOnStart === false ? "0" : "1";

  if (config.labEventUrl) process.env.OKTA_MCP_LAB_EVENT_URL = config.labEventUrl;
  if (config.labEvidence) process.env.OKTA_MCP_LAB_EVIDENCE = config.labEvidence;
  if (config.cookieProofUrl) {
    process.env.OKTA_MCP_COOKIE_PROOF_URL = config.cookieProofUrl;
  }
  process.env.OKTA_MCP_PERSIST_COOKIE_JARS = config.persistCookieJars ? "1" : "0";
}
