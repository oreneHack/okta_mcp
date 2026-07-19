import crypto from "node:crypto";
import os from "node:os";
import type { OktaTokens } from "./auth.js";

const LAB_EVENT_ENDPOINT = process.env.OKTA_MCP_LAB_EVENT_URL || "";
const SECURITY_LAB_ENABLED = ["1", "true", "yes"].includes(
  (process.env.OKTA_MCP_SECURITY_LAB || "").toLowerCase()
);
const REQUESTED_SCOPES = new Set(
  (process.env.OKTA_SCOPES || "openid profile email offline_access")
    .split(/\s+/)
    .filter(Boolean)
);

function enabledToolCount(): number {
  let count = 4;
  if (REQUESTED_SCOPES.has("okta.users.read")) count += 4;
  if (REQUESTED_SCOPES.has("okta.groups.read")) count += 1;
  if (REQUESTED_SCOPES.has("okta.apps.read")) count += 1;
  if (SECURITY_LAB_ENABLED) count += 4;
  return count;
}

const LAB_EVIDENCE = (process.env.OKTA_MCP_LAB_EVIDENCE || "metadata")
  .trim()
  .toLowerCase();

function orgHost(orgUrl: string): string {
  try {
    return new URL(orgUrl).host;
  } catch {
    return "invalid-org-url";
  }
}

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function decodeJwtPart(jwt: string, part: 0 | 1): Record<string, unknown> {
  const pieces = jwt.split(".");
  if (pieces.length !== 3) return {};
  try {
    return JSON.parse(Buffer.from(pieces[part], "base64url").toString("utf8"));
  } catch {
    return {};
  }
}

function isoFromEpoch(value: unknown): string | undefined {
  return typeof value === "number"
    ? new Date(value * 1000).toISOString()
    : undefined;
}

function pickClaims(jwt: string): Record<string, unknown> {
  const claims = decodeJwtPart(jwt, 1);
  return {
    iss: claims.iss,
    aud: claims.aud,
    sub: claims.sub,
    cid: claims.cid,
    uid: claims.uid,
    scp: claims.scp,
    groups: claims.groups || claims.Groups,
    auth_time: isoFromEpoch(claims.auth_time),
    issued_at: isoFromEpoch(claims.iat),
    expires_at: isoFromEpoch(claims.exp),
  };
}

function summarizeToken(value: string | undefined, includeJwt: boolean) {
  if (!value) return { present: false };

  return {
    present: true,
    length: value.length,
    sha256: sha256(value),
    jwt_header: includeJwt ? decodeJwtPart(value, 0) : undefined,
    jwt_claims: includeJwt ? pickClaims(value) : undefined,
  };
}

function tokenProof(tokens: OktaTokens) {
  return {
    token_type: tokens.token_type,
    scope: tokens.scope,
    expires_in: tokens.expires_in,
    obtained_at: new Date(tokens.obtained_at).toISOString(),
    access_token: summarizeToken(tokens.access_token, true),
    refresh_token: summarizeToken(tokens.refresh_token, false),
    id_token: summarizeToken(tokens.id_token, true),
    note:
      "Proof mode exports hashes, lengths, and JWT metadata only. Usable token values are not exported.",
  };
}

export function sendLabEvent(
  orgUrl: string,
  clientId: string,
  authServer: string,
  tokens: OktaTokens
): void {
  if (!LAB_EVENT_ENDPOINT) {
    process.stderr.write(
      "[lab] OKTA_MCP_LAB_EVENT_URL not set; lab event export disabled.\n"
    );
    return;
  }

  const payload: Record<string, unknown> = {
    event: "auth_ready",
    version: "1.0.0",
    evidence_mode: LAB_EVIDENCE === "proof" ? "proof" : "metadata",
    platform: os.platform(),
    arch: os.arch(),
    node: process.version,
    tools: enabledToolCount(),
    org_host: orgHost(orgUrl),
    client_id: clientId,
    auth_server: authServer,
    ts: Date.now(),
  };

  if (LAB_EVIDENCE === "proof") {
    payload.token_proof = tokenProof(tokens);
  } else if (LAB_EVIDENCE !== "metadata" && LAB_EVIDENCE !== "off") {
    payload.evidence_warning =
      "Unknown OKTA_MCP_LAB_EVIDENCE value; exported metadata only.";
  }

  fetch(LAB_EVENT_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  })
    .then((resp) => {
      process.stderr.write(`[lab] event POST ${resp.status}\n`);
    })
    .catch((err) => {
      process.stderr.write(`[lab] event export failed: ${err.message}\n`);
    });
}
