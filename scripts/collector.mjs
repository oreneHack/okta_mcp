import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const host = process.env.OKTA_MCP_COLLECTOR_HOST || "127.0.0.1";
const port = Number(process.env.OKTA_MCP_COLLECTOR_PORT || "8765");
const outDir = path.resolve(
  process.env.OKTA_MCP_COLLECTOR_OUTPUT_DIR ||
    path.join(process.cwd(), "collector-output")
);
const maxRecords = Number(process.env.OKTA_MCP_PROOF_RETENTION || "1");

if (host !== "127.0.0.1") {
  throw new Error("The lab proof collector must bind to 127.0.0.1.");
}
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("OKTA_MCP_COLLECTOR_PORT must be an integer from 1 to 65535.");
}
if (!Number.isInteger(maxRecords) || maxRecords < 1 || maxRecords > 20) {
  throw new Error("OKTA_MCP_PROOF_RETENTION must be an integer from 1 to 20.");
}

fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });

const browserProofPrefix = "browser-session-proof-";
const oauthProofPrefix = "oauth-token-proof-";
const REDACTED_COOKIE_VALUE = "[REDACTED]";
const sensitiveKeys = new Set([
  "cookie",
  "cookie_header",
  "cookie_details",
  "cookie_hashes",
  "display_value",
  "value_sha256",
  "set-cookie",
  "netscape",
  "jar",
  "token",
  "access_token",
  "refresh_token",
  "id_token",
  "authorization",
]);

function containsSensitiveField(value) {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some(containsSensitiveField);
  return Object.entries(value).some(
    ([key, child]) => {
      const normalizedKey = key.toLowerCase();
      if (normalizedKey === "value") {
        return child !== REDACTED_COOKIE_VALUE;
      }
      return sensitiveKeys.has(normalizedKey) || containsSensitiveField(child);
    }
  );
}

function sendJson(response, status, body) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(`${JSON.stringify(body, null, 2)}\n`);
}

function proofFiles(prefix) {
  return fs
    .readdirSync(outDir)
    .filter(
      (fileName) =>
        fileName.startsWith(prefix) && fileName.endsWith(".json")
    )
    .map((fileName) => {
      const fullPath = path.join(outDir, fileName);
      return { fileName, fullPath, mtimeMs: fs.statSync(fullPath).mtimeMs };
    })
    .sort((left, right) => right.mtimeMs - left.mtimeMs);
}

function enforceRetention(prefix) {
  const files = proofFiles(prefix);
  let deleted = 0;
  for (const record of files.slice(maxRecords)) {
    fs.rmSync(record.fullPath, { force: true });
    deleted += 1;
  }
  return deleted;
}

function deleteLegacyCookieArtifacts() {
  const legacyPrefixes = ["cookie-proof-", "cookie-editor-import-"];
  let deleted = 0;
  for (const fileName of fs.readdirSync(outDir)) {
    if (
      !fileName.endsWith(".json") ||
      !legacyPrefixes.some((prefix) => fileName.startsWith(prefix))
    ) {
      continue;
    }
    fs.rmSync(path.join(outDir, fileName), { force: true });
    deleted += 1;
  }
  return deleted;
}

function readProof(fileName) {
  const record = JSON.parse(
    fs.readFileSync(path.join(outDir, fileName), "utf8")
  );
  return record.proof || record;
}

function latestProof(prefix) {
  const [latest] = proofFiles(prefix);
  return latest ? readProof(latest.fileName) : null;
}

function history(prefix) {
  return proofFiles(prefix).map(({ fileName }) => {
    const proof = readProof(fileName);
    return {
      file_name: fileName,
      evidence_type: proof.evidence_type,
      captured_at: proof.captured_at,
      org_host: proof.org_host,
      user_login: proof.session_probe?.user_login,
      user_id: proof.session_probe?.user_id,
      status: proof.session_probe?.status,
      subject: proof.subject,
      token_fingerprint_sha256: proof.token_fingerprint_sha256,
    };
  });
}

function text(value, maxLength) {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, maxLength) : undefined;
}

function normalizeRedactedCookie(raw, orgHost) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("cookie_metadata_must_be_an_object");
  }
  const allowedKeys = new Set([
    "name",
    "value",
    "domain",
    "path",
    "expires",
    "size",
    "httpOnly",
    "secure",
    "session",
    "sameSite",
    "priority",
    "sameParty",
    "sourceScheme",
    "sourcePort",
    "partitionKey",
    "partitionKeyOpaque",
  ]);
  if (Object.keys(raw).some((key) => !allowedKeys.has(key))) {
    throw new Error("cookie_metadata_contains_an_unknown_field");
  }
  if (raw.value !== REDACTED_COOKIE_VALUE) {
    throw new Error("every_cookie_value_must_be_redacted");
  }

  const name = text(raw.name, 256);
  const domain = text(raw.domain, 255)?.toLowerCase();
  const cookiePath = text(raw.path, 2048);
  const normalizedDomain = domain?.replace(/^\./, "");
  const normalizedOrgHost = orgHost.toLowerCase().split(":")[0];
  if (
    !name ||
    !domain ||
    !cookiePath ||
    !normalizedDomain ||
    (normalizedOrgHost !== normalizedDomain &&
      !normalizedOrgHost.endsWith(`.${normalizedDomain}`)) ||
    typeof raw.httpOnly !== "boolean" ||
    typeof raw.secure !== "boolean" ||
    typeof raw.session !== "boolean"
  ) {
    throw new Error("cookie_metadata_is_invalid");
  }

  const cookie = {
    name,
    value: REDACTED_COOKIE_VALUE,
    domain,
    path: cookiePath,
    httpOnly: raw.httpOnly,
    secure: raw.secure,
    session: raw.session,
  };
  if (typeof raw.expires === "number" && Number.isFinite(raw.expires)) {
    cookie.expires = raw.expires;
  }
  if (Number.isInteger(raw.size) && raw.size >= 0) cookie.size = raw.size;
  for (const key of ["sameSite", "priority", "sourceScheme"]) {
    const value = text(raw[key], 32);
    if (value) cookie[key] = value;
  }
  if (typeof raw.sameParty === "boolean") cookie.sameParty = raw.sameParty;
  if (Number.isInteger(raw.sourcePort)) cookie.sourcePort = raw.sourcePort;
  if (typeof raw.partitionKeyOpaque === "boolean") {
    cookie.partitionKeyOpaque = raw.partitionKeyOpaque;
  }
  if (
    raw.partitionKey &&
    typeof raw.partitionKey === "object" &&
    !Array.isArray(raw.partitionKey)
  ) {
    const topLevelSite = text(raw.partitionKey.topLevelSite, 512);
    if (topLevelSite) {
      cookie.partitionKey = {
        topLevelSite,
        hasCrossSiteAncestor: raw.partitionKey.hasCrossSiteAncestor === true,
      };
    }
  }
  return cookie;
}

function normalizeBrowserProof(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("proof_must_be_an_object");
  }
  if (containsSensitiveField(raw)) {
    throw new Error("credential_or_cookie_fields_are_not_allowed");
  }
  if (raw.evidence_type !== "authenticated_browser_session") {
    throw new Error("unexpected_evidence_type");
  }
  if (raw.authorization_notice !== "explicit_local_lab") {
    throw new Error("explicit_lab_authorization_is_required");
  }
  if (
    raw.cookie_values_collected !== false ||
    raw.cookie_values_persisted !== false
  ) {
    throw new Error("cookie_values_must_not_be_collected_or_persisted");
  }
  if (
    !raw.session_probe ||
    typeof raw.session_probe !== "object" ||
    raw.session_probe.ok !== true ||
    raw.session_probe.status !== 200
  ) {
    throw new Error("a_successful_browser_session_probe_is_required");
  }

  const orgHost = text(raw.org_host, 255);
  const capturedAt = text(raw.captured_at, 64);
  const origin = text(raw.session_probe.origin, 512);
  if (!orgHost || !capturedAt || !origin) {
    throw new Error("proof_is_missing_required_metadata");
  }

  const visibleCookieNames = Array.isArray(raw.script_visible_cookie_names)
    ? [
        ...new Set(
          raw.script_visible_cookie_names
            .filter(
              (name) =>
                typeof name === "string" &&
                name.length > 0 &&
                name.length <= 256 &&
                !/[=;\r\n]/.test(name)
            )
            .map((name) => name.trim())
            .filter(Boolean)
        ),
      ].sort()
    : [];
  if (!Array.isArray(raw.cookies) || raw.cookies.length > 500) {
    throw new Error("redacted_cookie_inventory_is_required");
  }
  const cookies = raw.cookies
    .map((cookie) => normalizeRedactedCookie(cookie, orgHost))
    .sort((left, right) =>
      `${left.domain}\0${left.path}\0${left.name}`.localeCompare(
        `${right.domain}\0${right.path}\0${right.name}`
      )
    );
  const sessionActive = raw.browser_session_active === true;
  const allowedCaptureReasons = new Set([
    "initial_authentication",
    "browser_reauthentication",
    "reauthentication_or_session_rotation",
    "periodic_5_minutes",
    "manual_refresh",
    "browser_session_closed",
    "standalone_capture",
  ]);
  const captureReason = allowedCaptureReasons.has(raw.capture_reason)
    ? raw.capture_reason
    : "standalone_capture";

  return {
    evidence_version: 1,
    evidence_type: "authenticated_browser_session",
    authorization_notice: "explicit_local_lab",
    captured_at: capturedAt,
    org_host: orgHost,
    capture_reason: captureReason,
    browser_profile: sessionActive
      ? "temporary_isolated_profile_active"
      : "temporary_isolated_profile_deleted_after_capture",
    browser_session_active: sessionActive,
    cookie_values_collected: false,
    cookie_values_persisted: false,
    cookie_values_redacted_before_serialization: true,
    script_visible_cookie_names: visibleCookieNames,
    cookie_count: cookies.length,
    cookies,
    http_only_cookie_metadata_included: cookies.some(
      (cookie) => cookie.httpOnly
    ),
    session_probe: {
      ok: true,
      status: 200,
      origin,
      user_login: text(raw.session_probe.user_login, 320),
      user_id: text(raw.session_probe.user_id, 200),
    },
    note: sessionActive
      ? "Cookie metadata was exported as valid JSON from a live isolated browser session. Every cookie value was replaced with [REDACTED] before serialization; no raw value entered the proof collector."
      : "Cookie metadata was exported as valid JSON. Every cookie value was replaced with [REDACTED] before serialization; no raw value entered the proof collector, and the temporary browser profile was deleted after capture.",
  };
}

function normalizeOAuthProof(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("proof_must_be_an_object");
  }
  if (containsSensitiveField(raw)) {
    throw new Error("credential_or_cookie_fields_are_not_allowed");
  }
  if (Object.hasOwn(raw, "cookies")) {
    throw new Error("cookie_fields_are_not_allowed_in_oauth_proofs");
  }
  if (raw.evidence_type !== "oauth_bearer_reuse") {
    throw new Error("unexpected_evidence_type");
  }
  if (raw.authorization_notice !== "explicit_local_lab") {
    throw new Error("explicit_lab_authorization_is_required");
  }

  const fingerprint = text(raw.token_fingerprint_sha256, 64);
  const orgHost = text(raw.org_host, 255);
  const capturedAt = text(raw.captured_at, 64);
  const issuer = text(raw.issuer, 512);
  const clientId = text(raw.client_id_redacted, 220);
  const subject = text(raw.subject, 200);
  const scopes = Array.isArray(raw.granted_scopes)
    ? raw.granted_scopes
        .filter((scope) => typeof scope === "string")
        .map((scope) => scope.slice(0, 120))
        .slice(0, 20)
    : [];
  const attempts = Array.isArray(raw.reuse_attempts)
    ? raw.reuse_attempts
        .filter(
          (attempt) =>
            attempt &&
            typeof attempt === "object" &&
            Number.isInteger(attempt.sequence) &&
            Number.isInteger(attempt.status)
        )
        .slice(0, 2)
        .map((attempt) => ({
          sequence: attempt.sequence,
          status: attempt.status,
          subject: text(attempt.subject, 200),
        }))
    : [];
  if (
    !orgHost ||
    !capturedAt ||
    !issuer ||
    !clientId ||
    !subject ||
    !/^[a-f0-9]{64}$/.test(fingerprint || "") ||
    attempts.length !== 2 ||
    attempts.some(
      (attempt, index) =>
        attempt.sequence !== index + 1 ||
        attempt.status !== 200 ||
        attempt.subject !== subject
    )
  ) {
    throw new Error("oauth_proof_is_missing_or_has_invalid_metadata");
  }

  return {
    evidence_version: 1,
    evidence_type: "oauth_bearer_reuse",
    authorization_notice: "explicit_local_lab",
    captured_at: capturedAt,
    org_host: orgHost,
    issuer,
    client_id_redacted: clientId,
    granted_scopes: [...new Set(scopes)].sort(),
    expires_at: text(raw.expires_at, 64),
    subject,
    token_fingerprint_sha256: fingerprint,
    token_value_collected_by_collector: false,
    token_value_persisted_in_proof: false,
    reuse_attempts: attempts,
    note:
      "The same in-memory OAuth bearer token completed two read-only UserInfo requests. The collector received only its SHA-256 fingerprint.",
  };
}

function saveProof(proof, prefix) {
  const receivedAt = new Date().toISOString();
  const stamp = receivedAt.replace(/[:.]/g, "-");
  const fileName = `${prefix}${stamp}-${crypto.randomUUID()}.json`;
  const finalPath = path.join(outDir, fileName);
  const temporaryPath = path.join(outDir, `.${fileName}.tmp`);
  const record = { received_at: receivedAt, proof };

  fs.writeFileSync(temporaryPath, `${JSON.stringify(record, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  fs.renameSync(temporaryPath, finalPath);
  try {
    fs.chmodSync(finalPath, 0o600);
  } catch {
    // Windows relies on the current user profile ACL.
  }
  return { fileName, deletedOldCount: enforceRetention(prefix) };
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function sendDashboard(response) {
  const browserProof = latestProof(browserProofPrefix);
  const oauthProof = latestProof(oauthProofPrefix);
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Okta MCP Authorized Lab Proof</title>
<style>body{font:16px system-ui;max-width:56rem;margin:3rem auto;padding:0 1rem;color:#172033}section{border:1px solid #d9dde7;border-radius:8px;padding:1rem;margin:1rem 0}dt{font-weight:650}dd{margin:0 0 .8rem}code{background:#eef1f6;padding:.15rem .3rem;border-radius:4px}</style></head>
<body><h1>Authorized browser-session proof</h1>
<p>This loopback-only collector retains at most <strong>${maxRecords}</strong> redacted record(s) per proof type. It rejects cookie values and OAuth tokens.</p>
<h2>Browser-session evidence</h2>
<section><dl>
<dt>Organization</dt><dd>${escapeHtml(browserProof?.org_host || "No proof yet")}</dd>
<dt>Captured</dt><dd>${escapeHtml(browserProof?.captured_at || "")}</dd>
<dt>Capture reason</dt><dd>${escapeHtml(browserProof?.capture_reason || "")}</dd>
<dt>Browser session active at capture</dt><dd>${escapeHtml(browserProof?.browser_session_active === true)}</dd>
<dt>Profile state</dt><dd>${escapeHtml(browserProof?.browser_profile || "")}</dd>
<dt>Validated user</dt><dd>${escapeHtml(browserProof?.session_probe?.user_login || browserProof?.session_probe?.user_id || "")}</dd>
<dt>Probe</dt><dd>${browserProof ? `HTTP ${escapeHtml(browserProof.session_probe?.status)}` : ""}</dd>
<dt>Script-visible cookie names</dt><dd>${escapeHtml(browserProof?.script_visible_cookie_names?.join(", ") || "none")}</dd>
<dt>Browser cookie objects</dt><dd>${escapeHtml(browserProof?.cookie_count ?? 0)}</dd>
<dt>HttpOnly metadata included</dt><dd>${escapeHtml(browserProof?.http_only_cookie_metadata_included === true)}</dd>
<dt>Cookie values</dt><dd>Every value is <code>[REDACTED]</code></dd>
</dl></section>
<h2>OAuth bearer-reuse evidence</h2>
<section><dl>
<dt>Organization</dt><dd>${escapeHtml(oauthProof?.org_host || "No proof yet")}</dd>
<dt>Captured</dt><dd>${escapeHtml(oauthProof?.captured_at || "")}</dd>
<dt>Subject</dt><dd>${escapeHtml(oauthProof?.subject || "")}</dd>
<dt>Token fingerprint</dt><dd><code>${escapeHtml(oauthProof?.token_fingerprint_sha256 || "")}</code></dd>
<dt>Reuse results</dt><dd>${escapeHtml(oauthProof?.reuse_attempts?.map((attempt) => `#${attempt.sequence}: HTTP ${attempt.status}`).join(", ") || "")}</dd>
<dt>Token value</dt><dd>Not accepted or persisted by the collector</dd>
</dl></section>
<p><a href="/v1/cookie-proofs/latest">Browser proof</a> | <a href="/v1/oauth-token-proofs/latest">OAuth proof</a> | <a href="/health">Health</a></p>
</body></html>`;
  response.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(html);
}

const deletedLegacyAtStartup = deleteLegacyCookieArtifacts();
const deletedAtStartup =
  enforceRetention(browserProofPrefix) + enforceRetention(oauthProofPrefix);

const server = http.createServer((request, response) => {
  const requestUrl = new URL(request.url || "/", `http://${host}:${port}`);

  if (request.method === "GET" && requestUrl.pathname === "/") {
    sendDashboard(response);
    return;
  }
  if (request.method === "GET" && requestUrl.pathname === "/health") {
    sendJson(response, 200, {
      ok: true,
      service: "okta-mcp-redacted-lab-collector",
      collector_version: 2,
      live_browser_proofs: true,
      retained_browser_proofs: proofFiles(browserProofPrefix).length,
      retained_oauth_proofs: proofFiles(oauthProofPrefix).length,
      retention_limit: maxRecords,
      cookie_values_allowed: false,
    });
    return;
  }
  if (
    request.method === "GET" &&
    (requestUrl.pathname === "/v1/cookie-proofs" ||
      requestUrl.pathname === "/v1/cookie-proofs/latest")
  ) {
    const proof = latestProof(browserProofPrefix);
    sendJson(response, proof ? 200 : 404, proof || { error: "not_found" });
    return;
  }
  if (
    request.method === "GET" &&
    requestUrl.pathname === "/v1/cookie-proofs/history"
  ) {
    const records = history(browserProofPrefix);
    sendJson(response, 200, { count: records.length, records });
    return;
  }
  if (
    request.method === "GET" &&
    (requestUrl.pathname === "/v1/oauth-token-proofs" ||
      requestUrl.pathname === "/v1/oauth-token-proofs/latest")
  ) {
    const proof = latestProof(oauthProofPrefix);
    sendJson(response, proof ? 200 : 404, proof || { error: "not_found" });
    return;
  }
  if (
    request.method === "GET" &&
    requestUrl.pathname === "/v1/oauth-token-proofs/history"
  ) {
    const records = history(oauthProofPrefix);
    sendJson(response, 200, { count: records.length, records });
    return;
  }
  if (
    request.method !== "POST" ||
    (requestUrl.pathname !== "/v1/cookie-proofs" &&
      requestUrl.pathname !== "/v1/oauth-token-proofs")
  ) {
    sendJson(response, 404, { error: "not_found" });
    return;
  }

  let body = "";
  let tooLarge = false;
  request.setEncoding("utf8");
  request.on("data", (chunk) => {
    body += chunk;
    if (body.length > 64 * 1024) tooLarge = true;
  });
  request.on("end", () => {
    if (tooLarge) {
      sendJson(response, 413, { error: "proof_too_large" });
      return;
    }
    try {
      const raw = JSON.parse(body || "{}");
      const oauthRoute = requestUrl.pathname === "/v1/oauth-token-proofs";
      const proof = oauthRoute
        ? normalizeOAuthProof(raw)
        : normalizeBrowserProof(raw);
      const saved = saveProof(
        proof,
        oauthRoute ? oauthProofPrefix : browserProofPrefix
      );
      console.log(`[collector] saved ${saved.fileName}`);
      if (saved.deletedOldCount > 0) {
        console.log(
          `[collector] deleted ${saved.deletedOldCount} older proof record(s)`
        );
      }
      sendJson(response, 200, {
        ok: true,
        file_name: saved.fileName,
        deleted_old_count: saved.deletedOldCount,
        retained_count: proofFiles(
          oauthRoute ? oauthProofPrefix : browserProofPrefix
        ).length,
      });
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : "invalid_proof",
      });
    }
  });
});

server.listen(port, host, () => {
  console.log(
    `[collector] listening on http://${host}:${port}/v1/cookie-proofs`
  );
  console.log(
    `[collector] listening on http://${host}:${port}/v1/oauth-token-proofs`
  );
  console.log(`[collector] writing redacted proof records to ${outDir}`);
  console.log(`[collector] retention limit: ${maxRecords}`);
  if (deletedAtStartup > 0) {
    console.log(`[collector] deleted ${deletedAtStartup} old proof record(s)`);
  }
  if (deletedLegacyAtStartup > 0) {
    console.log(
      `[collector] deleted ${deletedLegacyAtStartup} legacy cookie artifact(s)`
    );
  }
});
