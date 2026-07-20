import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Could not allocate a test port."));
        return;
      }
      server.close(() => resolve(address.port));
    });
  });
}

async function stopProcess(child) {
  if (!child?.pid) return;
  const exited =
    child.exitCode !== null
      ? Promise.resolve()
      : new Promise((resolve) => {
          child.once("exit", resolve);
          setTimeout(resolve, 2_000).unref();
        });
  try {
    child.kill("SIGTERM");
  } catch {
    // Process already stopped.
  }
  await exited;
  child.unref();
}

async function waitForHealth(url, child) {
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Collector exited early with code ${child.exitCode}.`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) return response.json();
    } catch {
      // Collector is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Collector did not become healthy.");
}

function proof(userId, login) {
  return {
    evidence_version: 1,
    evidence_type: "authenticated_browser_session",
    authorization_notice: "explicit_local_lab",
    captured_at: new Date().toISOString(),
    org_host: "authorized-lab.example.test",
    browser_profile: "temporary_isolated_profile",
    cookie_values_collected: false,
    cookie_values_persisted: false,
    cookie_values_redacted_before_serialization: true,
    script_visible_cookie_names: ["oktaStateToken", "deviceFingerprint"],
    cookie_count: 2,
    cookies: [
      {
        name: "sid",
        value: "[REDACTED]",
        domain: ".example.test",
        path: "/",
        expires: -1,
        size: 128,
        httpOnly: true,
        secure: true,
        session: true,
        sameSite: "None",
        priority: "Medium",
        sourceScheme: "Secure",
        sourcePort: 443,
      },
      {
        name: "okta_user_lang",
        value: "[REDACTED]",
        domain: "authorized-lab.example.test",
        path: "/",
        expires: 2_000_000_000,
        size: 24,
        httpOnly: false,
        secure: true,
        session: false,
        sameSite: "Lax",
      },
    ],
    http_only_cookie_metadata_included: true,
    session_probe: {
      ok: true,
      status: 200,
      origin: "https://authorized-lab.example.test",
      user_id: userId,
      user_login: login,
    },
  };
}

function oauthProof(subject, fingerprint) {
  return {
    evidence_version: 1,
    evidence_type: "oauth_bearer_reuse",
    authorization_notice: "explicit_local_lab",
    captured_at: new Date().toISOString(),
    org_host: "authorized-lab.example.test",
    issuer: "https://authorized-lab.example.test",
    client_id_redacted: "0oa123...xy",
    granted_scopes: ["openid", "profile"],
    expires_at: new Date(Date.now() + 3_600_000).toISOString(),
    subject,
    token_fingerprint_sha256: fingerprint,
    reuse_attempts: [
      { sequence: 1, status: 200, subject },
      { sequence: 2, status: 200, subject },
    ],
  };
}

async function post(endpoint, body) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() };
}

const port = await freePort();
const outputDir = fs.mkdtempSync(
  path.join(os.tmpdir(), "okta-redacted-collector-test-")
);
const legacyArtifact = path.join(outputDir, "cookie-proof-legacy.json");
fs.writeFileSync(
  legacyArtifact,
  JSON.stringify({ cookies: [{ name: "sid", value: "legacy-replayable" }] })
);
const endpoint = `http://127.0.0.1:${port}/v1/cookie-proofs`;
const child = spawn(process.execPath, ["scripts/collector.mjs"], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    OKTA_MCP_COLLECTOR_HOST: "127.0.0.1",
    OKTA_MCP_COLLECTOR_PORT: String(port),
    OKTA_MCP_COLLECTOR_OUTPUT_DIR: outputDir,
    OKTA_MCP_PROOF_RETENTION: "1",
  },
  stdio: "ignore",
  windowsHide: true,
});

try {
  const health = await waitForHealth(`http://127.0.0.1:${port}/health`, child);
  assert.equal(health.service, "okta-mcp-redacted-lab-collector");
  assert.equal(health.collector_version, 2);
  assert.equal(health.live_browser_proofs, true);
  assert.equal(health.cookie_values_allowed, false);
  assert.equal(health.retention_limit, 1);
  assert.equal(fs.existsSync(legacyArtifact), false);

  const unsafe = await post(endpoint, {
    ...proof("unsafe", "unsafe@example.test"),
    cookies: [{ name: "sid", value: "replayable" }],
  });
  assert.equal(unsafe.response.status, 400);
  assert.equal(
    unsafe.body.error,
    "credential_or_cookie_fields_are_not_allowed"
  );

  const first = await post(endpoint, proof("first", "first@example.test"));
  assert.equal(first.response.status, 200);
  assert.equal(first.body.retained_count, 1);
  assert.equal(first.body.deleted_old_count, 0);

  await new Promise((resolve) => setTimeout(resolve, 20));
  const liveProof = {
    ...proof("second", "second@example.test"),
    capture_reason: "periodic_5_minutes",
    browser_profile: "temporary_isolated_profile_active",
    browser_session_active: true,
  };
  const second = await post(endpoint, liveProof);
  assert.equal(second.response.status, 200);
  assert.equal(second.body.retained_count, 1);
  assert.equal(second.body.deleted_old_count, 1);

  const latestResponse = await fetch(`${endpoint}/latest`);
  assert.equal(latestResponse.status, 200);
  const latest = await latestResponse.json();
  assert.equal(latest.session_probe.user_id, "second");
  assert.equal(latest.cookie_values_collected, false);
  assert.equal(latest.cookie_values_persisted, false);
  assert.equal(latest.capture_reason, "periodic_5_minutes");
  assert.equal(latest.browser_profile, "temporary_isolated_profile_active");
  assert.equal(latest.browser_session_active, true);
  assert.deepEqual(latest.script_visible_cookie_names, [
    "deviceFingerprint",
    "oktaStateToken",
  ]);
  assert.equal(latest.cookie_count, 2);
  assert.equal(latest.http_only_cookie_metadata_included, true);
  assert.equal(latest.cookies[0].value, "[REDACTED]");
  assert.equal(latest.cookies[1].value, "[REDACTED]");
  assert.equal(latest.cookies.some((cookie) => cookie.httpOnly), true);
  assert.equal(JSON.stringify(latest).includes("replayable"), false);

  const oauthEndpoint = `http://127.0.0.1:${port}/v1/oauth-token-proofs`;
  const unsafeOauth = await post(oauthEndpoint, {
    ...oauthProof("00u-unsafe", "a".repeat(64)),
    access_token: "replayable-token",
  });
  assert.equal(unsafeOauth.response.status, 400);
  assert.equal(
    unsafeOauth.body.error,
    "credential_or_cookie_fields_are_not_allowed"
  );

  const oauth = await post(
    oauthEndpoint,
    oauthProof("00u-safe", "b".repeat(64))
  );
  assert.equal(oauth.response.status, 200);
  assert.equal(oauth.body.retained_count, 1);
  const latestOauthResponse = await fetch(`${oauthEndpoint}/latest`);
  assert.equal(latestOauthResponse.status, 200);
  const latestOauth = await latestOauthResponse.json();
  assert.equal(latestOauth.subject, "00u-safe");
  assert.equal(latestOauth.token_fingerprint_sha256, "b".repeat(64));
  assert.equal(JSON.stringify(latestOauth).includes("replayable-token"), false);

  const files = fs
    .readdirSync(outputDir)
    .filter((fileName) => fileName.endsWith(".json"));
  assert.equal(files.length, 2);

  console.log(
    "Redacted collector test passed: browser metadata, OAuth fingerprint evidence, credential rejection, and per-type retention."
  );
} finally {
  await stopProcess(child);
  fs.rmSync(outputDir, { recursive: true, force: true });
}
