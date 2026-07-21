import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { nextBrowserProofReason } from "./lab-browser-session-proof.mjs";

const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), "okta-mcp-start-test-"));
const expectedTools = [
  "get-user",
  "list-apps",
  "list-groups",
  "list-users",
  "my-apps",
  "my-groups",
  "okta-browser-close",
  "okta-browser-navigate",
  "okta-browser-read",
  "okta-browser-refresh-proof",
  "okta-browser-session-proof",
  "okta-browser-snapshot",
  "okta-browser-status",
  "okta-oauth-login",
  "okta-oauth-reuse-proof",
  "okta-reset",
  "okta-start",
  "okta-status",
  "search-users",
  "token-details",
  "userinfo",
  "whoami",
].sort();

const proofNow = Date.parse("2026-07-20T12:00:00.000Z");
assert.equal(
  nextBrowserProofReason({
    lastAuthenticated: false,
    everAuthenticated: false,
    currentFingerprint: "first",
    now: proofNow,
  }),
  "initial_authentication"
);
assert.equal(
  nextBrowserProofReason({
    lastAuthenticated: false,
    everAuthenticated: true,
    currentFingerprint: "second",
    now: proofNow,
  }),
  "browser_reauthentication"
);
assert.equal(
  nextBrowserProofReason({
    lastAuthenticated: true,
    everAuthenticated: true,
    lastFingerprint: "first",
    currentFingerprint: "second",
    lastProofAt: new Date(proofNow - 31_000).toISOString(),
    now: proofNow,
  }),
  "reauthentication_or_session_rotation"
);
assert.equal(
  nextBrowserProofReason({
    lastAuthenticated: true,
    everAuthenticated: true,
    lastFingerprint: "same",
    currentFingerprint: "same",
    lastProofAt: new Date(proofNow - 5 * 60 * 1000).toISOString(),
    now: proofNow,
  }),
  "periodic_5_minutes"
);
assert.equal(
  nextBrowserProofReason({
    lastAuthenticated: true,
    everAuthenticated: true,
    lastFingerprint: "same",
    currentFingerprint: "same",
    lastProofAt: new Date(proofNow - (5 * 60 * 1000 - 1)).toISOString(),
    now: proofNow,
  }),
  null
);

function parseToolText(result) {
  const block = result.content?.find((item) => item.type === "text");
  assert.ok(block && typeof block.text === "string");
  return JSON.parse(block.text);
}

async function unusedPort() {
  const listener = net.createServer();
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const address = listener.address();
  assert.ok(address && typeof address !== "string");
  const port = address.port;
  await new Promise((resolve) => listener.close(resolve));
  return port;
}

async function withMcp(env, callback, configureClient) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["build/cli.js", "stdio"],
    cwd: process.cwd(),
    env,
    stderr: "pipe",
  });
  const stderr = [];
  transport.stderr?.on("data", (chunk) => stderr.push(chunk.toString()));
  const client = new Client(
    { name: "okta-start-smoke", version: "1.0.0" },
    configureClient
      ? { capabilities: { elicitation: { form: {} } } }
      : undefined
  );
  configureClient?.(client);
  try {
    await client.connect(transport);
    await callback(client, stderr);
  } finally {
    await client.close().catch(() => {});
  }
}

async function waitForHealth(url, child) {
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Collector exited early with code ${child.exitCode}.`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Collector is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Collector did not become healthy.");
}

async function stopProcess(child) {
  if (!child?.pid || child.exitCode !== null) return;
  const exited = new Promise((resolve) => {
    child.once("exit", resolve);
    setTimeout(resolve, 2_000).unref();
  });
  child.kill("SIGTERM");
  await exited;
}

try {
  const browserConfigDir = path.join(testRoot, "browser-config");
  const browserCollectorPort = await unusedPort();
  const browserEnv = {
    ...process.env,
    NODE_ENV: "test",
    OKTA_MCP_BROWSER_WORKER: "scripts/browser-session-worker-test.mjs",
    OKTA_MCP_CONFIG_DIR: browserConfigDir,
    OKTA_MCP_LAB_COLLECTOR: `http://127.0.0.1:${browserCollectorPort}`,
  };
  let browserElicitations = 0;
  const browserCollector = spawn(process.execPath, ["scripts/collector.mjs"], {
    cwd: process.cwd(),
    env: {
      ...browserEnv,
      OKTA_MCP_COLLECTOR_PORT: String(browserCollectorPort),
      OKTA_MCP_PROOF_RETENTION: "1",
      OKTA_MCP_COLLECTOR_OUTPUT_DIR: path.join(testRoot, "browser-collector"),
    },
    stdio: "ignore",
  });
  await waitForHealth(`http://127.0.0.1:${browserCollectorPort}/health`, browserCollector);

  try {
    await withMcp(browserEnv, async (client, stderr) => {
    const tools = await client.listTools();
    assert.deepEqual(
      tools.tools.map((tool) => tool.name).sort(),
      expectedTools
    );
    assert.match(client.getInstructions() || "", /call okta-start first/i);
    assert.match(client.getInstructions() || "", /Do not launch MCP Inspector/i);
    const status = parseToolText(
      await client.callTool({ name: "okta-status", arguments: {} })
    );
    assert.equal(status.configured, false);
    assert.equal(status.authentication_mode, null);

    const start = await client.callTool({
      name: "okta-start",
      arguments: { beginAuthentication: false },
    });
    assert.notEqual(start.isError, true);
    const started = parseToolText(start);
    assert.equal(started.authentication_mode, "browser");
    assert.equal(started.authentication_started, false);

    const restarted = parseToolText(
      await client.callTool({
        name: "okta-start",
        arguments: { beginAuthentication: false },
      })
    );
    assert.equal(restarted.authentication_mode, "browser");
    assert.equal(restarted.configuration_reused, true);
    assert.equal(browserElicitations, 1);

    const live = parseToolText(
      await client.callTool({ name: "okta-start", arguments: {} })
    );
    assert.equal(live.browser_session_active, true);
    assert.equal(live.browser_session.status, "authenticated");

    const browserStatus = parseToolText(
      await client.callTool({ name: "okta-browser-status", arguments: {} })
    );
    assert.equal(browserStatus.active, true);
    assert.equal(browserStatus.browser_session.cookie_values_exposed, false);

    const snapshot = parseToolText(
      await client.callTool({ name: "okta-browser-snapshot", arguments: {} })
    );
    assert.equal(snapshot.title, "Okta Dashboard");
    assert.doesNotMatch(JSON.stringify(snapshot), /cookie|bearer|token/i);

    const navigated = parseToolText(
      await client.callTool({
        name: "okta-browser-navigate",
        arguments: { url: "/admin/users" },
      })
    );
    assert.equal(navigated.current_url, "https://authorized-browser.invalid/admin/users");

    const crossOrigin = await client.callTool({
      name: "okta-browser-navigate",
      arguments: { url: "https://example.invalid/" },
    });
    assert.equal(crossOrigin.isError, true);

    const read = parseToolText(
      await client.callTool({
        name: "okta-browser-read",
        arguments: { path: "/api/v1/users?limit=1" },
      })
    );
    assert.equal(read.method, "GET");
    assert.equal(read.cookie_values_exposed, false);

    const nonApiRead = await client.callTool({
      name: "okta-browser-read",
      arguments: { path: "/oauth2/v1/authorize" },
    });
    assert.equal(nonApiRead.isError, true);

    const refreshed = parseToolText(
      await client.callTool({ name: "okta-browser-refresh-proof", arguments: {} })
    );
    assert.equal(refreshed.reason, "manual_refresh");
    assert.equal(refreshed.cookie_values_exposed, false);

    const reset = parseToolText(
      await client.callTool({
        name: "okta-reset",
        arguments: { confirm: true },
      })
    );
    assert.equal(reset.reset, true);
    assert.equal(reset.browser_session_closed, true);
    assert.equal(reset.next_start_requires_configuration, true);
    assert.equal(fs.existsSync(path.join(browserConfigDir, "startup.json")), false);

    const resetStatus = parseToolText(
      await client.callTool({ name: "okta-status", arguments: {} })
    );
    assert.equal(resetStatus.configured, false);
    assert.equal(resetStatus.browser_session_active, false);

    const configuredAgain = parseToolText(
      await client.callTool({
        name: "okta-start",
        arguments: { beginAuthentication: false },
      })
    );
    assert.equal(configuredAgain.configuration_reused, false);
    assert.equal(browserElicitations, 2);
    assert.equal(stderr.join(""), "");
    }, (client) => {
      client.setRequestHandler(ElicitRequestSchema, (request) => {
      browserElicitations += 1;
      assert.equal(request.params.mode, "form");
      assert.ok(request.params.requestedSchema.properties.authenticationMode);
      assert.equal(request.params.requestedSchema.properties.authorized, undefined);
      assert.match(request.params.message, /selecting Continue.*authorized/i);
      return {
        action: "accept",
        content: {
          authenticationMode: "browser",
          orgUrl: "https://authorized-browser.invalid",
          tenantConfirmation: "https://authorized-browser.invalid/",
        },
      };
      });
    });
  } finally {
    await stopProcess(browserCollector);
  }

  const savedBrowserStart = JSON.parse(
    fs.readFileSync(path.join(browserConfigDir, "startup.json"), "utf8")
  );
  assert.equal(savedBrowserStart.authenticationMode, "browser");
  assert.equal(savedBrowserStart.orgUrl, "https://authorized-browser.invalid");
  assert.equal(fs.existsSync(path.join(browserConfigDir, "config.json")), false);

  const oauthPort = await unusedPort();
  const oauthIssuer = `http://127.0.0.1:${oauthPort}`;
  const dummyToken = "authorized-lab-dummy-bearer-not-a-real-credential";
  const authorizationHeaders = [];
  const oidc = http.createServer((request, response) => {
    const url = new URL(request.url || "/", oauthIssuer);
    if (url.pathname === "/.well-known/openid-configuration") {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(
        JSON.stringify({
          issuer: oauthIssuer,
          authorization_endpoint: `${oauthIssuer}/authorize`,
          token_endpoint: `${oauthIssuer}/token`,
          userinfo_endpoint: `${oauthIssuer}/userinfo`,
          jwks_uri: `${oauthIssuer}/jwks`,
          id_token_signing_alg_values_supported: ["RS256"],
        })
      );
      return;
    }
    if (url.pathname === "/userinfo") {
      authorizationHeaders.push(request.headers.authorization);
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ sub: "00u-authorized-lab" }));
      return;
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise((resolve) => oidc.listen(oauthPort, "127.0.0.1", resolve));

  const oauthConfigDir = path.join(testRoot, "oauth-config");
  const collectorOutput = path.join(testRoot, "collector-output");
  const collectorPort = await unusedPort();
  const collector = spawn(process.execPath, ["scripts/collector.mjs"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      OKTA_MCP_COLLECTOR_HOST: "127.0.0.1",
      OKTA_MCP_COLLECTOR_PORT: String(collectorPort),
      OKTA_MCP_COLLECTOR_OUTPUT_DIR: collectorOutput,
      OKTA_MCP_PROOF_RETENTION: "1",
    },
    stdio: "ignore",
    windowsHide: true,
  });

  try {
    await waitForHealth(`http://127.0.0.1:${collectorPort}/health`, collector);
    const oauthEnv = {
      ...process.env,
      OKTA_MCP_CONFIG_DIR: oauthConfigDir,
      OKTA_MCP_ALLOW_INSECURE_HTTP: "1",
      OKTA_MCP_LAB_COLLECTOR: `http://127.0.0.1:${collectorPort}`,
    };
    await withMcp(oauthEnv, async (client) => {
      const setup = await client.callTool({
        name: "okta-start",
        arguments: {
          authenticationMode: "oidc",
          orgUrl: oauthIssuer,
          tenantConfirmation: `127.0.0.1:${oauthPort}`,
          authorized: true,
          clientId: "authorized-lab-client",
          authServer: "org",
          scopes: "openid profile email offline_access",
          callbackHost: "127.0.0.1",
          callbackPort: await unusedPort(),
          beginAuthentication: false,
        },
      });
      assert.notEqual(setup.isError, true, JSON.stringify(parseToolText(setup)));
      assert.equal(parseToolText(setup).authentication_mode, "oidc");

      fs.writeFileSync(
        path.join(oauthConfigDir, "tokens.json"),
        JSON.stringify({
          context: {
            orgUrl: oauthIssuer,
            clientId: "authorized-lab-client",
            authServerId: "org",
            scopes: "openid profile email offline_access",
          },
          tokens: {
            access_token: dummyToken,
            token_type: "Bearer",
            expires_in: 3600,
            scope: "openid profile email offline_access",
            obtained_at: Date.now(),
          },
        })
      );

      const result = await client.callTool({
        name: "okta-oauth-reuse-proof",
        arguments: {
          authorized: true,
          tenantConfirmation: `127.0.0.1:${oauthPort}`,
        },
      });
      const proofResult = parseToolText(result);
      assert.notEqual(result.isError, true, JSON.stringify(proofResult));
      const expectedFingerprint = crypto
        .createHash("sha256")
        .update(dummyToken)
        .digest("hex");
      assert.equal(proofResult.token_fingerprint_sha256, expectedFingerprint);
      assert.equal(proofResult.raw_token_returned, false);
      assert.equal(proofResult.raw_token_sent_to_collector, false);
      assert.deepEqual(authorizationHeaders, [
        `Bearer ${dummyToken}`,
        `Bearer ${dummyToken}`,
      ]);

      const storedResponse = await fetch(
        `http://127.0.0.1:${collectorPort}/v1/oauth-token-proofs/latest`
      );
      const storedText = await storedResponse.text();
      assert.equal(storedResponse.status, 200);
      assert.equal(storedText.includes(dummyToken), false);
      assert.equal(storedText.includes(expectedFingerprint), true);

      const reset = parseToolText(
        await client.callTool({
          name: "okta-reset",
          arguments: { confirm: true },
        })
      );
      assert.equal(reset.reset, true);
      assert.equal(reset.local_oauth_cache_removed, true);
      assert.equal(reset.next_start_requires_configuration, true);
      assert.equal(fs.existsSync(path.join(oauthConfigDir, "startup.json")), false);
      assert.equal(fs.existsSync(path.join(oauthConfigDir, "config.json")), false);
      assert.equal(fs.existsSync(path.join(oauthConfigDir, "tokens.json")), false);
    });
  } finally {
    await stopProcess(collector);
    await new Promise((resolve) => oidc.close(resolve));
  }

  console.log(
    "Unified Okta MCP smoke test passed: form-based mode selection, fresh-state reset, browser-only configuration, OIDC configuration, two-use token proof, and raw-token exclusion."
  );
} finally {
  fs.rmSync(testRoot, { recursive: true, force: true });
}
