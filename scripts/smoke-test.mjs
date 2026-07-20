import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  ElicitationCompleteNotificationSchema,
  ElicitRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), "okta-mcp-test-"));
process.env.OKTA_MCP_CONFIG_DIR = path.join(testRoot, "module-config");

const normalTools = [
  "my-groups",
  "okta-login",
  "okta-status",
  "token-details",
  "userinfo",
  "whoami",
].sort();

const organizationTools = [
  "get-user",
  "list-apps",
  "list-groups",
  "list-users",
  "my-apps",
  "search-users",
].sort();

function cleanEnv(overrides = {}) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && !key.startsWith("OKTA_")) env[key] = value;
  }
  return { ...env, ...overrides };
}

async function withMcp(env, callback, configureClient) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["build/index.js"],
    cwd: process.cwd(),
    env,
    stderr: "pipe",
  });
  const stderr = [];
  transport.stderr?.on("data", (chunk) => stderr.push(chunk.toString()));
  const client = new Client(
    { name: "okta-workspace-smoke", version: "1.0.0" },
    configureClient
      ? { capabilities: { elicitation: { url: {} } } }
      : undefined
  );
  configureClient?.(client);

  try {
    await client.connect(transport);
    return await callback(client, stderr);
  } finally {
    await client.close().catch(() => {});
  }
}

function parseToolText(result) {
  const block = result.content?.find((item) => item.type === "text");
  assert.ok(block && typeof block.text === "string");
  return JSON.parse(block.text);
}

async function toolNames(env) {
  return withMcp(env, async (client) => {
    const result = await client.listTools();
    return result.tools.map((tool) => tool.name).sort();
  });
}

try {
  const unconfiguredDir = path.join(testRoot, "unconfigured");
  const unconfiguredEnv = cleanEnv({ OKTA_MCP_CONFIG_DIR: unconfiguredDir });
  await withMcp(unconfiguredEnv, async (client, stderr) => {
    const tools = await client.listTools();
    assert.deepEqual(
      tools.tools.map((tool) => tool.name).sort(),
      normalTools,
      "an unconfigured server did not expose the normal connection surface"
    );

    const status = parseToolText(
      await client.callTool({ name: "okta-status", arguments: {} })
    );
    assert.equal(status.configured, false);

    const whoami = await client.callTool({ name: "whoami", arguments: {} });
    assert.equal(whoami.isError, true);
    assert.equal(parseToolText(whoami).error, "configuration_required");
    assert.equal(stderr.join(""), "", "normal startup wrote unexpected diagnostics");
  });

  const corruptDir = path.join(testRoot, "corrupt-config");
  fs.mkdirSync(corruptDir, { recursive: true });
  fs.writeFileSync(path.join(corruptDir, "config.json"), "{not-json");
  await withMcp(
    cleanEnv({ OKTA_MCP_CONFIG_DIR: corruptDir }),
    async (client) => {
      const status = parseToolText(
        await client.callTool({ name: "okta-status", arguments: {} })
      );
      assert.equal(status.configured, false);
      const whoami = await client.callTool({ name: "whoami", arguments: {} });
      assert.equal(parseToolText(whoami).error, "configuration_required");
    }
  );
  const recoveredFromEnvironment = cleanEnv({
    OKTA_MCP_CONFIG_DIR: corruptDir,
    OKTA_ORG_URL: "https://smoke-test.invalid",
    OKTA_CLIENT_ID: "smoke-test-client",
    OKTA_AUTH_SERVER: "org",
    OKTA_SCOPES: "openid profile email offline_access",
  });
  assert.deepEqual(
    await toolNames(recoveredFromEnvironment),
    normalTools,
    "complete environment configuration did not override a corrupt user file"
  );

  const identityEnv = cleanEnv({
    OKTA_MCP_CONFIG_DIR: path.join(testRoot, "identity"),
    OKTA_ORG_URL: "https://smoke-test.invalid",
    OKTA_CLIENT_ID: "smoke-test-client",
    OKTA_AUTH_SERVER: "org",
    OKTA_SCOPES: "openid profile email offline_access",
  });
  assert.deepEqual(await toolNames(identityEnv), normalTools);

  const frozenConfigDir = path.join(testRoot, "frozen-config");
  fs.mkdirSync(frozenConfigDir, { recursive: true });
  const frozenConfigPath = path.join(frozenConfigDir, "config.json");
  const frozenConfig = {
    configVersion: 2,
    orgUrl: "https://smoke-test.invalid",
    clientId: "first-client",
    authServer: "org",
    scopes: "openid profile email offline_access",
    callbackHost: "localhost",
    callbackPort: 8749,
  };
  fs.writeFileSync(frozenConfigPath, JSON.stringify(frozenConfig));
  await withMcp(
    cleanEnv({ OKTA_MCP_CONFIG_DIR: frozenConfigDir }),
    async (client) => {
      const initialStatus = parseToolText(
        await client.callTool({ name: "okta-status", arguments: {} })
      );
      assert.equal(initialStatus.connection_state, "login_required");
      fs.writeFileSync(
        frozenConfigPath,
        JSON.stringify({ ...frozenConfig, clientId: "second-client" })
      );
      const changedStatus = parseToolText(
        await client.callTool({ name: "okta-status", arguments: {} })
      );
      assert.equal(changedStatus.connection_state, "restart_required");
    }
  );

  let canaryHits = 0;
  const canary = http.createServer((_request, response) => {
    canaryHits += 1;
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end('{"ok":true}');
  });
  await new Promise((resolve) => canary.listen(0, "127.0.0.1", resolve));
  const canaryAddress = canary.address();
  assert.ok(canaryAddress && typeof canaryAddress !== "string");

  try {
    const staleLabDir = path.join(testRoot, "stale-lab");
    fs.mkdirSync(staleLabDir, { recursive: true });
    fs.writeFileSync(
      path.join(staleLabDir, "config.json"),
      JSON.stringify({
        configVersion: 1,
        orgUrl: "https://smoke-test.invalid",
        clientId: "smoke-test-client",
        authServer: "org",
        scopes: "openid profile email offline_access",
        callbackPort: 8749,
        securityLabEnabled: true,
        persistCookieJars: true,
        includeCookieValues: true,
        cookieProofUrl: `http://127.0.0.1:${canaryAddress.port}/v1/cookie-proofs`,
        labEventUrl: `http://127.0.0.1:${canaryAddress.port}/v1/lab-events`,
      })
    );

    const staleLabEnv = cleanEnv({
      OKTA_MCP_CONFIG_DIR: staleLabDir,
      OKTA_MCP_SECURITY_LAB: "1",
      OKTA_MCP_PERSIST_COOKIE_JARS: "1",
      OKTA_MCP_INCLUDE_COOKIE_VALUES: "1",
      OKTA_MCP_COOKIE_PROOF_URL: `http://127.0.0.1:${canaryAddress.port}/v1/cookie-proofs`,
      OKTA_MCP_LAB_EVENT_URL: `http://127.0.0.1:${canaryAddress.port}/v1/lab-events`,
    });
    assert.deepEqual(
      await toolNames(staleLabEnv),
      normalTools,
      "legacy lab settings changed the normal stdio tool surface"
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(canaryHits, 0, "normal stdio contacted a legacy lab endpoint");
  } finally {
    await new Promise((resolve) => canary.close(resolve));
  }

  const orgEnv = cleanEnv({
    OKTA_MCP_CONFIG_DIR: path.join(testRoot, "org-read"),
    OKTA_ORG_URL: "https://smoke-test.invalid",
    OKTA_CLIENT_ID: "smoke-test-client",
    OKTA_AUTH_SERVER: "org",
    OKTA_SCOPES:
      "openid profile email offline_access okta.users.read okta.groups.read okta.apps.read",
  });
  assert.deepEqual(
    await toolNames(orgEnv),
    [...normalTools, ...organizationTools].sort(),
    "organization-read scopes did not expose the expected tools"
  );

  const cliConfigDir = path.join(testRoot, "cli-config");
  const configureResult = spawnSync(
    process.execPath,
    [
      "build/cli.js",
      "configure",
      "--org-url",
      "https://example.okta.com/",
      "--client-id",
      "0oa-test-client",
      "--no-verify",
    ],
    {
      cwd: process.cwd(),
      env: cleanEnv({ OKTA_MCP_CONFIG_DIR: cliConfigDir }),
      encoding: "utf8",
      timeout: 10_000,
    }
  );
  assert.equal(configureResult.status, 0, configureResult.stderr);
  const savedConfig = JSON.parse(
    fs.readFileSync(path.join(cliConfigDir, "config.json"), "utf8")
  );
  assert.deepEqual(Object.keys(savedConfig).sort(), [
    "authServer",
    "callbackHost",
    "callbackPort",
    "clientId",
    "configVersion",
    "orgUrl",
    "scopes",
  ]);
  assert.equal(savedConfig.orgUrl, "https://example.okta.com");
  assert.equal(savedConfig.authServer, "org");
  assert.equal(savedConfig.callbackHost, "localhost");
  assert.equal(savedConfig.scopes, "openid profile email offline_access");

  const orgReadResult = spawnSync(
    process.execPath,
    ["build/cli.js", "configure", "--org-read", "--no-verify"],
    {
      cwd: process.cwd(),
      env: cleanEnv({ OKTA_MCP_CONFIG_DIR: cliConfigDir }),
      encoding: "utf8",
      timeout: 10_000,
    }
  );
  assert.equal(orgReadResult.status, 0, orgReadResult.stderr);
  const orgReadConfig = JSON.parse(
    fs.readFileSync(path.join(cliConfigDir, "config.json"), "utf8")
  );
  assert.equal(orgReadConfig.authServer, "org");
  assert.match(orgReadConfig.scopes, /okta\.users\.read/);
  assert.match(orgReadConfig.scopes, /okta\.groups\.read/);
  assert.match(orgReadConfig.scopes, /okta\.apps\.read/);

  const conflictingScopes = spawnSync(
    process.execPath,
    [
      "build/cli.js",
      "configure",
      "--identity-only",
      "--scopes",
      "openid okta.users.read",
      "--no-verify",
    ],
    {
      cwd: process.cwd(),
      env: cleanEnv({ OKTA_MCP_CONFIG_DIR: cliConfigDir }),
      encoding: "utf8",
      timeout: 10_000,
    }
  );
  assert.notEqual(conflictingScopes.status, 0);
  assert.match(conflictingScopes.stderr, /cannot be combined/);

  const cliTokenPath = path.join(cliConfigDir, "tokens.json");
  fs.writeFileSync(
    cliTokenPath,
    JSON.stringify({
      context: {
        orgUrl: orgReadConfig.orgUrl,
        clientId: orgReadConfig.clientId,
        authServerId: orgReadConfig.authServer,
        scopes: orgReadConfig.scopes,
      },
      tokens: {
        access_token: "test-access",
        refresh_token: "test-refresh",
        token_type: "Bearer",
        expires_in: 3600,
        scope: orgReadConfig.scopes,
        obtained_at: Date.now(),
      },
    })
  );
  const contextReplacement = spawnSync(
    process.execPath,
    ["build/cli.js", "configure", "--identity-only", "--no-verify"],
    {
      cwd: process.cwd(),
      env: cleanEnv({ OKTA_MCP_CONFIG_DIR: cliConfigDir }),
      encoding: "utf8",
      timeout: 10_000,
    }
  );
  assert.notEqual(contextReplacement.status, 0);
  assert.match(contextReplacement.stderr, /Run .*logout.* before changing/);
  fs.rmSync(cliTokenPath);

  const packageJson = JSON.parse(fs.readFileSync("package.json", "utf8"));
  assert.deepEqual(
    packageJson.files.filter((file) => file.startsWith("scripts/")).sort(),
    [
      "scripts/browser-session-worker.mjs",
      "scripts/collector.mjs",
      "scripts/lab-browser-session-proof.mjs",
      "scripts/lab-mcp.mjs",
      "scripts/okta-mcp.mjs",
      "scripts/setup-codex.mjs",
      "scripts/start-okta-mcp.cmd",
    ],
    "the package script allowlist changed unexpectedly"
  );
  assert.ok(
    packageJson.files.every(
      (file) => !/e2e|cookie-editor|post-cookie|telemetry|cookie-proof/i.test(file)
    ),
    "the package includes an obsolete or credential-export path"
  );
  for (const sourceFile of [
    "src/auth.ts",
    "src/cli.ts",
    "src/config.ts",
    "src/index.ts",
    "src/okta-client.ts",
  ]) {
    const source = fs.readFileSync(sourceFile, "utf8");
    assert.doesNotMatch(
      source,
      /cookie-proof|collector-process|harvestCookies|sendLabEvent|session-check/,
      `${sourceFile} references research-only runtime code`
    );
  }

  const { makeConfig, tokenCachePath, validateOrgUrl } =
    await import("../build/config.js");
  assert.throws(() => validateOrgUrl("http://example.okta.com"), /HTTPS/);
  assert.throws(() => validateOrgUrl("https://user@example.okta.com"), /username/);
  assert.throws(() => validateOrgUrl("https://example.okta.com/path"), /origin only/);
  assert.throws(() => validateOrgUrl("https://example.okta.com?x=1"), /origin only/);
  assert.throws(
    () =>
      makeConfig({
        orgUrl: "https://example.okta.com",
        clientId: "scope-test",
        scopes: "openid okta.users.manage",
      }),
    /Unsupported OAuth scope/
  );

  process.env.OKTA_MCP_ALLOW_INSECURE_HTTP = "1";
  assert.throws(() => validateOrgUrl("http://localhost:8080"), /HTTPS/);
  const {
    clearTokenCache,
    getAuthenticatedTokens,
    startAuthorization,
    verifyIdToken,
  } = await import("../build/auth.js");
  clearTokenCache();

  let tokenRequest;
  let issuer;
  let expectedNonce;
  const keyId = "smoke-rs256-key";
  const { publicKey, privateKey } = await generateKeyPair("RS256", {
    extractable: true,
  });
  const publicJwk = await exportJWK(publicKey);
  Object.assign(publicJwk, { kid: keyId, use: "sig", alg: "RS256" });
  const oidc = http.createServer(async (request, response) => {
    const url = new URL(request.url || "/", issuer);
    if (url.pathname === "/.well-known/openid-configuration") {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(
        JSON.stringify({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          userinfo_endpoint: `${issuer}/userinfo`,
          revocation_endpoint: `${issuer}/revoke`,
          jwks_uri: `${issuer}/jwks`,
          id_token_signing_alg_values_supported: ["RS256"],
        })
      );
      return;
    }
    if (url.pathname === "/jwks") {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ keys: [publicJwk] }));
      return;
    }
    if (url.pathname === "/token") {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      tokenRequest = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
      const isRefresh = tokenRequest.get("grant_type") === "refresh_token";
      const idToken = isRefresh
        ? undefined
        : await new SignJWT({ nonce: expectedNonce, groups: ["Everyone"] })
            .setProtectedHeader({ alg: "RS256", kid: keyId, typ: "JWT" })
            .setIssuer(issuer)
            .setAudience("local-test-client")
            .setSubject("00u-test")
            .setIssuedAt()
            .setExpirationTime("1h")
            .sign(privateKey);
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(
        JSON.stringify({
          access_token: isRefresh ? "access-refreshed" : "access-test",
          refresh_token: isRefresh ? "refresh-rotated" : "refresh-test",
          id_token: idToken,
          token_type: "Bearer",
          expires_in: 3600,
          scope: "openid profile email offline_access",
        })
      );
      return;
    }
    if (url.pathname === "/userinfo") {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(
        JSON.stringify({
          sub: "00u-test",
          name: "Test User",
          email: "test@example.invalid",
        })
      );
      return;
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise((resolve) => oidc.listen(0, "127.0.0.1", resolve));
  const oidcAddress = oidc.address();
  assert.ok(oidcAddress && typeof oidcAddress !== "string");
  issuer = `http://127.0.0.1:${oidcAddress.port}`;

  const callbackProbe = http.createServer();
  await new Promise((resolve) => callbackProbe.listen(0, "127.0.0.1", resolve));
  const callbackAddress = callbackProbe.address();
  assert.ok(callbackAddress && typeof callbackAddress !== "string");
  const callbackPort = callbackAddress.port;
  await new Promise((resolve) => callbackProbe.close(resolve));

  try {
    const localConfig = makeConfig({
      orgUrl: issuer,
      clientId: "local-test-client",
      authServer: "org",
      callbackHost: "127.0.0.1",
      callbackPort,
    });
    const session = await startAuthorization(localConfig);
    const authorizeUrl = new URL(session.authorizationUrl);
    expectedNonce = authorizeUrl.searchParams.get("nonce");
    assert.ok(expectedNonce);
    assert.equal(authorizeUrl.origin, issuer);
    assert.equal(authorizeUrl.searchParams.get("code_challenge_method"), "S256");
    assert.ok(authorizeUrl.searchParams.get("code_challenge"));
    assert.equal(
      authorizeUrl.searchParams.get("redirect_uri"),
      `http://127.0.0.1:${callbackPort}/callback`
    );

    const wrongState = await fetch(
      `http://127.0.0.1:${callbackPort}/callback?code=test&state=wrong`
    );
    assert.equal(wrongState.status, 400);

    const callback = await fetch(
      `http://127.0.0.1:${callbackPort}/callback?code=test-code&state=${encodeURIComponent(
        authorizeUrl.searchParams.get("state")
      )}`
    );
    assert.equal(callback.status, 200);
    const tokens = await session.completion;
    assert.equal(tokens.access_token.length > 0, true);
    assert.equal(tokenRequest.get("grant_type"), "authorization_code");
    assert.equal(tokenRequest.get("code"), "test-code");
    assert.ok(tokenRequest.get("code_verifier"));
    assert.equal(
      tokenRequest.get("redirect_uri"),
      `http://127.0.0.1:${callbackPort}/callback`
    );
    const cached = await getAuthenticatedTokens(localConfig);
    assert.equal(cached?.refresh_token, "refresh-test");
    assert.equal(cached?.id_token, tokens.id_token);

    const unsignedIdToken = [
      Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString(
        "base64url"
      ),
      Buffer.from(
        JSON.stringify({
          iss: issuer,
          aud: "local-test-client",
          sub: "00u-test",
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
        })
      ).toString("base64url"),
      "signature",
    ].join(".");
    await assert.rejects(
      () => verifyIdToken(localConfig, unsignedIdToken),
      /signature or claims validation failed/
    );

    const expiredRecord = JSON.parse(fs.readFileSync(tokenCachePath, "utf8"));
    expiredRecord.tokens.obtained_at = 0;
    fs.writeFileSync(tokenCachePath, JSON.stringify(expiredRecord));
    const refreshed = await getAuthenticatedTokens(localConfig);
    assert.equal(refreshed?.access_token, "access-refreshed");
    assert.equal(refreshed?.refresh_token, "refresh-rotated");
    assert.equal(refreshed?.id_token, undefined);
    assert.equal(tokenRequest.get("grant_type"), "refresh_token");

    clearTokenCache();
    const mcpCallbackProbe = http.createServer();
    await new Promise((resolve) =>
      mcpCallbackProbe.listen(0, "localhost", resolve)
    );
    const mcpCallbackAddress = mcpCallbackProbe.address();
    assert.ok(mcpCallbackAddress && typeof mcpCallbackAddress !== "string");
    const mcpCallbackPort = mcpCallbackAddress.port;
    await new Promise((resolve) => mcpCallbackProbe.close(resolve));

    const loginEnv = cleanEnv({
      OKTA_MCP_CONFIG_DIR: path.join(testRoot, "mcp-login"),
      OKTA_MCP_ALLOW_INSECURE_HTTP: "1",
      OKTA_ORG_URL: issuer,
      OKTA_CLIENT_ID: "local-test-client",
      OKTA_AUTH_SERVER: "org",
      OKTA_SCOPES: "openid profile email offline_access",
      OKTA_OAUTH_CALLBACK_PORT: String(mcpCallbackPort),
    });
    let completionNotifications = 0;
    let callbackCompletion;
    await withMcp(
      loginEnv,
      async (client) => {
        const result = await client.callTool({ name: "okta-login", arguments: {} });
        assert.notEqual(result.isError, true);
        const loginResult = parseToolText(result);
        assert.equal(loginResult.connected, false);
        assert.equal(loginResult.authorization_pending, true);
        assert.deepEqual(loginResult.requested_scopes, [
          "openid",
          "profile",
          "email",
          "offline_access",
        ]);

        await callbackCompletion;
        let status;
        for (let attempt = 0; attempt < 50; attempt += 1) {
          status = parseToolText(
            await client.callTool({ name: "okta-status", arguments: {} })
          );
          if (status.connection_state === "ready" && completionNotifications > 0) {
            break;
          }
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        assert.equal(status?.connection_state, "ready");
        assert.equal(completionNotifications, 1);

        const whoami = parseToolText(
          await client.callTool({ name: "whoami", arguments: {} })
        );
        assert.equal(whoami.subject, "00u-test");
        assert.equal(whoami.email, "test@example.invalid");
      },
      (client) => {
        client.setNotificationHandler(
          ElicitationCompleteNotificationSchema,
          async () => {
            completionNotifications += 1;
          }
        );
        client.setRequestHandler(ElicitRequestSchema, (request) => {
          assert.equal(request.params.mode, "url");
          const url = new URL(request.params.url);
          assert.equal(url.origin, issuer);
          assert.match(request.params.message, /openid profile email offline_access/);
          expectedNonce = url.searchParams.get("nonce");
          assert.ok(expectedNonce);
          const state = url.searchParams.get("state");
          assert.ok(state);
          callbackCompletion = new Promise((resolve, reject) => {
            setTimeout(async () => {
              try {
                const response = await fetch(
                  `http://localhost:${mcpCallbackPort}/callback?code=mcp-code&state=${encodeURIComponent(state)}`
                );
                assert.equal(response.status, 200);
                resolve();
              } catch (error) {
                reject(error);
              }
            }, 100);
          });
          return { action: "accept" };
        });
      }
    );
  } finally {
    clearTokenCache();
    await new Promise((resolve) => oidc.close(resolve));
  }

  console.log(
    "Smoke tests passed: clean stdio startup, first-run status, scope gating, legacy-lab isolation, CLI config, URL validation, PKCE callback flow, and MCP URL elicitation login."
  );
} finally {
  fs.rmSync(testRoot, { recursive: true, force: true });
}
