import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { buildCookieProofPayload } from "../build/cookie-proof.js";

const normalTools = [
  "my-groups",
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

const labTools = [
  "session-check",
  "session-export",
  "session-history",
  "session-validate",
];

async function listTools(securityLab, scopes = "openid profile email offline_access") {
  const transport = new StdioClientTransport({
    command: "node",
    args: ["build/cli.js", "serve"],
    cwd: process.cwd(),
    env: {
      ...process.env,
      OKTA_ORG_URL: "https://smoke-test.invalid",
      OKTA_CLIENT_ID: "smoke-test-client",
      OKTA_MCP_AUTH_ON_START: "0",
      OKTA_SCOPES: scopes,
      OKTA_MCP_SECURITY_LAB: securityLab ? "1" : "0",
      OKTA_MCP_COOKIE_PROOF_URL: "",
      OKTA_MCP_LAB_EVENT_URL: "",
      OKTA_MCP_PERSIST_COOKIE_JARS: "0",
      OKTA_MCP_INCLUDE_COOKIE_VALUES: "0",
    },
    stderr: "pipe",
  });
  const client = new Client({ name: "okta-workspace-smoke", version: "1.0.0" });

  try {
    await client.connect(transport);
    const result = await client.listTools();
    return result.tools.map((tool) => tool.name).sort();
  } finally {
    await client.close().catch(() => {});
  }
}

const defaultSurface = await listTools(false);
assert.deepEqual(defaultSurface, normalTools, "normal mode exposed unexpected tools");

const labSurface = await listTools(true);
assert.deepEqual(
  labSurface,
  [...normalTools, ...labTools].sort(),
  "security-lab mode did not expose the expected tools"
);

const organizationSurface = await listTools(
  false,
  "openid profile email offline_access okta.users.read okta.groups.read okta.apps.read"
);
assert.deepEqual(
  organizationSurface,
  [...normalTools, ...organizationTools].sort(),
  "organization-read scopes did not expose the expected tools"
);

const proofArgs = {
  capturedAt: "2026-01-01T00:00:00.000Z",
  orgHost: "example.okta.com",
  cookies: [{ name: "idx", value: "replayable-test-value", secure: true }],
  sessionProbe: {
    ok: true,
    status: 200,
    user_login: "lab-user@example.com",
    user_id: "00u-test",
  },
};

const redactedProof = buildCookieProofPayload(proofArgs);
assert.equal(redactedProof.cookies[0].display_value, null);
assert.equal(redactedProof.cookies[0].value_length, 21);
assert.equal(redactedProof.user_login, "lab-user@example.com");
assert.equal(redactedProof.session_probe.status, 200);

const valueProof = buildCookieProofPayload({
  ...proofArgs,
  includeCookieValues: true,
});
assert.equal(valueProof.cookies[0].display_value, "replayable-test-value");

console.log(
  "Smoke tests passed: core/org/lab tool gating and proof redaction."
);
