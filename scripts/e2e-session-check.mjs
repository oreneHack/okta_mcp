import fs from "node:fs";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const timeoutSeconds = Number(process.argv[2] || process.env.OKTA_MCP_COOKIE_TIMEOUT_SECONDS || "300");
const outDir = path.resolve(process.cwd(), "collector-output");
const mcpStderrPath = path.join(outDir, "e2e-mcp-server.stderr.log");

fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(mcpStderrPath, "");

function log(message) {
  console.log(`[e2e] ${new Date().toISOString()} ${message}`);
}

const env = {
  ...process.env,
  OKTA_MCP_AUTH_ON_START: "0",
  OKTA_MCP_SECURITY_LAB: "1",
  OKTA_MCP_COOKIE_PROOF_URL:
    process.env.OKTA_MCP_COOKIE_PROOF_URL || "http://127.0.0.1:8765/v1/cookie-proofs",
};

const transport = new StdioClientTransport({
  command: "node",
  args: ["build/cli.js", "serve"],
  cwd: process.cwd(),
  env,
  stderr: "pipe",
});

transport.stderr?.on("data", (chunk) => {
  fs.appendFileSync(mcpStderrPath, chunk);
});

const client = new Client({
  name: "okta-mcp-e2e-client",
  version: "1.0.0",
});

try {
  log("connecting to MCP server over stdio");
  await client.connect(transport);

  log(`calling session-check with timeoutSeconds=${timeoutSeconds}`);
  log("complete the Okta sign-in in the browser window that just opened");
  const result = await client.callTool(
    {
      name: "session-check",
      arguments: { timeoutSeconds },
    },
    undefined,
    {
      timeout: (timeoutSeconds + 60) * 1000,
      maxTotalTimeout: (timeoutSeconds + 90) * 1000,
    }
  );

  log("session-check returned");
  console.log(JSON.stringify(result, null, 2));
} catch (err) {
  log(`failed: ${err instanceof Error ? err.stack || err.message : String(err)}`);
  process.exitCode = 1;
} finally {
  await client.close().catch(() => {});
  log(`MCP stderr log: ${mcpStderrPath}`);
}
