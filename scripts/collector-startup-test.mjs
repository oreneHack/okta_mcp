import assert from "node:assert/strict";
import net from "node:net";
import { spawnSync } from "node:child_process";
import { ensureCookieProofCollector } from "../build/collector-process.js";

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Could not allocate test port."));
        return;
      }
      server.close(() => resolve(address.port));
    });
  });
}

function stopProcess(pid) {
  if (!pid) return;
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/F", "/T", "/PID", String(pid)], { stdio: "ignore" });
    return;
  }
  try {
    process.kill(pid, "SIGTERM");
  } catch {
    // Process already stopped.
  }
}

const port = await freePort();
const endpoint = `http://127.0.0.1:${port}/v1/cookie-proofs`;
let startedPid;

try {
  const first = await ensureCookieProofCollector(endpoint);
  assert.equal(first?.started, true);
  assert.ok(first?.pid);
  startedPid = first.pid;

  const healthResponse = await fetch(`http://127.0.0.1:${port}/health`);
  assert.equal(healthResponse.status, 200);
  const health = await healthResponse.json();
  assert.equal(health.ok, true);
  assert.equal(health.service, "okta-mcp-local-collector");

  const second = await ensureCookieProofCollector(endpoint);
  assert.equal(second?.started, false);

  const remote = await ensureCookieProofCollector(
    "https://collector.example.test/v1/cookie-proofs"
  );
  assert.equal(remote, null);

  await assert.rejects(
    ensureCookieProofCollector(`http://127.0.0.1:${port}/wrong-path`),
    /must use \/v1\/cookie-proofs/
  );

  console.log(
    "Collector startup test passed: auto-start, health reuse, loopback gating, and path validation."
  );
} finally {
  stopProcess(startedPid);
}
