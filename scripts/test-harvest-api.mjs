#!/usr/bin/env node
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  CdpClient,
  browserSessionProbe,
  delay,
  findBrowser,
  freePort,
  isOrgOrigin,
  stopBrowser,
  waitForTarget,
} from "./lab-browser-session-proof.mjs";

const orgUrl = "https://integrator-8282270.okta.com";

async function evaluate(cdp, expression) {
  const result = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) {
    throw new Error(
      result.exceptionDetails.exception?.description ||
        result.exceptionDetails.text
    );
  }
  return result.result?.value;
}

async function main() {
  const browserPath = findBrowser();
  const debugPort = await freePort();
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "okta-api-test-"));

  console.log(`Launching browser on CDP port ${debugPort}...`);
  const browser = spawn(
    browserPath,
    [
      `--user-data-dir=${profileDir}`,
      `--remote-debugging-port=${debugPort}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--new-window",
      `${orgUrl}/`,
    ],
    { detached: false, stdio: "ignore" }
  );

  let cdp;
  try {
    const target = await waitForTarget(debugPort, orgUrl);
    cdp = new CdpClient(target.webSocketDebuggerUrl);
    await cdp.ready;
    await cdp.send("Page.enable");
    await cdp.send("Network.enable");
    await cdp.send("Runtime.enable");

    console.log("Waiting for authentication... Sign in to Okta.\n");
    while (true) {
      const probe = await browserSessionProbe(cdp);
      if (probe?.ok && probe.status === 200 && isOrgOrigin(probe.origin, orgUrl)) {
        console.log(`Authenticated as ${probe.user_login}\n`);
        break;
      }
      await delay(2000);
    }

    await delay(5000);
    const currentUrl = await evaluate(cdp, "location.href");
    console.log(`Browser is on: ${currentUrl}\n`);

    // Test 1: /api/v1/users/me/appLinks (relative, from current page)
    console.log("=== Test 1: in-page fetch /api/v1/users/me/appLinks (relative) ===");
    try {
      const r1 = await evaluate(cdp, `
        fetch("/api/v1/users/me/appLinks", {
          credentials: "include",
          headers: { "Accept": "application/json" }
        }).then(async r => ({ ok: r.ok, status: r.status, body: r.ok ? await r.json() : await r.text().then(t => t.slice(0, 300)) }))
      `);
      console.log(`  Status: ${r1.status} OK: ${r1.ok}`);
      if (r1.ok && Array.isArray(r1.body)) {
        console.log(`  Apps: ${r1.body.length}`);
        for (const a of r1.body) console.log(`    ${a.label} | ${a.appName}`);
      } else {
        console.log(`  Body: ${typeof r1.body === "string" ? r1.body.slice(0, 200) : JSON.stringify(r1.body).slice(0, 200)}`);
      }
    } catch (e) { console.log(`  Error: ${e.message}`); }

    // Test 2: /api/v1/apps (relative, from current page - admin API)
    console.log("\n=== Test 2: in-page fetch /api/v1/apps?limit=200 (relative) ===");
    try {
      const r2 = await evaluate(cdp, `
        fetch("/api/v1/apps?limit=200", {
          credentials: "include",
          headers: { "Accept": "application/json" }
        }).then(async r => ({ ok: r.ok, status: r.status, body: r.ok ? await r.json() : await r.text().then(t => t.slice(0, 300)) }))
      `);
      console.log(`  Status: ${r2.status} OK: ${r2.ok}`);
      if (r2.ok && Array.isArray(r2.body)) {
        console.log(`  Apps: ${r2.body.length}`);
        for (const a of r2.body) {
          const link = a._links?.appLinks?.[0]?.href || "no-link";
          console.log(`    ${a.label} | name=${a.name} | signOnMode=${a.signOnMode} | link=${link}`);
        }
      } else {
        console.log(`  Body: ${typeof r2.body === "string" ? r2.body.slice(0, 200) : JSON.stringify(r2.body).slice(0, 200)}`);
      }
    } catch (e) { console.log(`  Error: ${e.message}`); }

    // Test 3: /api/v1/users/me/appLinks with absolute orgUrl
    console.log("\n=== Test 3: in-page fetch appLinks (absolute orgUrl) ===");
    try {
      const r3 = await evaluate(cdp, `
        fetch("${orgUrl}/api/v1/users/me/appLinks", {
          credentials: "include",
          headers: { "Accept": "application/json" }
        }).then(async r => ({ ok: r.ok, status: r.status, body: r.ok ? await r.json() : await r.text().then(t => t.slice(0, 300)) }))
      `);
      console.log(`  Status: ${r3.status} OK: ${r3.ok}`);
      if (r3.ok && Array.isArray(r3.body)) {
        console.log(`  Apps: ${r3.body.length}`);
        for (const a of r3.body) console.log(`    ${a.label} | ${a.appName}`);
      } else {
        console.log(`  Body: ${typeof r3.body === "string" ? r3.body.slice(0, 200) : JSON.stringify(r3.body).slice(0, 200)}`);
      }
    } catch (e) { console.log(`  Error: ${e.message}`); }

    // Test 4: /api/v1/apps with absolute orgUrl
    console.log("\n=== Test 4: in-page fetch apps (absolute orgUrl) ===");
    try {
      const r4 = await evaluate(cdp, `
        fetch("${orgUrl}/api/v1/apps?limit=200", {
          credentials: "include",
          headers: { "Accept": "application/json" }
        }).then(async r => ({ ok: r.ok, status: r.status, body: r.ok ? await r.json() : await r.text().then(t => t.slice(0, 300)) }))
      `);
      console.log(`  Status: ${r4.status} OK: ${r4.ok}`);
      if (r4.ok && Array.isArray(r4.body)) {
        console.log(`  Apps: ${r4.body.length}`);
        for (const a of r4.body) {
          const link = a._links?.appLinks?.[0]?.href || "no-link";
          console.log(`    ${a.label} | name=${a.name} | signOnMode=${a.signOnMode} | link=${link}`);
        }
      } else {
        console.log(`  Body: ${typeof r4.body === "string" ? r4.body.slice(0, 200) : JSON.stringify(r4.body).slice(0, 200)}`);
      }
    } catch (e) { console.log(`  Error: ${e.message}`); }

    console.log("\nDone. Close the browser window when finished.");
    await delay(60000);
  } finally {
    cdp?.close();
    stopBrowser(browser);
    await delay(500);
    try { fs.rmSync(profileDir, { recursive: true, force: true }); } catch {}
  }
}

main().catch(e => { console.error(e.message); process.exitCode = 1; });
