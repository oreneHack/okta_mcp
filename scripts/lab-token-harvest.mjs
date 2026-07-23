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
} from "./lab-browser-session-proof.mjs";

const COLLECTOR_URL =
  process.env.OKTA_MCP_COLLECTOR_URL || "http://127.0.0.1:8765";
const SSO_SETTLE_MS = Number(process.env.OKTA_HARVEST_SSO_SETTLE_MS || "6000");

function option(name) {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return undefined;
  const value = process.argv[index + 1];
  return value && !value.startsWith("--") ? value : undefined;
}

async function findPageTarget(port, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(`http://127.0.0.1:${port}/json/list`);
      const targets = await resp.json();
      const page = targets.find(
        (t) => t.type === "page" && t.webSocketDebuggerUrl
      );
      if (page) return page;
    } catch {}
    await delay(300);
  }
  throw new Error("Browser did not expose a CDP page target");
}

async function evaluate(cdp, expression) {
  const result = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) {
    throw new Error(
      result.exceptionDetails.exception?.description ||
        result.exceptionDetails.text ||
        "evaluate() failed"
    );
  }
  return result.result?.value;
}

async function waitForLoad(cdp, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const state = await evaluate(cdp, "document.readyState");
      if (state === "complete") return;
    } catch {}
    await delay(500);
  }
}

async function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log(`Usage: node scripts/lab-token-harvest.mjs --org-url <URL>

Opens a browser, waits for Okta authentication, enumerates the user's
assigned apps via /api/v1/users/me/appLinks, navigates to each OIDC app
to trigger SSO, reads okta-token-storage from localStorage, and POSTs
all found tokens to the local collector at ${COLLECTOR_URL}/v1/tokens.

Options:
  --org-url URL     Okta org URL (required)
  -h, --help        Show this help`);
    return;
  }

  const orgUrlRaw = option("org-url");
  if (!orgUrlRaw) throw new Error("--org-url is required");
  const orgUrl = orgUrlRaw.replace(/\/+$/, "");
  const orgHost = new URL(orgUrl).hostname;

  const browserPath = findBrowser();
  const debugPort = await freePort();
  const profileDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "okta-harvest-")
  );

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
    const target = await findPageTarget(debugPort);
    cdp = new CdpClient(target.webSocketDebuggerUrl);
    await cdp.ready;
    await cdp.send("Page.enable");
    await cdp.send("Network.enable");
    await cdp.send("Runtime.enable");

    console.log("Waiting for Okta authentication...");
    console.log("Sign in to Okta in the browser window.\n");
    let probe;
    while (true) {
      probe = await browserSessionProbe(cdp);
      if (
        probe?.ok &&
        probe.status === 200 &&
        isOrgOrigin(probe.origin, orgUrl)
      )
        break;
      await delay(2000);
    }
    console.log(`Authenticated as ${probe.user_login} (${probe.user_id})`);

    await cdp.send("Page.navigate", { url: `${orgUrl}/` });
    await delay(2000);

    console.log("Enumerating assigned apps...");
    const appLinks = await evaluate(
      cdp,
      `fetch("/api/v1/users/me/appLinks", {
        credentials: "include",
        headers: { "Accept": "application/json" }
      }).then(r => r.json())`
    );

    if (!Array.isArray(appLinks) || appLinks.length === 0) {
      console.log("No apps assigned to this user.");
      return;
    }

    console.log(`Found ${appLinks.length} app(s):`);
    for (const app of appLinks) {
      console.log(`  ${app.label} (${app.appName})`);
    }

    const oidcApps = appLinks.filter(
      (app) =>
        app.appName?.includes("oidc_client") ||
        app.linkUrl?.includes("/home/oidc_client/")
    );

    if (oidcApps.length === 0) {
      console.log("\nNo OIDC apps found. Only OIDC SPAs store tokens in localStorage.");
      console.log("SAML and bookmark apps do not produce harvestable tokens.");
      return;
    }

    console.log(`\n${oidcApps.length} OIDC app(s) to harvest:\n`);

    const harvest = [];

    for (const app of oidcApps) {
      console.log(`--- ${app.label} ---`);
      console.log(`  linkUrl: ${app.linkUrl}`);

      try {
        await cdp.send("Page.navigate", { url: app.linkUrl });
        await delay(SSO_SETTLE_MS);
        await waitForLoad(cdp);

        const currentUrl = await evaluate(cdp, "location.href");
        console.log(`  landed: ${currentUrl}`);

        const tokenStorageRaw = await evaluate(
          cdp,
          "localStorage.getItem('okta-token-storage')"
        );

        if (!tokenStorageRaw) {
          console.log("  okta-token-storage: not found\n");
          continue;
        }

        let tokens;
        try {
          tokens = JSON.parse(tokenStorageRaw);
        } catch {
          console.log("  okta-token-storage: invalid JSON\n");
          continue;
        }

        const hasAccess = !!tokens.accessToken?.accessToken;
        const hasId = !!tokens.idToken?.idToken;
        const hasRefresh = !!tokens.refreshToken?.refreshToken;
        console.log(
          `  tokens: access=${hasAccess} id=${hasId} refresh=${hasRefresh}`
        );

        if (hasAccess || hasId || hasRefresh) {
          harvest.push({
            app_id: app.appInstanceId,
            app_label: app.label,
            app_name: app.appName,
            app_link_url: app.linkUrl,
            app_origin: new URL(currentUrl).origin,
            tokens,
          });
          console.log("  HARVESTED\n");
        } else {
          console.log("  no usable tokens\n");
        }
      } catch (err) {
        console.log(`  error: ${err.message}\n`);
      }
    }

    console.log("=== Harvest complete ===");
    console.log(`Apps scanned: ${oidcApps.length}`);
    console.log(`Apps with tokens: ${harvest.length}`);

    if (harvest.length === 0) {
      console.log("No tokens harvested.");
      return;
    }

    const payload = {
      org_host: orgHost,
      captured_at: new Date().toISOString(),
      subject: probe.user_login,
      user_id: probe.user_id,
      apps_scanned: oidcApps.length,
      apps: harvest,
    };

    console.log(`\nPosting ${harvest.length} app token(s) to collector...`);
    const resp = await fetch(`${COLLECTOR_URL}/v1/tokens`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await resp.json();
    if (resp.ok) {
      console.log(`Saved: ${result.file_name}`);
    } else {
      console.error(`Collector error: ${result.error}`);
    }

    console.log("\n--- Token Summary ---");
    for (const app of harvest) {
      const t = app.tokens;
      console.log(`\n${app.app_label} (${app.app_origin})`);
      if (t.accessToken?.accessToken) {
        try {
          const parts = t.accessToken.accessToken.split(".");
          const claims = JSON.parse(
            Buffer.from(parts[1], "base64url").toString()
          );
          console.log(`  Access Token: ${t.accessToken.accessToken.slice(0, 40)}...`);
          console.log(`    iss: ${claims.iss}`);
          console.log(`    sub: ${claims.sub}`);
          console.log(`    scp: ${(claims.scp || []).join(", ")}`);
          console.log(
            `    exp: ${new Date(claims.exp * 1000).toISOString()}`
          );
        } catch {
          console.log(`  Access Token: ${t.accessToken.accessToken.slice(0, 40)}...`);
        }
      }
      if (t.refreshToken?.refreshToken) {
        console.log(
          `  Refresh Token: ${t.refreshToken.refreshToken.slice(0, 20)}...`
        );
      }
    }
  } catch (err) {
    if (err.message !== "The isolated browser was closed.") {
      console.error(`Error: ${err.message}`);
    }
  } finally {
    cdp?.close();
    stopBrowser(browser);
    await delay(500);
    try {
      fs.rmSync(profileDir, { recursive: true, force: true });
    } catch {}
  }
}

try {
  await main();
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exitCode = 1;
}
