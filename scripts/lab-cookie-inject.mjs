import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  findBrowser,
  freePort,
  CdpClient,
  stopBrowser,
  delay,
  adminHostname,
} from "./lab-browser-session-proof.mjs";

const COLLECTOR_URL =
  process.env.OKTA_MCP_COLLECTOR_URL || "http://127.0.0.1:8765";

function cookieEditorSameSiteToCdp(value) {
  if (value === "no_restriction") return "None";
  if (value === "lax") return "Lax";
  if (value === "strict") return "Strict";
  return "Lax";
}

function toCdpCookie(cookie) {
  const cdp = {
    name: cookie.name,
    value: cookie.value,
    domain: cookie.domain,
    path: cookie.path || "/",
    secure: cookie.secure ?? true,
    httpOnly: cookie.httpOnly ?? false,
    sameSite: cookieEditorSameSiteToCdp(cookie.sameSite),
  };
  if (cookie.expirationDate) {
    cdp.expires = cookie.expirationDate;
  }
  return cdp;
}

async function fetchCookies() {
  const resp = await fetch(`${COLLECTOR_URL}/v1/cookies`);
  if (!resp.ok) throw new Error(`Collector returned ${resp.status}`);
  const cookies = await resp.json();
  if (!Array.isArray(cookies) || cookies.length === 0) {
    throw new Error("No cookies in collector");
  }
  return cookies;
}

function classifyCookies(cookies, mainHost, adminHost) {
  const main = [];
  const admin = [];
  const other = [];
  for (const c of cookies) {
    const d = (c.domain || "").replace(/^\./, "").toLowerCase();
    if (d === mainHost || mainHost.endsWith(`.${d}`)) {
      main.push(c);
    } else if (adminHost && (d === adminHost || adminHost.endsWith(`.${d}`))) {
      admin.push(c);
    } else {
      other.push(c);
    }
  }
  return { main, admin, other };
}

async function findPageTarget(port, timeoutMs = 10_000) {
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
    await delay(200);
  }
  throw new Error("Browser did not expose a CDP page target");
}

function option(name) {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return undefined;
  const value = process.argv[index + 1];
  return value && !value.startsWith("--") ? value : undefined;
}

async function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log(`Usage: node scripts/lab-cookie-inject.mjs --org-url <URL>

Fetches cookies from the local collector and injects them into a fresh
browser via CDP. Then navigates to the admin dashboard.

Options:
  --org-url URL     Okta org URL (required)
  --target PATH     Navigate to this path after injection (default: /admin/dashboard)
  -h, --help        Show this help`);
    return;
  }

  const orgUrlRaw = option("org-url");
  if (!orgUrlRaw) throw new Error("--org-url is required");
  const orgUrl = orgUrlRaw.replace(/\/+$/, "");
  const hostname = new URL(orgUrl).hostname;
  const adminHost = adminHostname(orgUrl);
  const targetPath = option("target") || "/admin/dashboard";

  console.log(`Fetching cookies from collector...`);
  const cookies = await fetchCookies();
  const { main, admin, other } = classifyCookies(cookies, hostname, adminHost);
  console.log(`Total: ${cookies.length} (main=${main.length} admin=${admin.length} other=${other.length})`);

  const critical = {
    idx: main.some((c) => c.name === "idx"),
    sid: admin.some((c) => c.name === "sid"),
    xids: admin.some((c) => c.name === "xids"),
    smax: admin.some((c) => c.name === "smax"),
  };
  console.log(`Critical cookies: idx=${critical.idx} sid=${critical.sid} xids=${critical.xids} smax=${critical.smax}`);

  const smax = admin.find((c) => c.name === "smax");
  if (smax) {
    const remaining = Math.round((parseInt(smax.value) - Date.now()) / 60000);
    console.log(`smax TTL: ${remaining} minutes`);
    if (remaining <= 0) console.warn("WARNING: admin session expired (smax)");
  }

  if (!critical.idx || !critical.sid) {
    console.warn("WARNING: missing critical session cookies — replay will likely fail");
  }

  const browserPath = findBrowser();
  const debugPort = await freePort();
  const profileDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "okta-inject-lab-")
  );

  console.log(`Launching browser with CDP on port ${debugPort}...`);
  const browser = spawn(
    browserPath,
    [
      `--user-data-dir=${profileDir}`,
      `--remote-debugging-port=${debugPort}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--new-window",
      "about:blank",
    ],
    { detached: false, stdio: "ignore" }
  );

  let cdp;
  try {
    const target = await findPageTarget(debugPort);

    cdp = new CdpClient(target.webSocketDebuggerUrl);
    await cdp.ready;
    await cdp.send("Network.enable");

    console.log("Clearing existing cookies...");
    await cdp.send("Network.clearBrowserCookies");

    console.log("Injecting cookies via CDP...");
    const cdpCookies = cookies.map(toCdpCookie);
    await cdp.send("Network.setCookies", { cookies: cdpCookies });

    const verify = await cdp.send("Network.getCookies", {
      urls: [
        `https://${hostname}/`,
        ...(adminHost ? [`https://${adminHost}/`] : []),
      ],
    });
    const injected = verify.cookies?.length || 0;
    console.log(`Verified: ${injected} cookies set in browser`);

    if (injected === 0) {
      throw new Error("No cookies were injected — check cookie format");
    }

    const adminUrl = adminHost
      ? `https://${adminHost}${targetPath}`
      : `${orgUrl}${targetPath}`;
    console.log(`Navigating to ${adminUrl}...`);
    await cdp.send("Page.enable");
    await cdp.send("Page.navigate", { url: adminUrl });

    await delay(3000);

    const result = await cdp.send("Runtime.evaluate", {
      expression: `JSON.stringify({ url: location.href, title: document.title })`,
      returnByValue: true,
    });
    const page = JSON.parse(result.result?.value || "{}");
    console.log(`Page: ${page.url}`);
    console.log(`Title: ${page.title}`);

    if (page.url?.includes("/login/") || page.url?.includes("/signin/")) {
      console.warn("RESULT: Redirected to login — session replay failed");
    } else if (page.url?.includes("/admin/")) {
      console.log("RESULT: Admin dashboard loaded — session replay succeeded");
    } else {
      console.log("RESULT: Check the browser manually");
    }

    console.log("\nBrowser is open. Press Ctrl+C to close.");
    await new Promise(() => {});
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
