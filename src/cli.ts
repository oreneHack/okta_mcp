#!/usr/bin/env node

import fs from "node:fs";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import {
  applyConfigToEnv,
  configDir,
  configPath,
  loadFileConfig,
  loadRuntimeConfig,
  normalizeOrgUrl,
  saveFileConfig,
  tokenCachePath,
  type OktaMcpConfig,
} from "./config.js";

const DEFAULT_COOKIE_PROOF_URL =
  "http://127.0.0.1:8765/v1/cookie-proofs";

function yes(value: string): boolean {
  return ["y", "yes", "true", "1"].includes(value.trim().toLowerCase());
}

function option(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return undefined;
  const value = process.argv[index + 1];
  return value && !value.startsWith("--") ? value : undefined;
}

function flag(name: string): boolean {
  return process.argv.includes(`--${name}`);
}

async function ask(
  rl: ReturnType<typeof createInterface>,
  prompt: string,
  fallback = ""
): Promise<string> {
  const suffix = fallback ? ` [${fallback}]` : "";
  const answer = await rl.question(`${prompt}${suffix}: `);
  return answer.trim() || fallback;
}

async function init(): Promise<void> {
  const existing = loadFileConfig();

  const orgUrlArg = option("org-url");
  const clientIdArg = option("client-id");

  if (orgUrlArg && clientIdArg) {
    const adminScopes = flag("admin-scopes");
    const securityLabEnabled = flag("security-lab");
    const proofEnabled = flag("proof");
    const persistCookieJars = flag("persist-cookie-jars");
    const includeCookieValues = flag("include-cookie-values");

    if (
      !securityLabEnabled &&
      (proofEnabled || persistCookieJars || includeCookieValues)
    ) {
      throw new Error(
        "--proof, --persist-cookie-jars, and --include-cookie-values require --security-lab."
      );
    }
    if (includeCookieValues && !proofEnabled) {
      throw new Error("--include-cookie-values requires --proof.");
    }

    const config: OktaMcpConfig = {
      orgUrl: normalizeOrgUrl(orgUrlArg),
      clientId: clientIdArg,
      authServer: option("auth-server") || (adminScopes ? "org" : "default"),
      scopes:
        option("scopes") ||
        (adminScopes
          ? "openid profile email offline_access okta.users.read okta.groups.read okta.apps.read"
          : "openid profile email offline_access"),
      authOnStart: !flag("no-auth-on-start"),
      securityLabEnabled,
      labEventUrl: securityLabEnabled && proofEnabled
        ? option("lab-event-url") || "http://127.0.0.1:8765/v1/lab-events"
        : undefined,
      labEvidence: securityLabEnabled && proofEnabled ? "proof" : "metadata",
      cookieProofUrl: securityLabEnabled && proofEnabled
        ? option("cookie-proof-url") || DEFAULT_COOKIE_PROOF_URL
        : undefined,
      persistCookieJars: securityLabEnabled && persistCookieJars,
      includeCookieValues: securityLabEnabled && includeCookieValues,
    };

    saveFileConfig(config);
    console.log(`Saved config: ${configPath}`);
    return;
  }

  const rl = createInterface({ input, output });

  try {
    const orgUrl = normalizeOrgUrl(
      await ask(rl, "Okta org URL", existing.orgUrl || "")
    );
    const clientId = await ask(rl, "Okta OIDC client ID", existing.clientId || "");

    if (!orgUrl || !clientId) {
      throw new Error("Okta org URL and client ID are required.");
    }

    const adminAnswer = await ask(
      rl,
      "Enable org-management scopes for admin tools? y/N",
      "N"
    );
    const adminScopes = yes(adminAnswer);

    const authOnStartAnswer = await ask(
      rl,
      "Open Okta browser authentication when the MCP starts? Y/n",
      "Y"
    );

    const securityLabAnswer = await ask(
      rl,
      "Enable authorized security-lab session capture tools? y/N",
      existing.securityLabEnabled ? "Y" : "N"
    );
    const securityLabEnabled = yes(securityLabAnswer);

    let proofEnabled = false;
    let includeCookieValues = false;
    if (securityLabEnabled) {
      proofEnabled = yes(
        await ask(rl, "Enable the local evidence collector? y/N", "N")
      );
      if (proofEnabled) {
        includeCookieValues = yes(
          await ask(
            rl,
            "Include replayable cookie values in collector records? y/N",
            "N"
          )
        );
      }
    }

    const config: OktaMcpConfig = {
      orgUrl,
      clientId,
      authServer: adminScopes ? "org" : "default",
      scopes: adminScopes
        ? "openid profile email offline_access okta.users.read okta.groups.read okta.apps.read"
        : "openid profile email offline_access",
      authOnStart: !["n", "no", "0", "false"].includes(
        authOnStartAnswer.trim().toLowerCase()
      ),
      securityLabEnabled,
      labEventUrl: securityLabEnabled && proofEnabled
        ? "http://127.0.0.1:8765/v1/lab-events"
        : undefined,
      labEvidence: securityLabEnabled && proofEnabled ? "proof" : "metadata",
      cookieProofUrl:
        securityLabEnabled && proofEnabled ? DEFAULT_COOKIE_PROOF_URL : undefined,
      persistCookieJars: false,
      includeCookieValues,
    };

    saveFileConfig(config);

    console.log(`\nSaved config: ${configPath}`);
    console.log("\nVS Code MCP config:");
    console.log(
      JSON.stringify(
        {
          servers: {
            "okta-workspace": {
              command: "okta-workspace-mcp",
              args: ["serve"],
            },
          },
        },
        null,
        2
      )
    );
  } finally {
    rl.close();
  }
}

function printConfig(): void {
  const runtime = loadRuntimeConfig();
  console.log(
    JSON.stringify(
      {
        configPath,
        tokenCachePath,
        config: {
          ...runtime,
          clientId: `${runtime.clientId.slice(0, 6)}...`,
        },
      },
      null,
      2
    )
  );
}

function reset(): void {
  if (fs.existsSync(configPath)) fs.rmSync(configPath);
  if (fs.existsSync(tokenCachePath)) fs.rmSync(tokenCachePath);
  console.log(`Removed config/token cache from ${configDir}`);
}

function help(): void {
  console.log(`okta-workspace-mcp

Commands:
  init         Configure Okta org URL and client ID
               Optional flags: --org-url, --client-id, --admin-scopes,
               --security-lab, --proof, --cookie-proof-url,
               --persist-cookie-jars, --include-cookie-values
  serve        Start the MCP server
  collector    Start the local session diagnostics collector
  config       Print resolved config with redacted client ID
  config-path  Print user config path
  reset        Remove local config and token cache
`);
}

async function serve(): Promise<void> {
  const config = loadRuntimeConfig();
  applyConfigToEnv(config);
  await import("./index.js");
}

async function collector(): Promise<void> {
  await import(new URL("../scripts/collector.mjs", import.meta.url).href);
}

const command = process.argv[2] || "serve";

try {
  if (command === "init") await init();
  else if (command === "serve") await serve();
  else if (command === "collector") await collector();
  else if (command === "config") printConfig();
  else if (command === "config-path") console.log(configPath);
  else if (command === "reset") reset();
  else {
    help();
    process.exit(command === "help" || command === "--help" ? 0 : 1);
  }
} catch (err) {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`Error: ${message}`);
  process.exit(1);
}
