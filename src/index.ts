#!/usr/bin/env node

import crypto from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  AuthenticationRequiredError,
  getAuthenticatedTokens,
  inspectTokenCache,
  startAuthorization,
  type AuthorizationSession,
  type OktaTokens,
} from "./auth.js";
import {
  configSource,
  IDENTITY_SCOPES,
  loadRuntimeConfig,
  redactClientId,
  tryLoadRuntimeConfig,
  type OktaMcpConfig,
} from "./config.js";
import { OktaApiError, OktaClient } from "./okta-client.js";

const startupConfig = tryLoadRuntimeConfig();
let frozenConfig = startupConfig
  ? Object.freeze({ ...startupConfig })
  : null;
const requestedScopes = new Set(
  (startupConfig?.scopes || IDENTITY_SCOPES).split(/\s+/).filter(Boolean)
);

const server = new McpServer({
  name: "okta-workspace",
  version: "1.1.0",
});

type LoginOutcome =
  | { status: "connected"; tokens: OktaTokens }
  | { status: "authorization_pending" };

let tokenCheckInFlight: Promise<OktaTokens | null> | null = null;
let loginStartInFlight: Promise<LoginOutcome> | null = null;
let loginCompletionInFlight: Promise<OktaTokens> | null = null;
let activeAuthorizationSession: AuthorizationSession | null = null;
let lastAuthenticationError: string | undefined;

function jsonResult(value: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
  };
}

function errorResult(error: unknown) {
  let code = "okta_error";
  let message = error instanceof Error ? error.message : String(error);
  let status: number | undefined;

  if (error instanceof AuthenticationRequiredError) {
    code = "authentication_required";
  } else if (error instanceof OktaApiError) {
    code = error.code;
    status = error.status;
  } else if (message.startsWith("Okta MCP is not configured:")) {
    code = "configuration_required";
  } else if (message.startsWith("Okta MCP configuration changed")) {
    code = "restart_required";
  }

  return {
    isError: true,
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(
          {
            error: code,
            message,
            status,
            next_step:
              code === "configuration_required"
                ? 'Run "okta-workspace-mcp configure" or configure OKTA_ORG_URL and OKTA_CLIENT_ID in the MCP client.'
                : code === "restart_required"
                  ? "Restart this MCP server so it can use the new configuration safely."
                : code === "authentication_required"
                  ? "Call the okta-login tool, then retry."
                  : undefined,
          },
          null,
          2
        ),
      },
    ],
  };
}

function runtimeConfig(): OktaMcpConfig {
  const loaded = loadRuntimeConfig();
  if (!frozenConfig) {
    frozenConfig = Object.freeze({ ...loaded });
    return frozenConfig;
  }

  const keys: Array<keyof OktaMcpConfig> = [
    "configVersion",
    "orgUrl",
    "clientId",
    "authServer",
    "scopes",
    "callbackHost",
    "callbackPort",
  ];
  if (keys.some((key) => loaded[key] !== frozenConfig?.[key])) {
    throw new Error(
      "Okta MCP configuration changed while this server was running. Restart the MCP server before making another request."
    );
  }
  return frozenConfig;
}

async function cachedTokens(config: OktaMcpConfig): Promise<OktaTokens | null> {
  if (!tokenCheckInFlight) {
    tokenCheckInFlight = getAuthenticatedTokens(config).finally(() => {
      tokenCheckInFlight = null;
    });
  }
  return tokenCheckInFlight;
}

async function authenticatedClient(): Promise<{
  config: OktaMcpConfig;
  tokens: OktaTokens;
  client: OktaClient;
}> {
  const config = runtimeConfig();
  const tokens = await cachedTokens(config);
  if (!tokens) {
    throw new AuthenticationRequiredError(
      "Okta is configured but not connected. Call okta-login first."
    );
  }
  return { config, tokens, client: await OktaClient.create(config, tokens) };
}

function requireGrantedScope(tokens: OktaTokens, scope: string): void {
  const granted = new Set(tokens.scope.split(/\s+/).filter(Boolean));
  if (!granted.has(scope)) {
    throw new OktaApiError(
      `The current Okta token was not granted ${scope}. Reconfigure the app and reconnect.`,
      403,
      "insufficient_scope",
      "oauth"
    );
  }
}

async function login(
  config: OktaMcpConfig,
  signal: AbortSignal
): Promise<LoginOutcome> {
  const existing = await cachedTokens(config);
  if (existing) return { status: "connected", tokens: existing };
  if (loginCompletionInFlight) return { status: "authorization_pending" };
  if (loginStartInFlight) return loginStartInFlight;
  lastAuthenticationError = undefined;

  const loginAttempt: Promise<LoginOutcome> = (async (): Promise<LoginOutcome> => {
    const urlElicitationSupported = Boolean(
      server.server.getClientCapabilities()?.elicitation?.url
    );
    const session = await startAuthorization(config);
    activeAuthorizationSession = session;
    if (urlElicitationSupported) {
      const elicitationId = crypto.randomUUID();
      const notifyComplete =
        server.server.createElicitationCompletionNotifier(elicitationId);
      let response;
      try {
        response = await server.server.elicitInput(
          {
            mode: "url",
            elicitationId,
            url: session.authorizationUrl,
            message:
              `Connect this MCP to ${config.orgUrl}. ` +
              `It is requesting exactly these scopes: ${config.scopes}`,
          },
          { signal, timeout: 180_000 }
        );
      } catch (error) {
        session.cancel();
        if (activeAuthorizationSession === session) {
          activeAuthorizationSession = null;
        }
        throw error;
      }
      if (response.action !== "accept") {
        session.cancel();
        if (activeAuthorizationSession === session) {
          activeAuthorizationSession = null;
        }
        throw new AuthenticationRequiredError(
          "Okta authentication was declined or cancelled."
        );
      }

      const completion = session.completion
        .then(
          async (tokens) => {
            lastAuthenticationError = undefined;
            await notifyComplete().catch(() => {});
            return tokens;
          },
          async (error) => {
            lastAuthenticationError =
              error instanceof Error ? error.message : String(error);
            await notifyComplete().catch(() => {});
            throw error;
          }
        )
        .finally(() => {
          if (activeAuthorizationSession === session) {
            activeAuthorizationSession = null;
          }
          if (loginCompletionInFlight === completion) {
            loginCompletionInFlight = null;
          }
        });
      loginCompletionInFlight = completion;
      completion.catch(() => {});
      return { status: "authorization_pending" };
    }

    const cancelOnAbort = () => session.cancel();
    if (signal.aborted) {
      cancelOnAbort();
    } else signal.addEventListener("abort", cancelOnAbort, { once: true });
    try {
      if (signal.aborted) {
        throw new AuthenticationRequiredError(
          "Okta authentication was cancelled by the MCP client."
        );
      }
      const open = (await import("open")).default;
      await open(session.authorizationUrl);
      const tokens = await session.completion;
      lastAuthenticationError = undefined;
      return { status: "connected", tokens };
    } catch (error) {
      session.cancel();
      lastAuthenticationError =
        error instanceof Error ? error.message : String(error);
      throw error;
    } finally {
      signal.removeEventListener("abort", cancelOnAbort);
      if (activeAuthorizationSession === session) {
        activeAuthorizationSession = null;
      }
    }
  })().finally(() => {
    if (loginStartInFlight === loginAttempt) {
      loginStartInFlight = null;
    }
  });
  loginStartInFlight = loginAttempt;

  return loginAttempt;
}

server.tool(
  "okta-status",
  "Show the configured Okta organization, requested scopes, and connection status without exposing credentials",
  {},
  async () => {
    try {
      const config = runtimeConfig();
      const tokenStatus = inspectTokenCache(config);
      const connectionState = loginCompletionInFlight
        ? "authorization_pending"
        : tokenStatus.present && tokenStatus.contextMatches && !tokenStatus.expired
          ? "ready"
          : tokenStatus.contextMatches && tokenStatus.refreshTokenAvailable
            ? "refreshable"
            : "login_required";
      return jsonResult({
        configured: true,
        configuration_source: configSource(),
        organization: config.orgUrl,
        client_id: redactClientId(config.clientId),
        issuer:
          config.authServer === "org"
            ? config.orgUrl
            : `${config.orgUrl}/oauth2/${config.authServer}`,
        requested_scopes: config.scopes.split(/\s+/),
        callback: `http://${config.callbackHost}:${config.callbackPort}/callback`,
        connection_state: connectionState,
        connected: connectionState === "ready",
        refresh_available:
          tokenStatus.contextMatches && tokenStatus.refreshTokenAvailable,
        last_authentication_error: lastAuthenticationError,
        token_cache: tokenStatus,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.startsWith("Okta MCP configuration changed")) {
        return jsonResult({
          configured: true,
          connection_state: "restart_required",
          message,
          next_step:
            "Restart this MCP server so it can use the new configuration safely.",
        });
      }
      return jsonResult({
        configured: false,
        configuration_source: configSource(),
        message,
        next_step:
          'Run "okta-workspace-mcp configure" or set OKTA_ORG_URL and OKTA_CLIENT_ID in the MCP client.',
      });
    }
  }
);

server.tool(
  "okta-login",
  "Connect to the configured Okta organization using its hosted sign-in page and OAuth Authorization Code with PKCE",
  {},
  async (_args, extra) => {
    try {
      const config = runtimeConfig();
      const before = inspectTokenCache(config);
      const outcome = await login(config, extra.signal);
      if (outcome.status === "authorization_pending") {
        return jsonResult({
          connected: false,
          authorization_pending: true,
          organization: config.orgUrl,
          requested_scopes: config.scopes.split(/\s+/).filter(Boolean),
          next_step:
            "Complete authentication in the opened Okta page. The MCP client will be notified when it finishes; then call okta-status or retry your tool.",
        });
      }
      const tokens = outcome.tokens;
      const client = await OktaClient.create(config, tokens);
      const profile = await client.userinfo();
      return jsonResult({
        connected: true,
        reused_cached_authorization:
          before.present && before.contextMatches && !before.expired,
        organization: config.orgUrl,
        subject: profile.sub,
        name: profile.name,
        email: profile.email,
        granted_scopes: tokens.scope.split(/\s+/).filter(Boolean),
      });
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "whoami",
  "Show the profile returned by the configured Okta organization for the connected user",
  {},
  async () => {
    try {
      const { client } = await authenticatedClient();
      return jsonResult(await client.whoami());
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "userinfo",
  "Fetch the connected user's profile from Okta's OIDC userinfo endpoint",
  {},
  async () => {
    try {
      const { client } = await authenticatedClient();
      return jsonResult(await client.userinfo());
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "token-details",
  "Show safe metadata about the current authorization without returning bearer-token values or unstable access-token claims",
  {},
  async () => {
    try {
      const { client } = await authenticatedClient();
      return jsonResult(client.tokenDetails());
    } catch (error) {
      return errorResult(error);
    }
  }
);

server.tool(
  "my-groups",
  "Show group names from the connected user's Okta ID-token groups claim, when configured",
  {},
  async () => {
    try {
      const { client } = await authenticatedClient();
      return jsonResult(client.myGroups());
    } catch (error) {
      return errorResult(error);
    }
  }
);

if (requestedScopes.has("okta.users.read")) {
  server.tool(
    "my-apps",
    "List Okta application links assigned to the connected user (requires okta.users.read and suitable authorization)",
    {},
    async () => {
      try {
        const { client, tokens } = await authenticatedClient();
        requireGrantedScope(tokens, "okta.users.read");
        return jsonResult(await client.myAppLinks());
      } catch (error) {
        return errorResult(error);
      }
    }
  );

  server.tool(
    "list-users",
    "List users visible to the connected Okta administrator (requires okta.users.read)",
    {
      limit: z
        .number()
        .int()
        .min(1)
        .max(200)
        .optional()
        .describe("Maximum users to return, from 1 to 200 (default 25)"),
    },
    async ({ limit }) => {
      try {
        const { client, tokens } = await authenticatedClient();
        requireGrantedScope(tokens, "okta.users.read");
        return jsonResult(await client.listUsers(limit));
      } catch (error) {
        return errorResult(error);
      }
    }
  );

  server.tool(
    "get-user",
    "Get one user visible to the connected Okta administrator (requires okta.users.read)",
    {
      userId: z.string().min(1).max(200).describe("Okta user ID or login"),
    },
    async ({ userId }) => {
      try {
        const { client, tokens } = await authenticatedClient();
        requireGrantedScope(tokens, "okta.users.read");
        return jsonResult(await client.getUser(userId));
      } catch (error) {
        return errorResult(error);
      }
    }
  );

  server.tool(
    "search-users",
    "Search users visible to the connected Okta administrator (requires okta.users.read)",
    {
      query: z.string().min(1).max(500).describe("Okta search expression"),
    },
    async ({ query }) => {
      try {
        const { client, tokens } = await authenticatedClient();
        requireGrantedScope(tokens, "okta.users.read");
        return jsonResult(await client.searchUsers(query));
      } catch (error) {
        return errorResult(error);
      }
    }
  );
}

if (requestedScopes.has("okta.groups.read")) {
  server.tool(
    "list-groups",
    "List groups visible to the connected Okta administrator (requires okta.groups.read)",
    {
      limit: z
        .number()
        .int()
        .min(1)
        .max(200)
        .optional()
        .describe("Maximum groups to return, from 1 to 200 (default 25)"),
    },
    async ({ limit }) => {
      try {
        const { client, tokens } = await authenticatedClient();
        requireGrantedScope(tokens, "okta.groups.read");
        return jsonResult(await client.listGroups(limit));
      } catch (error) {
        return errorResult(error);
      }
    }
  );
}

if (requestedScopes.has("okta.apps.read")) {
  server.tool(
    "list-apps",
    "List applications visible to the connected Okta administrator (requires okta.apps.read)",
    {
      limit: z
        .number()
        .int()
        .min(1)
        .max(200)
        .optional()
        .describe("Maximum applications to return, from 1 to 200 (default 25)"),
    },
    async ({ limit }) => {
      try {
        const { client, tokens } = await authenticatedClient();
        requireGrantedScope(tokens, "okta.apps.read");
        return jsonResult(await client.listApps(limit));
      } catch (error) {
        return errorResult(error);
      }
    }
  );
}

const transport = new StdioServerTransport();
await server.connect(transport);

process.stdin.once("end", () => {
  activeAuthorizationSession?.cancel();
});
