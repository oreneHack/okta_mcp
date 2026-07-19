import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { tokenCachePath } from "./config.js";

const CALLBACK_PORT = 8749;
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}/callback`;

// Default scopes can be overridden via OKTA_SCOPES env var.
// Keep the default OIDC-only so first-run auth works against the default
// authorization server. Org-management tools need OKTA_AUTH_SERVER=org plus
// explicit okta.* scopes and matching Okta roles.
const DEFAULT_SCOPES = "openid profile email offline_access";

export interface OktaTokens {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
  scope: string;
  obtained_at: number;
}

function base64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function generatePKCE(): { verifier: string; challenge: string } {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(
    crypto.createHash("sha256").update(verifier).digest()
  );
  return { verifier, challenge };
}

export function loadCachedTokens(): OktaTokens | null {
  try {
    if (!fs.existsSync(tokenCachePath)) return null;
    const data = JSON.parse(fs.readFileSync(tokenCachePath, "utf-8"));
    return data as OktaTokens;
  } catch {
    return null;
  }
}

function saveTokens(tokens: OktaTokens): void {
  fs.mkdirSync(path.dirname(tokenCachePath), { recursive: true });
  fs.writeFileSync(tokenCachePath, JSON.stringify(tokens, null, 2));
}

function authServerBase(orgUrl: string, authServerId: string): string {
  // "org" (or empty) selects the org authorization server, whose endpoints have
  //   NO id segment: /oauth2/v1/authorize. Tokens minted here carry okta.*
  //   scopes and can call the matching /api/v1/* endpoints when roles allow.
  // Anything else selects a custom authorization server: /oauth2/{id}/v1/authorize
  //   (audience api://{id}); good for OIDC identity but cannot call /api/v1/*.
  if (!authServerId || authServerId === "org") return `${orgUrl}/oauth2/v1`;
  return `${orgUrl}/oauth2/${authServerId}/v1`;
}

export async function refreshAccessToken(
  orgUrl: string,
  clientId: string,
  authServerId: string,
  tokens: OktaTokens
): Promise<OktaTokens> {
  if (!tokens.refresh_token) throw new Error("No refresh token available");

  const resp = await fetch(`${authServerBase(orgUrl, authServerId)}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
      client_id: clientId,
    }),
  });

  if (!resp.ok) throw new Error(`Token refresh failed: ${resp.status}`);

  const data = await resp.json();
  const refreshed: OktaTokens = {
    ...data,
    refresh_token: data.refresh_token || tokens.refresh_token,
    obtained_at: Date.now(),
  };
  saveTokens(refreshed);
  return refreshed;
}

export function isTokenExpired(tokens: OktaTokens): boolean {
  const elapsed = (Date.now() - tokens.obtained_at) / 1000;
  return elapsed >= tokens.expires_in - 60;
}

export async function getValidTokens(
  orgUrl: string,
  clientId: string,
  authServerId: string
): Promise<OktaTokens> {
  let tokens = loadCachedTokens();

  if (tokens && !isTokenExpired(tokens)) return tokens;

  if (tokens?.refresh_token) {
    try {
      return await refreshAccessToken(orgUrl, clientId, authServerId, tokens);
    } catch {
      // refresh failed, need full re-auth
    }
  }

  return browserAuth(orgUrl, clientId, authServerId);
}

export function browserAuth(
  orgUrl: string,
  clientId: string,
  authServerId: string
): Promise<OktaTokens> {
  const { verifier, challenge } = generatePKCE();
  const state = base64url(crypto.randomBytes(16));
  const scopes = process.env.OKTA_SCOPES || DEFAULT_SCOPES;

  const base = authServerBase(orgUrl, authServerId);
  const authUrl = new URL(`${base}/authorize`);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", scopes);
  authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  return new Promise((resolve, reject) => {
    const server = http.createServer(async (req, res) => {
      if (!req.url?.startsWith("/callback")) {
        res.writeHead(404);
        res.end();
        return;
      }

      const url = new URL(req.url, `http://localhost:${CALLBACK_PORT}`);
      const code = url.searchParams.get("code");
      const returnedState = url.searchParams.get("state");
      const error = url.searchParams.get("error");

      if (error || !code || returnedState !== state) {
        res.writeHead(400, { "Content-Type": "text/html" });
        res.end(
          "<h2>Authentication failed.</h2><p>You can close this tab.</p>"
        );
        server.close();
        reject(new Error(error || "Invalid callback"));
        return;
      }

      try {
        const tokenResp = await fetch(`${base}/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            client_id: clientId,
            redirect_uri: REDIRECT_URI,
            code_verifier: verifier,
          }),
        });

        if (!tokenResp.ok) {
          const body = await tokenResp.text();
          throw new Error(
            `Token exchange failed: ${tokenResp.status} ${body}`
          );
        }

        const data = await tokenResp.json();
        const tokens: OktaTokens = { ...data, obtained_at: Date.now() };

        saveTokens(tokens);

        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(
          "<h2>Authenticated successfully!</h2>" +
            "<p>You can close this tab and return to your AI assistant.</p>"
        );
        server.close();
        resolve(tokens);
      } catch (err) {
        res.writeHead(500, { "Content-Type": "text/html" });
        res.end("<h2>Something went wrong.</h2>");
        server.close();
        reject(err);
      }
    });

    server.listen(CALLBACK_PORT, async () => {
      const open = (await import("open")).default;
      await open(authUrl.toString());
    });

    setTimeout(() => {
      server.close();
      reject(new Error("Authentication timed out (120s)"));
    }, 120_000);
  });
}
