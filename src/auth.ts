import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import {
  createRemoteJWKSet,
  customFetch,
  jwtVerify,
  type JWTPayload,
} from "jose";
import {
  DEFAULT_CALLBACK_PORT,
  makeConfig,
  tokenCachePath,
  writePrivateJson,
  type OktaMcpConfig,
} from "./config.js";

const AUTH_TIMEOUT_MS = 180_000;
const FETCH_TIMEOUT_MS = 15_000;
const TOKEN_LOCK_TIMEOUT_MS = 20_000;
const TOKEN_LOCK_STALE_MS = 120_000;
const tokenLockPath = `${tokenCachePath}.lock`;

export interface OktaTokens {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
  scope: string;
  obtained_at: number;
}

export interface OidcMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  id_token_signing_alg_values_supported: string[];
  revocation_endpoint?: string;
}

interface TokenCacheContext {
  orgUrl: string;
  clientId: string;
  authServerId: string;
  scopes: string;
}

interface TokenCacheRecord {
  context: TokenCacheContext;
  tokens: OktaTokens;
}

export interface TokenCacheStatus {
  present: boolean;
  contextMatches: boolean;
  expired?: boolean;
  expiresAt?: string;
  refreshTokenAvailable?: boolean;
  grantedScopes?: string[];
}

export interface AuthorizationSession {
  authorizationUrl: string;
  redirectUri: string;
  completion: Promise<OktaTokens>;
  cancel: () => void;
}

export class AuthenticationRequiredError extends Error {
  constructor(message = "Okta authentication is required.") {
    super(message);
    this.name = "AuthenticationRequiredError";
  }
}

function base64url(buffer: Buffer): string {
  return buffer.toString("base64url");
}

function generatePKCE(): { verifier: string; challenge: string } {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(
    crypto.createHash("sha256").update(verifier).digest()
  );
  return { verifier, challenge };
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected a JSON object.");
  }
  return value as Record<string, unknown>;
}

function expectedIssuer(config: OktaMcpConfig): string {
  return config.authServer === "org"
    ? config.orgUrl
    : `${config.orgUrl}/oauth2/${config.authServer}`;
}

export function oidcDiscoveryUrl(config: OktaMcpConfig): string {
  return config.authServer === "org"
    ? `${config.orgUrl}/.well-known/openid-configuration`
    : `${config.orgUrl}/oauth2/${config.authServer}/.well-known/openid-configuration`;
}

function assertTrustedEndpoint(
  value: unknown,
  field: string,
  config: OktaMcpConfig
): string {
  if (typeof value !== "string") {
    throw new Error(`OIDC discovery is missing ${field}.`);
  }

  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    throw new Error(`OIDC discovery returned an invalid ${field}.`);
  }

  const configuredOrigin = new URL(config.orgUrl).origin;
  const insecureLoopbackTestMode =
    endpoint.protocol === "http:" &&
    (endpoint.hostname === "127.0.0.1" || endpoint.hostname === "[::1]") &&
    ["1", "true", "yes"].includes(
      (process.env.OKTA_MCP_ALLOW_INSECURE_HTTP || "").toLowerCase()
    );
  if (endpoint.protocol !== "https:" && !insecureLoopbackTestMode) {
    throw new Error(`OIDC ${field} must use HTTPS.`);
  }
  if (endpoint.origin !== configuredOrigin) {
    throw new Error(
      `OIDC ${field} points to an unexpected origin (${endpoint.origin}).`
    );
  }
  if (endpoint.username || endpoint.password) {
    throw new Error(`OIDC ${field} must not include URL credentials.`);
  }
  if (endpoint.hash) {
    throw new Error(`OIDC ${field} must not include a URL fragment.`);
  }
  return endpoint.toString();
}

const metadataCache = new Map<string, OidcMetadata>();
const jwksCache = new Map<
  string,
  ReturnType<typeof createRemoteJWKSet>
>();

const SAFE_ID_TOKEN_ALGORITHMS = new Set([
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
]);

function configKey(config: OktaMcpConfig): string {
  return [config.orgUrl, config.clientId, config.authServer, config.scopes].join("\n");
}

export async function discoverOidcMetadata(
  config: OktaMcpConfig,
  options: { force?: boolean; timeoutMs?: number } = {}
): Promise<OidcMetadata> {
  const key = configKey(config);
  if (!options.force) {
    const cached = metadataCache.get(key);
    if (cached) return cached;
  }

  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(),
    options.timeoutMs ?? FETCH_TIMEOUT_MS
  );

  try {
    const response = await fetch(oidcDiscoveryUrl(config), {
      headers: { Accept: "application/json" },
      redirect: "error",
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`OIDC discovery failed with HTTP ${response.status}.`);
    }
    const data = asRecord(await response.json());
    if (data.issuer !== expectedIssuer(config)) {
      throw new Error(
        `OIDC issuer mismatch: expected ${expectedIssuer(config)}, received ${String(data.issuer)}.`
      );
    }

    if (!Array.isArray(data.id_token_signing_alg_values_supported)) {
      throw new Error(
        "OIDC discovery is missing id_token_signing_alg_values_supported."
      );
    }
    const signingAlgorithms = data.id_token_signing_alg_values_supported.filter(
      (value): value is string =>
        typeof value === "string" && SAFE_ID_TOKEN_ALGORITHMS.has(value)
    );
    if (signingAlgorithms.length === 0) {
      throw new Error(
        "OIDC discovery did not advertise a supported asymmetric ID-token signing algorithm."
      );
    }

    const metadata: OidcMetadata = {
      issuer: data.issuer,
      authorization_endpoint: assertTrustedEndpoint(
        data.authorization_endpoint,
        "authorization_endpoint",
        config
      ),
      token_endpoint: assertTrustedEndpoint(
        data.token_endpoint,
        "token_endpoint",
        config
      ),
      userinfo_endpoint: assertTrustedEndpoint(
        data.userinfo_endpoint,
        "userinfo_endpoint",
        config
      ),
      jwks_uri: assertTrustedEndpoint(data.jwks_uri, "jwks_uri", config),
      id_token_signing_alg_values_supported: signingAlgorithms,
      revocation_endpoint:
        data.revocation_endpoint === undefined
          ? undefined
          : assertTrustedEndpoint(
              data.revocation_endpoint,
              "revocation_endpoint",
              config
            ),
    };
    metadataCache.set(key, metadata);
    return metadata;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("OIDC discovery timed out.");
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function cacheContext(config: OktaMcpConfig): TokenCacheContext {
  return {
    orgUrl: config.orgUrl,
    clientId: config.clientId,
    authServerId: config.authServer,
    scopes: config.scopes,
  };
}

function sameContext(a: TokenCacheContext, b: TokenCacheContext): boolean {
  return (
    a.orgUrl === b.orgUrl &&
    a.clientId === b.clientId &&
    a.authServerId === b.authServerId &&
    a.scopes === b.scopes
  );
}

function parseTokens(value: unknown): OktaTokens {
  const data = asRecord(value);
  if (
    typeof data.access_token !== "string" ||
    typeof data.token_type !== "string" ||
    typeof data.expires_in !== "number" ||
    !Number.isFinite(data.expires_in) ||
    typeof data.scope !== "string" ||
    typeof data.obtained_at !== "number"
  ) {
    throw new Error("Token cache contains an invalid token record.");
  }
  if (data.refresh_token !== undefined && typeof data.refresh_token !== "string") {
    throw new Error("Token cache contains an invalid refresh token.");
  }
  if (data.id_token !== undefined && typeof data.id_token !== "string") {
    throw new Error("Token cache contains an invalid ID token.");
  }
  return data as unknown as OktaTokens;
}

function loadTokenRecord(): TokenCacheRecord | null {
  if (!fs.existsSync(tokenCachePath)) return null;
  try {
    const data = asRecord(JSON.parse(fs.readFileSync(tokenCachePath, "utf8")));
    const contextData = asRecord(data.context);
    const context: TokenCacheContext = {
      orgUrl: String(contextData.orgUrl || ""),
      clientId: String(contextData.clientId || ""),
      authServerId: String(contextData.authServerId || ""),
      scopes: String(contextData.scopes || ""),
    };
    return { context, tokens: parseTokens(data.tokens) };
  } catch {
    return null;
  }
}

function saveTokens(tokens: OktaTokens, config: OktaMcpConfig): void {
  writePrivateJson(tokenCachePath, {
    context: cacheContext(config),
    tokens,
  } satisfies TokenCacheRecord);
}

async function withTokenCacheLock<T>(operation: () => Promise<T>): Promise<T> {
  const deadline = Date.now() + TOKEN_LOCK_TIMEOUT_MS;
  let descriptor: number | undefined;

  while (descriptor === undefined) {
    try {
      descriptor = fs.openSync(tokenLockPath, "wx", 0o600);
      fs.writeFileSync(descriptor, `${process.pid} ${Date.now()}\n`, "utf8");
    } catch (error) {
      const code =
        error && typeof error === "object" && "code" in error
          ? String(error.code)
          : "";
      if (code !== "EEXIST") throw error;

      try {
        const age = Date.now() - fs.statSync(tokenLockPath).mtimeMs;
        if (age > TOKEN_LOCK_STALE_MS) {
          fs.rmSync(tokenLockPath);
          continue;
        }
      } catch (statError) {
        const statCode =
          statError && typeof statError === "object" && "code" in statError
            ? String(statError.code)
            : "";
        if (statCode === "ENOENT") continue;
        throw statError;
      }

      if (Date.now() >= deadline) {
        throw new Error("Timed out waiting for another Okta token refresh to finish.");
      }
      await new Promise((resolve) => setTimeout(resolve, 75));
    }
  }

  try {
    return await operation();
  } finally {
    fs.closeSync(descriptor);
    try {
      fs.rmSync(tokenLockPath);
    } catch (error) {
      const code =
        error && typeof error === "object" && "code" in error
          ? String(error.code)
          : "";
      if (code !== "ENOENT") throw error;
    }
  }
}

export function clearTokenCache(): void {
  if (fs.existsSync(tokenCachePath)) fs.rmSync(tokenCachePath);
}

export function invalidateTokenCache(
  config: OktaMcpConfig,
  tokens: OktaTokens
): boolean {
  const latest = loadTokenRecord();
  if (
    !latest ||
    !sameContext(latest.context, cacheContext(config)) ||
    latest.tokens.access_token !== tokens.access_token
  ) {
    return false;
  }
  clearTokenCache();
  return true;
}

export function isTokenExpired(tokens: OktaTokens): boolean {
  const elapsed = (Date.now() - tokens.obtained_at) / 1000;
  return elapsed >= tokens.expires_in - 60;
}

export function inspectTokenCache(config: OktaMcpConfig): TokenCacheStatus {
  const record = loadTokenRecord();
  if (!record) return { present: false, contextMatches: false };

  const contextMatches = sameContext(record.context, cacheContext(config));
  if (!contextMatches) return { present: true, contextMatches: false };

  const expiresAt = new Date(
    record.tokens.obtained_at + record.tokens.expires_in * 1000
  ).toISOString();
  return {
    present: true,
    contextMatches: true,
    expired: isTokenExpired(record.tokens),
    expiresAt,
    refreshTokenAvailable: Boolean(record.tokens.refresh_token),
    grantedScopes: record.tokens.scope.split(/\s+/).filter(Boolean),
  };
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMessage: string
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, {
      redirect: "error",
      ...init,
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(timeoutMessage);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function oauthError(response: Response, operation: string): Promise<Error> {
  let detail = "";
  try {
    const data = asRecord(await response.json());
    const code = typeof data.error === "string" ? data.error : "";
    const description =
      typeof data.error_description === "string" ? data.error_description : "";
    detail = [code, description].filter(Boolean).join(": ");
  } catch {
    // Do not surface arbitrary response bodies because they may contain credentials.
  }
  return new Error(
    `${operation} failed with HTTP ${response.status}${detail ? ` (${detail})` : ""}.`
  );
}

function tokensFromResponse(
  value: unknown,
  requestedScopes: string,
  previous?: OktaTokens
): OktaTokens {
  const data = asRecord(value);
  if (
    typeof data.access_token !== "string" ||
    typeof data.token_type !== "string" ||
    typeof data.expires_in !== "number"
  ) {
    throw new Error("Okta returned an invalid token response.");
  }

  return {
    access_token: data.access_token,
    token_type: data.token_type,
    expires_in: data.expires_in,
    scope:
      typeof data.scope === "string"
        ? data.scope
        : previous?.scope || requestedScopes,
    refresh_token:
      typeof data.refresh_token === "string"
        ? data.refresh_token
        : previous?.refresh_token,
    id_token: typeof data.id_token === "string" ? data.id_token : undefined,
    obtained_at: Date.now(),
  };
}

export async function verifyIdToken(
  config: OktaMcpConfig,
  idToken: string,
  expectedNonce?: string
): Promise<JWTPayload> {
  const metadata = await discoverOidcMetadata(config);
  let jwks = jwksCache.get(metadata.jwks_uri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(metadata.jwks_uri), {
      timeoutDuration: FETCH_TIMEOUT_MS,
      cooldownDuration: 30_000,
      [customFetch]: (url, init) =>
        fetch(url, {
          ...init,
          redirect: "error",
        }),
    });
    jwksCache.set(metadata.jwks_uri, jwks);
  }

  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(idToken, jwks, {
      issuer: metadata.issuer,
      audience: config.clientId,
      algorithms: metadata.id_token_signing_alg_values_supported,
      requiredClaims: ["exp", "iat", "sub"],
      clockTolerance: 60,
    }));
  } catch {
    throw new Error("Okta ID token signature or claims validation failed.");
  }

  if (expectedNonce !== undefined && payload.nonce !== expectedNonce) {
    throw new Error("Okta ID token nonce validation failed.");
  }
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (
    (audiences.length > 1 || payload.azp !== undefined) &&
    payload.azp !== config.clientId
  ) {
    throw new Error("Okta ID token authorized-party validation failed.");
  }
  if (typeof payload.iat !== "number" || payload.iat > Date.now() / 1000 + 60) {
    throw new Error("Okta ID token issued-at claim is invalid.");
  }
  return payload;
}

async function refreshAccessTokenUnlocked(
  config: OktaMcpConfig,
  tokens: OktaTokens
): Promise<OktaTokens> {
  if (!tokens.refresh_token) throw new AuthenticationRequiredError();
  const metadata = await discoverOidcMetadata(config);
  const response = await fetchWithTimeout(
    metadata.token_endpoint,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: config.clientId,
      }),
    },
    "Okta token refresh timed out."
  );

  if (!response.ok) {
    if (response.status === 400 || response.status === 401) {
      const latest = loadTokenRecord();
      if (
        latest &&
        sameContext(latest.context, cacheContext(config)) &&
        latest.tokens.access_token !== tokens.access_token &&
        !isTokenExpired(latest.tokens)
      ) {
        return latest.tokens;
      }
      invalidateTokenCache(config, tokens);
      throw new AuthenticationRequiredError(
        "The cached Okta session can no longer be refreshed. Run login again."
      );
    }
    throw await oauthError(response, "Token refresh");
  }

  const refreshed = tokensFromResponse(await response.json(), config.scopes, tokens);
  if (refreshed.id_token) {
    try {
      await verifyIdToken(config, refreshed.id_token);
    } catch (error) {
      invalidateTokenCache(config, tokens);
      throw new AuthenticationRequiredError(
        error instanceof Error
          ? `Okta returned an invalid refreshed ID token: ${error.message}`
          : "Okta returned an invalid refreshed ID token."
      );
    }
  }
  saveTokens(refreshed, config);
  return refreshed;
}

export async function refreshAccessToken(
  config: OktaMcpConfig,
  tokens: OktaTokens
): Promise<OktaTokens> {
  return withTokenCacheLock(async () => {
    const latest = loadTokenRecord();
    let candidate = tokens;
    if (latest && sameContext(latest.context, cacheContext(config))) {
      if (
        latest.tokens.access_token !== tokens.access_token &&
        !isTokenExpired(latest.tokens)
      ) {
        if (latest.tokens.id_token) {
          await verifyIdToken(config, latest.tokens.id_token);
        }
        return latest.tokens;
      }
      candidate = latest.tokens;
    }
    return refreshAccessTokenUnlocked(config, candidate);
  });
}

export async function getAuthenticatedTokens(
  config: OktaMcpConfig
): Promise<OktaTokens | null> {
  const record = loadTokenRecord();
  if (!record || !sameContext(record.context, cacheContext(config))) return null;
  if (!isTokenExpired(record.tokens)) {
    if (record.tokens.id_token) {
      try {
        await verifyIdToken(config, record.tokens.id_token);
      } catch {
        invalidateTokenCache(config, record.tokens);
        return null;
      }
    }
    return record.tokens;
  }
  if (!record.tokens.refresh_token) return null;

  try {
    return await refreshAccessToken(config, record.tokens);
  } catch (error) {
    if (error instanceof AuthenticationRequiredError) return null;
    throw error;
  }
}

function htmlResponse(response: http.ServerResponse, status: number, body: string): void {
  response.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(
    `<!doctype html><meta charset="utf-8"><title>Okta MCP</title>` +
      `<style>body{font:16px system-ui;max-width:42rem;margin:5rem auto;padding:0 1rem}</style>` +
      body
  );
}

export async function startAuthorization(
  config: OktaMcpConfig
): Promise<AuthorizationSession> {
  const metadata = await discoverOidcMetadata(config);
  const { verifier, challenge } = generatePKCE();
  const state = base64url(crypto.randomBytes(24));
  const nonce = base64url(crypto.randomBytes(24));
  const redirectUri = `http://${config.callbackHost}:${config.callbackPort}/callback`;
  let exchangeInFlight = false;
  let settled = false;
  let timer: NodeJS.Timeout | undefined;
  let resolveCompletion!: (tokens: OktaTokens) => void;
  let rejectCompletion!: (error: Error) => void;

  const completion = new Promise<OktaTokens>((resolve, reject) => {
    resolveCompletion = resolve;
    rejectCompletion = reject;
  });
  // A URL-elicitation client may take time before awaiting completion.
  completion.catch(() => {});

  const server = http.createServer(async (request, response) => {
    if (request.method !== "GET") {
      response.writeHead(405, { Allow: "GET" });
      response.end();
      return;
    }

    const requestUrl = new URL(request.url || "/", redirectUri);
    if (requestUrl.pathname !== "/callback") {
      response.writeHead(404);
      response.end();
      return;
    }

    if (requestUrl.searchParams.get("state") !== state) {
      htmlResponse(
        response,
        400,
        "<h1>Authentication request not recognized</h1><p>Return to your MCP client and try again.</p>"
      );
      return;
    }

    const oauthFailure = requestUrl.searchParams.get("error");
    if (oauthFailure) {
      htmlResponse(
        response,
        400,
        "<h1>Authentication was not completed</h1><p>You can close this tab.</p>"
      );
      finish(new Error(`Okta authorization failed (${oauthFailure}).`));
      return;
    }

    const code = requestUrl.searchParams.get("code");
    if (!code) {
      htmlResponse(response, 400, "<h1>Missing authorization code</h1>");
      return;
    }
    if (exchangeInFlight) {
      htmlResponse(response, 409, "<h1>Authentication is already being completed</h1>");
      return;
    }
    exchangeInFlight = true;

    try {
      const tokenResponse = await fetchWithTimeout(
        metadata.token_endpoint,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            client_id: config.clientId,
            redirect_uri: redirectUri,
            code_verifier: verifier,
          }),
        },
        "Okta token exchange timed out."
      );
      if (!tokenResponse.ok) {
        throw await oauthError(tokenResponse, "Token exchange");
      }

      const tokens = tokensFromResponse(await tokenResponse.json(), config.scopes);
      if (!tokens.id_token) {
        throw new Error("Okta did not return the required ID token.");
      }
      await verifyIdToken(config, tokens.id_token, nonce);
      saveTokens(tokens, config);
      htmlResponse(
        response,
        200,
        "<h1>Connected to Okta</h1><p>You can close this tab and return to your MCP client.</p>"
      );
      finish(undefined, tokens);
    } catch (error) {
      htmlResponse(
        response,
        500,
        "<h1>Authentication could not be completed</h1><p>Return to your MCP client for details.</p>"
      );
      finish(error instanceof Error ? error : new Error(String(error)));
    }
  });

  function cleanup(): void {
    if (timer) clearTimeout(timer);
    timer = undefined;
    server.close();
  }

  function finish(error?: Error, tokens?: OktaTokens): void {
    if (settled) return;
    settled = true;
    cleanup();
    if (error) rejectCompletion(error);
    else resolveCompletion(tokens as OktaTokens);
  }

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(config.callbackPort, config.callbackHost);
  }).catch((error) => {
    cleanup();
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Could not start the OAuth callback on ${config.callbackHost}:${config.callbackPort}: ${detail}`
    );
  });

  server.on("error", (error) => finish(error));
  timer = setTimeout(
    () => finish(new Error("Okta authentication timed out.")),
    AUTH_TIMEOUT_MS
  );

  const authorizationUrl = new URL(metadata.authorization_endpoint);
  authorizationUrl.searchParams.set("client_id", config.clientId);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("scope", config.scopes);
  authorizationUrl.searchParams.set("redirect_uri", redirectUri);
  authorizationUrl.searchParams.set("state", state);
  authorizationUrl.searchParams.set("nonce", nonce);
  authorizationUrl.searchParams.set("code_challenge", challenge);
  authorizationUrl.searchParams.set("code_challenge_method", "S256");

  return {
    authorizationUrl: authorizationUrl.toString(),
    redirectUri,
    completion,
    cancel: () => finish(new Error("Okta authentication was cancelled.")),
  };
}

export async function browserAuth(config: OktaMcpConfig): Promise<OktaTokens> {
  const session = await startAuthorization(config);
  try {
    const open = (await import("open")).default;
    await open(session.authorizationUrl);
  } catch (error) {
    session.cancel();
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Could not open the Okta sign-in page: ${detail}`);
  }
  return session.completion;
}

export async function revokeAndClearTokens(
  config: OktaMcpConfig
): Promise<{ revoked: boolean; localCacheCleared: boolean }> {
  const record = loadTokenRecord();
  if (!record) {
    clearTokenCache();
    return { revoked: false, localCacheCleared: true };
  }

  let revocationConfig = config;
  if (!sameContext(record.context, cacheContext(config))) {
    try {
      revocationConfig = makeConfig({
        orgUrl: record.context.orgUrl,
        clientId: record.context.clientId,
        authServer: record.context.authServerId,
        scopes: record.context.scopes,
        callbackPort: DEFAULT_CALLBACK_PORT,
      });
    } catch {
      clearTokenCache();
      return { revoked: false, localCacheCleared: true };
    }
  }

  let revoked = false;
  try {
    const metadata = await discoverOidcMetadata(revocationConfig);
    if (metadata.revocation_endpoint) {
      const candidates = [
        record.tokens.refresh_token
          ? { token: record.tokens.refresh_token, hint: "refresh_token" }
          : undefined,
        { token: record.tokens.access_token, hint: "access_token" },
      ].filter(
        (candidate): candidate is { token: string; hint: string } =>
          candidate !== undefined
      );

      for (const candidate of candidates) {
        const response = await fetchWithTimeout(
          metadata.revocation_endpoint,
          {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              token: candidate.token,
              token_type_hint: candidate.hint,
              client_id: revocationConfig.clientId,
            }),
          },
          "Okta token revocation timed out."
        );
        if (!response.ok) throw await oauthError(response, "Token revocation");
      }
      revoked = true;
    }
  } finally {
    clearTokenCache();
  }

  return { revoked, localCacheCleared: true };
}
