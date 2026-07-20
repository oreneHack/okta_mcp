import {
  discoverOidcMetadata,
  invalidateTokenCache,
  verifyIdToken,
  type OktaTokens,
} from "./auth.js";
import type { OktaMcpConfig } from "./config.js";
import type { JWTPayload } from "jose";

const API_TIMEOUT_MS = 15_000;

export class OktaApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
    readonly path: string
  ) {
    super(message);
    this.name = "OktaApiError";
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Okta returned an unexpected JSON response.");
  }
  return value as Record<string, unknown>;
}

function decodeJwtPart(jwt: string, index: number): Record<string, unknown> {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("Token is not a JWT.");
  return asRecord(
    JSON.parse(Buffer.from(parts[index], "base64url").toString("utf8"))
  );
}

async function fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  try {
    return await fetch(url, {
      redirect: "error",
      ...init,
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("Okta API request timed out.");
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export class OktaClient {
  private constructor(
    private readonly config: OktaMcpConfig,
    private readonly tokens: OktaTokens,
    private readonly userinfoEndpoint: string,
    private readonly idTokenClaims?: JWTPayload
  ) {}

  static async create(
    config: OktaMcpConfig,
    tokens: OktaTokens
  ): Promise<OktaClient> {
    const metadata = await discoverOidcMetadata(config);
    const idTokenClaims = tokens.id_token
      ? await verifyIdToken(config, tokens.id_token)
      : undefined;
    return new OktaClient(
      config,
      tokens,
      metadata.userinfo_endpoint,
      idTokenClaims
    );
  }

  private async parseJson(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch {
      throw new Error("Okta returned a non-JSON response.");
    }
  }

  private async apiFetch(path: string): Promise<unknown> {
    const response = await fetchWithTimeout(`${this.config.orgUrl}${path}`, {
      headers: {
        Authorization: `Bearer ${this.tokens.access_token}`,
        Accept: "application/json",
      },
    });

    if (response.ok) return this.parseJson(response);

    if (response.status === 401) {
      invalidateTokenCache(this.config, this.tokens);
      throw new OktaApiError(
        "Okta rejected the cached authorization. Run okta-login again.",
        401,
        "authentication_required",
        path
      );
    }
    if (response.status === 403) {
      throw new OktaApiError(
        "The signed-in user or OIDC app lacks the required Okta scope, grant, or admin role.",
        403,
        "insufficient_authorization",
        path
      );
    }
    if (response.status === 429) {
      const retryAfter = response.headers.get("retry-after");
      throw new OktaApiError(
        `Okta rate limit reached${retryAfter ? `; Retry-After is ${retryAfter}` : ""}.`,
        429,
        "rate_limited",
        path
      );
    }

    throw new OktaApiError(
      `Okta API request failed with HTTP ${response.status}.`,
      response.status,
      "api_error",
      path
    );
  }

  async userinfo(): Promise<Record<string, unknown>> {
    const response = await fetchWithTimeout(this.userinfoEndpoint, {
      headers: {
        Authorization: `Bearer ${this.tokens.access_token}`,
        Accept: "application/json",
      },
    });
    if (!response.ok) {
      if (response.status === 401) {
        invalidateTokenCache(this.config, this.tokens);
        throw new OktaApiError(
          "Okta authorization is no longer valid. Run okta-login again.",
          401,
          "authentication_required",
          new URL(this.userinfoEndpoint).pathname
        );
      }
      throw new OktaApiError(
        `Okta userinfo failed with HTTP ${response.status}.`,
        response.status,
        "userinfo_error",
        new URL(this.userinfoEndpoint).pathname
      );
    }
    const profile = asRecord(await this.parseJson(response));
    if (
      this.idTokenClaims?.sub !== undefined &&
      profile.sub !== this.idTokenClaims.sub
    ) {
      invalidateTokenCache(this.config, this.tokens);
      throw new OktaApiError(
        "Okta userinfo subject did not match the verified ID token. Reconnect before retrying.",
        401,
        "authentication_required",
        new URL(this.userinfoEndpoint).pathname
      );
    }
    return profile;
  }

  async whoami(): Promise<unknown> {
    const profile = await this.userinfo();
    return {
      organization: this.config.orgUrl,
      issuer:
        this.config.authServer === "org"
          ? this.config.orgUrl
          : `${this.config.orgUrl}/oauth2/${this.config.authServer}`,
      subject: profile.sub,
      name: profile.name,
      preferred_username: profile.preferred_username,
      email: profile.email,
      email_verified: profile.email_verified,
      granted_scopes: this.tokens.scope.split(/\s+/).filter(Boolean),
      profile,
    };
  }

  tokenDetails(): unknown {
    const obtainedAt = new Date(this.tokens.obtained_at);
    const expiresAt = new Date(
      this.tokens.obtained_at + this.tokens.expires_in * 1000
    );
    const accessTokenParts = this.tokens.access_token.split(".");
    let jwtHeader: Record<string, unknown> | undefined;
    if (accessTokenParts.length === 3) {
      try {
        jwtHeader = decodeJwtPart(this.tokens.access_token, 0);
      } catch {
        // Token format is diagnostic only; do not depend on Okta org-token internals.
      }
    }

    return {
      token_type: this.tokens.token_type,
      access_token_format: accessTokenParts.length === 3 ? "JWT" : "opaque",
      jwt_header: jwtHeader,
      granted_scopes: this.tokens.scope.split(/\s+/).filter(Boolean),
      obtained_at: obtainedAt.toISOString(),
      expires_at: expiresAt.toISOString(),
      expires_in_seconds: Math.max(
        0,
        Math.floor((expiresAt.getTime() - Date.now()) / 1000)
      ),
      refresh_token_available: Boolean(this.tokens.refresh_token),
      id_token_available: Boolean(this.tokens.id_token),
      note: "Bearer token values and unstable access-token claims are intentionally omitted.",
    };
  }

  myGroups(): unknown {
    if (!this.idTokenClaims) {
      return {
        groups: [],
        note:
          "No current verified ID token is available. Reconnect, or retry after a refresh that returns a new ID token.",
      };
    }

    const groups = this.idTokenClaims.groups || this.idTokenClaims.Groups;
    if (!Array.isArray(groups) || !groups.every((group) => typeof group === "string")) {
      return {
        groups: [],
        note:
          'No "groups" claim is present in the ID token. Configure an Okta groups claim for this OIDC app if needed.',
      };
    }
    return { subject: this.idTokenClaims.sub, groups };
  }

  async listUsers(limit = 25): Promise<unknown> {
    return this.apiFetch(`/api/v1/users?limit=${limit}`);
  }

  async getUser(userId: string): Promise<unknown> {
    return this.apiFetch(`/api/v1/users/${encodeURIComponent(userId)}`);
  }

  async searchUsers(query: string): Promise<unknown> {
    return this.apiFetch(
      `/api/v1/users?search=${encodeURIComponent(query)}&limit=100`
    );
  }

  async listGroups(limit = 25): Promise<unknown> {
    return this.apiFetch(`/api/v1/groups?limit=${limit}`);
  }

  async listApps(limit = 25): Promise<unknown> {
    return this.apiFetch(`/api/v1/apps?limit=${limit}`);
  }

  async myAppLinks(): Promise<unknown> {
    const profile = await this.userinfo();
    const subject = profile.sub;
    if (typeof subject !== "string" || !subject) {
      throw new Error("Okta userinfo did not include a subject identifier.");
    }
    return this.apiFetch(`/api/v1/users/${encodeURIComponent(subject)}/appLinks`);
  }
}
