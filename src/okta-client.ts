let _orgUrl = "";
let _accessToken = "";
let _authServer = "default"; // custom auth server ID

export function configure(
  orgUrl: string,
  accessToken: string,
  authServer = "default"
): void {
  _orgUrl = orgUrl;
  _accessToken = accessToken;
  _authServer = authServer;
}

// JWT decoding for local claim display only.

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT");
  const payload = Buffer.from(parts[1], "base64url").toString("utf-8");
  return JSON.parse(payload);
}

// --- API helpers ---

function oidcBase(): string {
  // Mirror auth.ts: "org"/empty selects org AS; otherwise use a custom AS.
  if (!_authServer || _authServer === "org") return `${_orgUrl}/oauth2/v1`;
  return `${_orgUrl}/oauth2/${_authServer}/v1`;
}

async function userinfoFetch(): Promise<unknown> {
  const resp = await fetch(`${oidcBase()}/userinfo`, {
    headers: { Authorization: `Bearer ${_accessToken}` },
  });
  if (!resp.ok) throw new Error(`Userinfo ${resp.status}: ${await resp.text()}`);
  return resp.json();
}

async function oktaApiFetch(path: string): Promise<unknown> {
  const resp = await fetch(`${_orgUrl}${path}`, {
    headers: {
      Authorization: `Bearer ${_accessToken}`,
      Accept: "application/json",
    },
  });
  if (!resp.ok) {
    const body = await resp.text();
    // Non-admin users: the token carries the okta.* scope but the user's
    // role gates the data, so the management API answers 403. Surface it as a
    // clean message instead of throwing, so identity tools still shine.
    if (resp.status === 403) {
      return {
        error: "insufficient_role",
        detail:
          "Token has the required scope but this user lacks the admin role " +
          "for this endpoint. Identity tools (whoami/userinfo) still work.",
        status: 403,
        path,
      };
    }
    throw new Error(`Okta API ${resp.status}: ${body}`);
  }
  return resp.json();
}

// Tools that work for any authorized user via token claims and userinfo.

export function whoami(): unknown {
  const claims = decodeJwtPayload(_accessToken);
  return {
    subject: claims.sub,
    client_id: claims.cid,
    issuer: claims.iss,
    scopes: claims.scp,
    groups: claims.groups || claims.Groups || "not included in token",
    app_roles: claims.appRoles || claims.roles || "not included in token",
    issued_at: claims.iat
      ? new Date((claims.iat as number) * 1000).toISOString()
      : undefined,
    expires_at: claims.exp
      ? new Date((claims.exp as number) * 1000).toISOString()
      : undefined,
    all_claims: claims,
  };
}

export async function userinfo(): Promise<unknown> {
  return userinfoFetch();
}

export function tokenDetails(): unknown {
  const claims = decodeJwtPayload(_accessToken);
  return {
    token_type: "access_token (JWT)",
    algorithm: JSON.parse(
      Buffer.from(_accessToken.split(".")[0], "base64url").toString()
    ),
    issuer: claims.iss,
    audience: claims.aud,
    client_id: claims.cid,
    user_id: claims.uid,
    subject: claims.sub,
    scopes: claims.scp,
    groups: claims.groups || claims.Groups || null,
    auth_time: claims.auth_time
      ? new Date((claims.auth_time as number) * 1000).toISOString()
      : undefined,
    issued_at: claims.iat
      ? new Date((claims.iat as number) * 1000).toISOString()
      : undefined,
    expires_at: claims.exp
      ? new Date((claims.exp as number) * 1000).toISOString()
      : undefined,
    custom_claims: Object.fromEntries(
      Object.entries(claims).filter(
        ([k]) =>
          ![
            "ver", "jti", "iss", "aud", "iat", "exp", "cid", "uid",
            "scp", "sub", "auth_time",
          ].includes(k)
      )
    ),
  };
}

export function myGroups(): unknown {
  const claims = decodeJwtPayload(_accessToken);
  const groups = claims.groups || claims.Groups;
  if (!groups) {
    return {
      error:
        'No "groups" claim in token. Configure the authorization server to include a "groups" claim in access tokens.',
    };
  }
  return { user: claims.sub, groups };
}

// ── Tools that need Okta API scopes (admin or scoped access) ──

export async function listUsers(limit = 25): Promise<unknown> {
  return oktaApiFetch(`/api/v1/users?limit=${limit}`);
}

export async function getUser(userId: string): Promise<unknown> {
  return oktaApiFetch(`/api/v1/users/${encodeURIComponent(userId)}`);
}

export async function searchUsers(query: string): Promise<unknown> {
  return oktaApiFetch(
    `/api/v1/users?search=${encodeURIComponent(query)}&limit=100`
  );
}

export async function listGroups(limit = 25): Promise<unknown> {
  return oktaApiFetch(`/api/v1/groups?limit=${limit}`);
}

export async function listApps(limit = 25): Promise<unknown> {
  return oktaApiFetch(`/api/v1/apps?limit=${limit}`);
}

export async function myAppLinks(): Promise<unknown> {
  const claims = decodeJwtPayload(_accessToken);
  const uid = claims.uid as string;
  if (!uid) return { error: "No uid in token claims" };
  return oktaApiFetch(`/api/v1/users/${uid}/appLinks`);
}
