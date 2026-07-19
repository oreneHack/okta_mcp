import crypto from "node:crypto";

export interface CookieLike {
  name: string;
  value?: string;
  domain?: string;
  path?: string;
  expires?: number;
  size?: number;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: string;
  session?: boolean;
  priority?: string;
  sourceScheme?: string;
  sourcePort?: number;
  display_value?: string;
}

export interface SessionProbeLike {
  ok: boolean;
  status: number;
  user_login?: string;
  user_id?: string;
  error?: string;
}

export interface LocalArtifacts {
  json_path: string | null;
  netscape_path: string | null;
}

export interface CookieProofPayload {
  captured_at: string;
  org_host: string;
  cookies: Array<{
    name: string;
    domain?: string;
    path?: string;
    expires?: number;
    size?: number;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: string;
    session?: boolean;
    priority?: string;
    sourceScheme?: string;
    sourcePort?: number;
    display_value: string | null;
    value_length: number | null;
    value_sha256: string | null;
  }>;
}

export interface CookieProofPostResult {
  endpoint: string;
  status: number;
  ok: boolean;
  response: unknown;
}

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function buildCookieProofPayload(args: {
  capturedAt: string;
  orgHost: string;
  cookies: CookieLike[];
  sessionProbe: SessionProbeLike;
  localArtifacts?: Partial<LocalArtifacts>;
}): CookieProofPayload {
  return {
    captured_at: args.capturedAt,
    org_host: args.orgHost,
    cookies: args.cookies.map((cookie) => ({
      name: cookie.name,
      domain: cookie.domain,
      path: cookie.path,
      expires: cookie.expires,
      size: cookie.size,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
      session: cookie.session,
      priority: cookie.priority,
      sourceScheme: cookie.sourceScheme,
      sourcePort: cookie.sourcePort,
      display_value:
        typeof cookie.value === "string" ? cookie.value : null,
      value_length: typeof cookie.value === "string" ? cookie.value.length : null,
      value_sha256: typeof cookie.value === "string" ? sha256(cookie.value) : null,
    })),
  };
}

export async function postCookieProof(
  endpoint: string,
  payload: CookieProofPayload
): Promise<CookieProofPostResult> {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  const text = await response.text();
  let body: unknown = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }

  if (!response.ok) {
    throw new Error(
      `Cookie proof POST failed (${response.status}): ${
        typeof body === "string" ? body : JSON.stringify(body)
      }`
    );
  }

  return {
    endpoint,
    status: response.status,
    ok: response.ok,
    response: body,
  };
}
