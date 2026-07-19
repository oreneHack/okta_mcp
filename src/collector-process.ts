import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);
const COLLECTOR_SERVICE = "okta-mcp-local-collector";
const START_TIMEOUT_MS = 10_000;

export interface CollectorStatus {
  endpoint: string;
  health_url: string;
  started: boolean;
  pid?: number;
}

function collectorUrls(endpoint: string): {
  endpointUrl: URL;
  healthUrl: URL;
} | null {
  if (!endpoint) return null;

  const endpointUrl = new URL(endpoint);
  if (
    endpointUrl.protocol !== "http:" ||
    !LOOPBACK_HOSTS.has(endpointUrl.hostname)
  ) {
    return null;
  }
  if (endpointUrl.pathname !== "/v1/cookie-proofs") {
    throw new Error(
      `Local cookie-proof endpoint must use /v1/cookie-proofs, received ${endpointUrl.pathname}.`
    );
  }

  const healthUrl = new URL(endpointUrl.origin);
  healthUrl.pathname = "/health";
  return { endpointUrl, healthUrl };
}

async function collectorIsHealthy(healthUrl: URL): Promise<boolean> {
  try {
    const response = await fetch(healthUrl, { signal: AbortSignal.timeout(1_000) });
    if (!response.ok) return false;
    const body = (await response.json()) as { ok?: boolean; service?: string };
    return body.ok === true && body.service === COLLECTOR_SERVICE;
  } catch {
    return false;
  }
}

export async function ensureCookieProofCollector(
  endpoint: string
): Promise<CollectorStatus | null> {
  const urls = collectorUrls(endpoint);
  if (!urls) return null;

  const { endpointUrl, healthUrl } = urls;
  if (await collectorIsHealthy(healthUrl)) {
    return {
      endpoint: endpointUrl.href,
      health_url: healthUrl.href,
      started: false,
    };
  }

  const collectorScript = fileURLToPath(
    new URL("../scripts/collector.mjs", import.meta.url)
  );
  const packageRoot = path.dirname(path.dirname(collectorScript));
  const port = endpointUrl.port || "80";
  const host =
    endpointUrl.hostname === "localhost"
      ? "127.0.0.1"
      : endpointUrl.hostname.replace(/^\[|\]$/g, "");

  const child = spawn(process.execPath, [collectorScript], {
    cwd: packageRoot,
    detached: true,
    windowsHide: true,
    stdio: "ignore",
    env: {
      ...process.env,
      OKTA_MCP_COLLECTOR_HOST: host,
      OKTA_MCP_COLLECTOR_PORT: port,
    },
  });
  child.unref();

  const startedAt = Date.now();
  while (Date.now() - startedAt < START_TIMEOUT_MS) {
    if (await collectorIsHealthy(healthUrl)) {
      return {
        endpoint: endpointUrl.href,
        health_url: healthUrl.href,
        started: true,
        pid: child.pid,
      };
    }
    await delay(200);
  }

  throw new Error(
    `Local cookie-proof collector did not become healthy at ${healthUrl.href} within ${START_TIMEOUT_MS}ms.`
  );
}
