import fs from "node:fs";
import path from "node:path";

const DEFAULT_ENDPOINT = "http://127.0.0.1:8765/v1/cookie-proofs";
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

function option(name) {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return undefined;
  const value = process.argv[index + 1];
  return value && !value.startsWith("--") ? value : undefined;
}

function usage() {
  console.error(
    "Usage: node scripts/lab-export-cookie-editor.mjs --org-host <test-org.okta.com> [--endpoint http://127.0.0.1:8765/v1/cookie-proofs]"
  );
}

function normalizeHost(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^\./, "")
    .replace(/\/$/, "");
}

function sameSiteForCookieEditor(value) {
  switch (String(value || "").toLowerCase()) {
    case "none":
    case "no_restriction":
      return "no_restriction";
    case "lax":
      return "lax";
    case "strict":
      return "strict";
    default:
      return null;
  }
}

function cookieBelongsToOrg(cookieDomain, orgHost) {
  const domain = normalizeHost(cookieDomain);
  return domain === orgHost || orgHost.endsWith(`.${domain}`);
}

const expectedOrgHost = normalizeHost(option("org-host"));
const endpoint = new URL(option("endpoint") || DEFAULT_ENDPOINT);

if (!expectedOrgHost) {
  usage();
  process.exit(1);
}

if (!LOOPBACK_HOSTS.has(endpoint.hostname)) {
  throw new Error("The lab export adapter accepts loopback collector URLs only.");
}

if (
  endpoint.pathname !== "/v1/cookie-proofs" &&
  endpoint.pathname !== "/v1/cookie-proofs/latest"
) {
  throw new Error("Unexpected collector path. Use /v1/cookie-proofs or /latest.");
}

const response = await fetch(endpoint);
if (!response.ok) {
  throw new Error(`Collector returned HTTP ${response.status}.`);
}

const proof = await response.json();
const proofOrgHost = normalizeHost(proof.org_host || proof.org_url);
if (proofOrgHost !== expectedOrgHost) {
  throw new Error(
    `Collector proof is for ${proofOrgHost || "an unknown host"}, not ${expectedOrgHost}.`
  );
}

if (!Array.isArray(proof.cookies) || proof.cookies.length === 0) {
  throw new Error("Collector proof does not contain a cookie array.");
}

const missingValues = proof.cookies
  .filter(
    (cookie) =>
      !cookie ||
      typeof cookie.name !== "string" ||
      typeof cookie.display_value !== "string" ||
      cookie.display_value.length === 0
  )
  .map((cookie) => cookie?.name || "<unnamed>");

if (missingValues.length > 0) {
  throw new Error(
    "Collector values are redacted or missing. Re-create the authorized lab proof with --include-cookie-values."
  );
}

const cookieEditorRows = proof.cookies.map((cookie) => {
  if (!cookieBelongsToOrg(cookie.domain, expectedOrgHost)) {
    throw new Error(
      `Cookie ${cookie.name} has domain ${cookie.domain}, outside ${expectedOrgHost}.`
    );
  }

  const session = cookie.session === true || !(Number(cookie.expires) > 0);
  const row = {
    domain: cookie.domain,
    hostOnly: !String(cookie.domain || "").startsWith("."),
    httpOnly: Boolean(cookie.httpOnly),
    name: cookie.name,
    path: cookie.path || "/",
    sameSite: sameSiteForCookieEditor(cookie.sameSite),
    secure: Boolean(cookie.secure),
    session,
    storeId: null,
    value: cookie.display_value,
  };

  if (!session) row.expirationDate = Number(cookie.expires);
  return row;
});

const outputDir = path.resolve(process.cwd(), "collector-output");
fs.mkdirSync(outputDir, { recursive: true, mode: 0o700 });
const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const outputPath = path.join(outputDir, `cookie-editor-import-${stamp}.json`);
fs.writeFileSync(outputPath, JSON.stringify(cookieEditorRows, null, 2), {
  mode: 0o600,
  flag: "wx",
});

console.log(`Saved ${cookieEditorRows.length} Cookie-Editor rows for ${expectedOrgHost}.`);
console.log(`Output: ${outputPath}`);
console.log("Cookie values were written to the file and were not printed.");
