import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const DEFAULT_ENDPOINT =
  "http://127.0.0.1:8765/v1/cookie-proofs";

function usage() {
  console.error(
    "Usage: node scripts/post-cookie-proof.mjs <cookie-json-path> [endpoint]"
  );
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizeCookieJar(raw) {
  if (!raw || typeof raw !== "object" || !Array.isArray(raw.cookies)) {
    throw new Error("Cookie file must be a JSON object with a cookies array.");
  }

  const cookies = raw.cookies.filter(
    (cookie) => cookie && typeof cookie === "object" && typeof cookie.name === "string"
  );
  if (!cookies.length) {
    throw new Error("Cookie file does not contain any cookies.");
  }

  const orgHost =
    raw.org_host ||
    cookies.find((cookie) => typeof cookie.domain === "string")?.domain ||
    "";
  if (!orgHost) throw new Error("Unable to determine org host from cookie file.");

  return {
    captured_at: raw.captured_at || null,
    org_host: orgHost,
    cookies: cookies.map((cookie) => ({
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

const sourcePath = process.argv[2];
const endpoint = process.argv[3] || DEFAULT_ENDPOINT;

if (!sourcePath) {
  usage();
  process.exit(1);
}

if (!fs.existsSync(sourcePath)) {
  console.error(`Error: file not found: ${sourcePath}`);
  process.exit(1);
}

const raw = JSON.parse(fs.readFileSync(sourcePath, "utf8"));
const payload = normalizeCookieJar(raw);

const response = await fetch(endpoint, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(payload),
});

const text = await response.text();
if (!response.ok) {
  console.error(text);
  process.exit(1);
}

console.log(text);
