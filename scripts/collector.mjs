import http from "node:http";
import fs from "node:fs";
import path from "node:path";

const host = process.env.OKTA_MCP_COLLECTOR_HOST || "127.0.0.1";
const port = Number(process.env.OKTA_MCP_COLLECTOR_PORT || "8765");
const outDir = path.resolve(process.cwd(), "collector-output");

fs.mkdirSync(outDir, { recursive: true });

const blockedCookieProofKeys = new Set([
  "cookie_header",
  "set-cookie",
  "netscape",
  "jar",
  "value",
]);

function hasBlockedCookieProofKey(value) {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some((item) => hasBlockedCookieProofKey(item));

  for (const [key, child] of Object.entries(value)) {
    if (blockedCookieProofKeys.has(key.toLowerCase())) return true;
    if (hasBlockedCookieProofKey(child)) return true;
  }
  return false;
}

function sendJson(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(body, null, 2));
}

function readRecord(fileName) {
  const fullPath = path.join(outDir, fileName);
  const record = JSON.parse(fs.readFileSync(fullPath, "utf8"));
  const payload = record.payload || record;
  const cookieRows = payload.cookie_details || payload.cookies || [];
  return {
    file: fullPath,
    file_name: fileName,
    received_at: record.received_at || payload.captured_at,
    event: payload.event,
    org_url: payload.org_url,
    org_host: payload.org_host,
    user_login: payload.user_login,
    user_id: payload.user_id,
    session_probe: payload.session_probe,
    cookie_summary:
      payload.cookie_summary || {
        count: cookieRows.length,
        names: cookieRows.map((cookie) => cookie.name).filter(Boolean),
      },
    cookie_details: cookieRows,
    cookies: cookieRows,
    token_proof: payload.token_proof,
    payload,
  };
}

function listRecords(prefix) {
  return fs
    .readdirSync(outDir)
    .filter((fileName) => fileName.startsWith(prefix) && fileName.endsWith(".json"))
    .map((fileName) => {
      try {
        const fullPath = path.join(outDir, fileName);
        const stat = fs.statSync(fullPath);
        const record = readRecord(fileName);
        return {
          file_name: fileName,
          file: fullPath,
          last_write_time: stat.mtime.toISOString(),
          received_at: record.received_at,
          event: record.event,
          org_url: record.org_url,
          user_login: record.user_login,
          cookie_count: record.cookie_summary?.count,
          cookie_names: record.cookie_summary?.names,
          cookie_details: record.cookie_details,
          cookies: record.cookies,
          cookie_hashes:
            record.payload?.cookie_hashes ||
            Object.fromEntries(
              (record.cookies || [])
                .filter((cookie) => cookie.name && cookie.value_sha256)
                .map((cookie) => [cookie.name, cookie.value_sha256])
            ),
          session_probe: record.session_probe,
        };
      } catch (err) {
        return {
          file_name: fileName,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    })
    .sort((a, b) => String(b.received_at || "").localeCompare(String(a.received_at || "")));
}

function deleteRecordsExcept(prefix, keepPath) {
  const keepFullPath = path.resolve(keepPath);
  let deleted = 0;

  for (const fileName of fs.readdirSync(outDir)) {
    if (!fileName.startsWith(prefix) || !fileName.endsWith(".json")) continue;

    const fullPath = path.resolve(outDir, fileName);
    if (fullPath === keepFullPath) continue;

    fs.rmSync(fullPath, { force: true });
    deleted++;
  }

  return deleted;
}

function latestRecord(prefix) {
  const [latest] = listRecords(prefix);
  return latest ? readRecord(latest.file_name) : null;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function sendDashboard(res) {
  const cookieProofs = listRecords("cookie-proof-");
  const labEvents = listRecords("lab-event-");
  const latestCookie = cookieProofs[0];
  const latestDetails = latestRecord("cookie-proof-")?.cookies || [];
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Okta MCP Local Collector</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #172033; background: #f7f8fa; }
    main { max-width: 980px; margin: 0 auto; }
    h1 { font-size: 28px; margin: 0 0 8px; }
    h2 { font-size: 18px; margin-top: 28px; }
    .panel { background: #fff; border: 1px solid #d9dde7; border-radius: 8px; padding: 18px; margin-top: 16px; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .stat { background: #f3f5f8; border-radius: 6px; padding: 12px; }
    .label { color: #5c667a; font-size: 12px; }
    .value { font-size: 18px; font-weight: 650; margin-top: 4px; overflow-wrap: anywhere; }
    code { background: #eef1f6; padding: 2px 5px; border-radius: 4px; }
    a { color: #1f55d5; }
    table { width: 100%; border-collapse: collapse; background: #fff; }
    th, td { text-align: left; border-bottom: 1px solid #e5e8ef; padding: 10px 8px; vertical-align: top; }
    th { color: #5c667a; font-size: 12px; font-weight: 600; }
    .hash { font-family: Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }
  </style>
</head>
<body>
  <main>
    <h1>Okta MCP Local Collector</h1>
    <p>Listening on <code>http://${host}:${port}</code>. This view shows local proof records written under <code>${outDir}</code>.</p>

    <section class="panel">
      <div class="grid">
        <div class="stat"><div class="label">Cookie Proofs</div><div class="value">${cookieProofs.length}</div></div>
        <div class="stat"><div class="label">Lab Events</div><div class="value">${labEvents.length}</div></div>
        <div class="stat"><div class="label">Latest User</div><div class="value">${latestCookie?.user_login || "none"}</div></div>
        <div class="stat"><div class="label">Latest Cookies</div><div class="value">${latestCookie?.cookie_count ?? 0}</div></div>
      </div>
    </section>

    <section class="panel">
      <h2>Useful Links</h2>
      <p><a href="/v1/cookie-proofs">/v1/cookie-proofs</a> lists cookie proof records.</p>
      <p><a href="/v1/cookie-proofs/latest">/v1/cookie-proofs/latest</a> shows the latest cookie proof record.</p>
      <p><a href="/v1/lab-events">/v1/lab-events</a> lists token/auth lab events.</p>
      <p><a href="/health">/health</a> shows collector health.</p>
    </section>

    <section class="panel">
      <h2>Latest Cookie Rows</h2>
      <table>
        <thead><tr><th>Name</th><th>Domain</th><th>Expires</th><th>Flags</th><th>Size</th><th>Priority</th><th>Source</th><th>Display Value</th><th>Length</th><th>Value SHA-256</th></tr></thead>
        <tbody>
          ${latestDetails
            .map(
              (cookie) =>
                `<tr><td>${escapeHtml(cookie.name)}</td><td>${escapeHtml(cookie.domain)}${cookie.path ? `<br><code>${escapeHtml(cookie.path)}</code>` : ""}</td><td>${cookie.expires ?? ""}${cookie.session ? "<br>session" : ""}</td><td>${cookie.httpOnly ? "HttpOnly " : ""}${cookie.secure ? "Secure " : ""}${escapeHtml(cookie.sameSite)}</td><td>${cookie.size ?? ""}</td><td>${escapeHtml(cookie.priority)}</td><td>${escapeHtml(cookie.sourceScheme)}${cookie.sourcePort ? `<br>${cookie.sourcePort}` : ""}</td><td class="hash">${escapeHtml(cookie.display_value)}</td><td>${cookie.value_length ?? ""}</td><td class="hash">${escapeHtml(cookie.value_sha256)}</td></tr>`
            )
            .join("")}
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Recent Cookie Proofs</h2>
      <table>
        <thead><tr><th>Received</th><th>User</th><th>Cookies</th><th>Probe</th><th>File</th></tr></thead>
        <tbody>
          ${cookieProofs
            .slice(0, 10)
            .map(
              (record) =>
                `<tr><td>${record.received_at || ""}</td><td>${record.user_login || ""}</td><td>${record.cookie_count ?? ""}</td><td>${record.session_probe?.status ?? ""}</td><td>${record.file_name}</td></tr>`
            )
            .join("")}
        </tbody>
      </table>
    </section>
  </main>
</body>
</html>`;
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(html);
}

const server = http.createServer((req, res) => {
  const requestUrl = new URL(req.url || "/", `http://${host}:${port}`);
  const pathname = requestUrl.pathname;

  if (req.method === "GET") {
    if (pathname === "/") {
      sendDashboard(res);
      return;
    }
    if (pathname === "/health") {
      sendJson(res, 200, {
        ok: true,
        service: "okta-mcp-local-collector",
        out_dir: outDir,
        cookie_proofs: listRecords("cookie-proof-").length,
        lab_events: listRecords("lab-event-").length,
      });
      return;
    }
    if (pathname === "/v1/cookie-proofs") {
      const record = latestRecord("cookie-proof-");
      sendJson(res, record ? 200 : 404, record?.payload || { error: "not_found" });
      return;
    }
    if (pathname === "/v1/cookie-proofs/latest") {
      const record = latestRecord("cookie-proof-");
      sendJson(res, record ? 200 : 404, record?.payload || { error: "not_found" });
      return;
    }
    if (pathname === "/v1/lab-events") {
      const records = listRecords("lab-event-");
      sendJson(res, 200, { ok: true, count: records.length, records });
      return;
    }
    if (pathname === "/v1/lab-events/latest") {
      const record = latestRecord("lab-event-");
      sendJson(res, record ? 200 : 404, record || { error: "not_found" });
      return;
    }
  }

  const routeNames = {
    "/v1/lab-events": "lab-event",
    "/v1/telemetry": "lab-event",
    "/v1/cookie-proofs": "cookie-proof",
  };
  const routeName = routeNames[pathname];
  const allowedPath = Boolean(routeName);
  if (req.method !== "POST" || !allowedPath) {
    sendJson(res, 404, { error: "not_found" });
    return;
  }

  let body = "";
  req.setEncoding("utf8");
  req.on("data", (chunk) => {
    body += chunk;
    if (body.length > 1_000_000) req.destroy();
  });

  req.on("end", () => {
    const receivedAt = new Date().toISOString();
    let raw;
    try {
      raw = JSON.parse(body || "{}");
    } catch {
      sendJson(res, 400, { error: "invalid_json" });
      return;
    }

    if (routeName === "cookie-proof" && hasBlockedCookieProofKey(raw)) {
      sendJson(res, 400, { error: "raw_cookie_fields_are_not_allowed" });
      return;
    }

    const record =
      routeName === "cookie-proof"
        ? raw
        : {
            received_at: receivedAt,
            remote: req.socket.remoteAddress,
            payload: raw,
          };

    const file = path.join(
      outDir,
      `${routeName}-${receivedAt.replace(/[:.]/g, "-")}.json`
    );
    fs.writeFileSync(file, JSON.stringify(record, null, 2));
    const deletedOldCount =
      routeName === "cookie-proof" ? deleteRecordsExcept("cookie-proof-", file) : 0;

    console.log(`[collector] saved ${file}`);
    if (deletedOldCount) {
      console.log(`[collector] deleted ${deletedOldCount} old cookie proof file(s)`);
    }
    sendJson(res, 200, { ok: true, file, deleted_old_count: deletedOldCount });
  });
});

server.listen(port, host, () => {
  console.log(`[collector] listening on http://${host}:${port}/v1/lab-events`);
  console.log(`[collector] listening on http://${host}:${port}/v1/cookie-proofs`);
  console.log(`[collector] writing payloads to ${outDir}`);
});
