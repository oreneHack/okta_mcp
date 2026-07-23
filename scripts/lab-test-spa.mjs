#!/usr/bin/env node

import http from "node:http";

const ORG_URL = "https://integrator-8282270.okta.com";
const CLIENT_ID = "0oa15hohdu4FsSRTe698";
const REDIRECT_URI = "http://localhost:3000/callback";
const PORT = 3000;
const SCOPES = "openid profile email offline_access";

const HTML = `<!doctype html>
<html>
<head>
  <title>Lab-SPA</title>
  <script src="https://global.oktacdn.com/okta-auth-js/7.8.1/okta-auth-js.min.js"></script>
  <style>
    body { font: 15px/1.5 system-ui; max-width: 52rem; margin: 2rem auto; padding: 0 1rem; }
    pre { background: #f4f4f4; padding: 1rem; overflow-x: auto; font-size: 13px; }
    button { font-size: 15px; padding: .4rem 1.2rem; cursor: pointer; }
    .token-value { word-break: break-all; }
    h3 { margin-top: 2rem; }
  </style>
</head>
<body>
  <h1>Lab-SPA (OIDC Test App)</h1>
  <div id="status">Initializing...</div>
  <div id="content"></div>

  <script>
    const authClient = new OktaAuth({
      issuer: "${ORG_URL}/oauth2/default",
      clientId: "${CLIENT_ID}",
      redirectUri: "${REDIRECT_URI}",
      scopes: "${SCOPES}".split(" "),
      tokenManager: { storage: "localStorage" },
      pkce: true
    });

    const statusEl = document.getElementById("status");
    const contentEl = document.getElementById("content");

    async function init() {
      if (window.location.pathname === "/callback") {
        statusEl.textContent = "Processing callback...";
        try {
          const { tokens } = await authClient.token.parseFromUrl();
          authClient.tokenManager.setTokens(tokens);
          window.history.replaceState(null, "", "/");
          showAuthenticated();
        } catch (err) {
          statusEl.textContent = "Callback error: " + err.message;
        }
        return;
      }

      const accessToken = await authClient.tokenManager.get("accessToken");
      if (accessToken) {
        showAuthenticated();
      } else {
        showLogin();
      }
    }

    function showLogin() {
      statusEl.textContent = "Not authenticated";
      contentEl.innerHTML = '<button onclick="doLogin()">Sign in with Okta</button>';
    }

    async function doLogin() {
      statusEl.textContent = "Redirecting to Okta...";
      await authClient.token.getWithRedirect();
    }

    async function showAuthenticated() {
      const raw = localStorage.getItem("okta-token-storage");
      const parsed = JSON.parse(raw || "{}");

      statusEl.textContent = "Authenticated";

      let html = "<h3>okta-token-storage contents (this is what the MCP steals):</h3>";
      html += '<pre id="raw">' + escHtml(JSON.stringify(parsed, null, 2)) + "</pre>";

      if (parsed.accessToken) {
        html += "<h3>Access Token (raw JWT)</h3>";
        html += '<pre class="token-value">' + escHtml(parsed.accessToken.accessToken || parsed.accessToken.value) + "</pre>";
        html += "<p>Expires at: " + new Date(parsed.accessToken.expiresAt * 1000).toISOString() + "</p>";
        html += "<p>Scopes: " + (parsed.accessToken.scopes || []).join(", ") + "</p>";
      }

      if (parsed.idToken?.claims) {
        html += "<h3>ID Token Claims</h3>";
        html += "<pre>" + escHtml(JSON.stringify(parsed.idToken.claims, null, 2)) + "</pre>";
      }

      if (parsed.refreshToken) {
        html += "<h3>Refresh Token</h3>";
        html += '<pre class="token-value">' + escHtml(parsed.refreshToken.refreshToken || parsed.refreshToken.value) + "</pre>";
      }

      html += "<h3>All localStorage keys on this origin</h3>";
      const keys = [];
      for (let i = 0; i < localStorage.length; i++) keys.push(localStorage.key(i));
      html += "<pre>" + escHtml(JSON.stringify(keys, null, 2)) + "</pre>";

      html += '<br><button onclick="doLogout()">Sign out</button>';
      contentEl.innerHTML = html;
    }

    async function doLogout() {
      await authClient.tokenManager.clear();
      localStorage.removeItem("okta-token-storage");
      showLogin();
    }

    function escHtml(s) {
      return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
    }

    init();
  </script>
</body>
</html>`;

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(HTML);
});

server.listen(PORT, () => {
  console.log(`Lab-SPA running at http://localhost:${PORT}`);
  console.log(`Org: ${ORG_URL}`);
  console.log(`Client ID: ${CLIENT_ID}`);
  console.log(`Redirect: ${REDIRECT_URI}`);
  console.log(`\nSign in, then check localStorage for okta-token-storage`);
});
