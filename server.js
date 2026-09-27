import express from "express";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.DERIV_CLIENT_ID;
const REDIRECT_URI =
  process.env.DERIV_REDIRECT_URI ||
  "https://tradezora-backend-use-1.onrender.com/auth/callback";

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://davieswaweru123-boop.github.io/Tradezora-/";

const oauthSessions = new Map();
const userSessions = new Map();
const connectionCodes = new Map();

function base64url(buffer) {
  return buffer.toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function createCodeVerifier() {
  return base64url(crypto.randomBytes(64));
}

function createCodeChallenge(verifier) {
  return base64url(crypto.createHash("sha256").update(verifier).digest());
}

function createState() {
  return base64url(crypto.randomBytes(32));
}

function createRandomId() {
  return base64url(crypto.randomBytes(32));
}

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", FRONTEND_URL.replace(/\/$/, ""));
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

app.use((req, res, next) => {
  cors(res);
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.get("/", (req, res) => {
  res.json({
    name: "TradeZora Backend",
    status: "online",
    message: "TradeZora backend is running."
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.get("/auth/login", (req, res) => {
  if (!CLIENT_ID) {
    return res.status(500).json({
      error: "DERIV_CLIENT_ID is not configured on the server."
    });
  }

  const state = createState();
  const codeVerifier = createCodeVerifier();
  const codeChallenge = createCodeChallenge(codeVerifier);

  oauthSessions.set(state, {
    codeVerifier,
    createdAt: Date.now()
  });

  const authUrl = new URL("https://auth.deriv.com/oauth2/auth");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authUrl.searchParams.set("scope", "trade");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/auth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).json({ error, error_description });
  }

  if (!code || !state) {
    return res.status(400).json({
      error: "Missing authorization code or state."
    });
  }

  const session = oauthSessions.get(state);

  if (!session) {
    return res.status(400).json({
      error: "Invalid or expired OAuth state."
    });
  }

  oauthSessions.delete(state);

  try {
    const response = await fetch("https://auth.deriv.com/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: CLIENT_ID,
        code,
        code_verifier: session.codeVerifier,
        redirect_uri: REDIRECT_URI
      })
    });

    const data = await response.json();

    if (!response.ok || !data.access_token) {
      return res.status(response.status || 500).json({
        error: "Deriv token exchange failed",
        details: data
      });
    }

    const sessionId = createRandomId();
    userSessions.set(sessionId, {
      accessToken: data.access_token,
      expiresAt: Date.now() + ((data.expires_in || 3600) * 1000)
    });

    // One-time code: the Deriv token never goes into the browser URL.
    const connectionCode = createRandomId();
    connectionCodes.set(connectionCode, {
      sessionId,
      expiresAt: Date.now() + 2 * 60 * 1000
    });

    const redirectUrl = new URL(FRONTEND_URL);
    redirectUrl.searchParams.set("connected", "1");
    redirectUrl.searchParams.set("connection_code", connectionCode);

    return res.redirect(302, redirectUrl.toString());
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "OAuth callback failed." });
  }
});

app.post("/api/session/exchange", express.json(), (req, res) => {
  const { connection_code } = req.body || {};
  const item = connectionCodes.get(connection_code);

  if (!item || item.expiresAt < Date.now()) {
    connectionCodes.delete(connection_code);
    return res.status(401).json({ error: "Invalid or expired connection code." });
  }

  connectionCodes.delete(connection_code);

  const session = userSessions.get(item.sessionId);

  if (!session || session.expiresAt < Date.now()) {
    userSessions.delete(item.sessionId);
    return res.status(401).json({ error: "Session expired. Please reconnect Deriv." });
  }

  res.json({
    session_id: item.sessionId,
    expires_at: session.expiresAt
  });
});

app.get("/api/account", async (req, res) => {
  const sessionId = req.get("X-TradeZora-Session");
  const session = userSessions.get(sessionId);

  if (!session || session.expiresAt < Date.now()) {
    if (sessionId) userSessions.delete(sessionId);
    return res.status(401).json({
      error: "Not connected. Please connect Deriv again."
    });
  }

  try {
    const response = await fetch(
      "https://api.derivws.com/trading/v1/options/accounts",
      {
        headers: {
          "Authorization": `Bearer ${session.accessToken}`
        }
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        error: "Deriv account request failed",
        details: data
      });
    }

    // Return the Deriv response without exposing the OAuth token.
    return res.json(data);
  } catch (err) {
    console.error(err);
    return res.status(502).json({
      error: "Could not reach Deriv account service."
    });
  }
});

app.listen(PORT, () => {
  console.log(`TradeZora backend running on port ${PORT}`);
});
