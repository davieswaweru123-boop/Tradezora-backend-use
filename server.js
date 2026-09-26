import express from "express";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.DERIV_CLIENT_ID;
const REDIRECT_URI =
  process.env.DERIV_REDIRECT_URI ||
  "https://tradezora-backend-use.onrender.com/auth/callback";

// Temporary storage for OAuth login attempts.
// For production, we'll move this to a persistent store.
const oauthSessions = new Map();

function base64url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function createCodeVerifier() {
  return base64url(crypto.randomBytes(64));
}

function createCodeChallenge(verifier) {
  return base64url(
    crypto.createHash("sha256").update(verifier).digest()
  );
}

function createState() {
  return base64url(crypto.randomBytes(32));
}

app.get("/", (req, res) => {
  res.json({
    name: "TradeZora Backend",
    status: "online",
    message: "TradeZora backend is running."
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok"
  });
});

// Start Deriv OAuth login
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

// Deriv OAuth callback
app.get("/auth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).json({
      error,
      error_description
    });
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
    const response = await fetch(
      "https://auth.deriv.com/oauth2/token",
      {
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
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        error: "Deriv token exchange failed",
        details: data
      });
    }

    // We will securely connect this token to the TradeZora
    // user session in the next stage.
    res.json({
      success: true,
      message: "TradeZora successfully connected to Deriv.",
      token_received: Boolean(data.access_token),
      expires_in: data.expires_in
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "OAuth callback failed."
    });
  }
});

app.listen(PORT, () => {
  console.log(`TradeZora backend running on port ${PORT}`);
});
