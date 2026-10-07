import express from "express";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import pg from "pg";

const { Pool } = pg;

const app = express();

const PORT = process.env.PORT || 3000;

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://davieswaweru123-boop.github.io/Tradezora-/";

const FRONTEND_ORIGIN = new URL(FRONTEND_URL).origin;

const DATABASE_URL = process.env.DATABASE_URL;

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESEND_FROM_EMAIL =
  process.env.RESEND_FROM_EMAIL || "TradeZora <onboarding@resend.dev>";

if (!DATABASE_URL) {
  console.error("DATABASE_URL is not configured.");
}

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

/* =========================================================
   BASIC HELPERS
========================================================= */

function createSessionToken() {
  return crypto.randomBytes(48).toString("hex");
}

function hashSessionToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function createPasswordResetToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashPasswordResetToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidName(name) {
  const value = String(name || "").trim();

  return value.length >= 2 && value.length <= 80;
}

/* =========================================================
   CORS
========================================================= */

function addCors(res) {
  res.setHeader(
    "Access-Control-Allow-Origin",
    FRONTEND_ORIGIN
  );

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS"
  );

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, X-TradeZora-Session, Authorization"
  );

  res.setHeader(
    "Access-Control-Allow-Credentials",
    "true"
  );
}

app.use((req, res, next) => {
  addCors(res);

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json({ limit: "1mb" }));

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initializeDatabase() {
  if (!DATABASE_URL) {
    throw new Error("DATABASE_URL is missing.");
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(80) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      balance NUMERIC(18, 2) NOT NULL DEFAULT 10000.00,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash CHAR(64) NOT NULL UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS sessions_token_hash_idx
    ON sessions(token_hash);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS sessions_user_id_idx
    ON sessions(user_id);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash CHAR(64) NOT NULL UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS password_reset_tokens_user_id_idx
    ON password_reset_tokens(user_id);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS password_reset_tokens_expires_at_idx
    ON password_reset_tokens(expires_at);
  `);

  console.log("TradeZora database initialized.");
}

/* =========================================================
   AUTHENTICATION
========================================================= */

async function getSessionFromRequest(req) {
  let token =
    req.get("X-TradeZora-Session") ||
    "";

  if (!token) {
    const authorization = req.get("Authorization") || "";

    if (authorization.startsWith("Bearer ")) {
      token = authorization.slice(7).trim();
    }
  }

  if (!token) {
    return null;
  }

  const tokenHash = hashSessionToken(token);

  const result = await pool.query(
    `
      SELECT
        s.id AS session_id,
        s.expires_at,
        u.id,
        u.name,
        u.email,
        u.balance,
        u.created_at
      FROM sessions s
      INNER JOIN users u
        ON u.id = s.user_id
      WHERE s.token_hash = $1
        AND s.expires_at > NOW()
      LIMIT 1
    `,
    [tokenHash]
  );

  if (result.rows.length === 0) {
    return null;
  }

  return {
    token,
    session: result.rows[0]
  };
}

async function requireAuth(req, res) {
  try {
    const auth = await getSessionFromRequest(req);

    if (!auth) {
      res.status(401).json({
        success: false,
        error: "You are not logged in."
      });

      return null;
    }

    return auth;
  } catch (error) {
    console.error("Authentication error:", error);

    res.status(500).json({
      success: false,
      error: "Authentication service error."
    });

    return null;
  }
}

/* =========================================================
   PASSWORD RESET / EMAIL
========================================================= */

async function sendPasswordResetEmail({
  to,
  name,
  resetUrl
}) {
  if (!RESEND_API_KEY) {
    throw new Error(
      "RESEND_API_KEY is not configured."
    );
  }

  const safeName = String(
    name || "Trader"
  ).replace(/[&<>"']/g, "");

  const response = await fetch(
    "https://api.resend.com/emails",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: RESEND_FROM_EMAIL,
        to: [to],
        subject: "Reset your TradeZora password",
        html: `
          <div style="font-family:Arial,sans-serif;background:#050807;color:#eaf5ef;padding:32px">
            <div style="max-width:560px;margin:auto;background:#0c1210;border:1px solid #1c2923;border-radius:16px;padding:28px">
              <h2 style="margin-top:0;color:#16e58a">TradeZora</h2>

              <p>Hello ${safeName},</p>

              <p>
                We received a request to reset your TradeZora password.
              </p>

              <p>
                <a
                  href="${resetUrl}"
                  style="display:inline-block;background:#16e58a;color:#031009;text-decoration:none;font-weight:800;padding:13px 20px;border-radius:9px"
                >
                  Reset Password
                </a>
              </p>

              <p style="color:#9aa7a1;font-size:13px">
                This link expires in 30 minutes and can only be used once.
              </p>

              <p style="color:#9aa7a1;font-size:13px">
                If you did not request this, you can safely ignore this email.
              </p>
            </div>
          </div>
        `
      })
    }
  );

  if (!response.ok) {
    const errorText = await response.text();

    throw new Error(
      `Resend email failed (${response.status}): ${errorText}`
    );
  }

  return response.json();
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/", (req, res) => {
  res.json({
    name: "TradeZora Backend",
    status: "online",
    version: "2.0.0",
    mode: "standalone-demo",
    deriv_connected: false
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      database: "connected",
      mode: "standalone-demo",
      deriv: false
    });
  } catch (error) {
    console.error("Health check error:", error);

    res.status(503).json({
      status: "error",
      database: "disconnected"
    });
  }
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const name =
      String(req.body?.name || "").trim();

    const email =
      normalizeEmail(req.body?.email);

    const password =
      String(req.body?.password || "");

    if (!isValidName(name)) {
      return res.status(400).json({
        success: false,
        error:
          "Name must be between 2 and 80 characters."
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        error:
          "Please enter a valid email address."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        error:
          "Password must be at least 8 characters."
      });
    }

    const existing = await pool.query(
      `
        SELECT id
        FROM users
        WHERE email = $1
        LIMIT 1
      `,
      [email]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error:
          "An account with this email already exists."
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 12);

    const userResult = await pool.query(
      `
        INSERT INTO users
          (name, email, password_hash, balance)
        VALUES
          ($1, $2, $3, 10000.00)
        RETURNING
          id,
          name,
          email,
          balance,
          created_at
      `,
      [
        name,
        email,
        passwordHash
      ]
    );

    const user = userResult.rows[0];

    const token =
      createSessionToken();

    const tokenHash =
      hashSessionToken(token);

    await pool.query(
      `
        INSERT INTO sessions
          (user_id, token_hash, expires_at)
        VALUES
          ($1, $2, NOW() + INTERVAL '30 days')
      `,
      [
        user.id,
        tokenHash
      ]
    );

    console.log(
      `New TradeZora account created: ${user.email}`
    );

    res.status(201).json({
      success: true,
      message:
        "Account created successfully.",
      session_token: token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        balance: Number(user.balance),
        created_at: user.created_at
      }
    });
  } catch (error) {
    console.error(
      "Registration error:",
      error
    );

    res.status(500).json({
      success: false,
      error:
        "Could not create the account."
    });
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const email =
      normalizeEmail(req.body?.email);

    const password =
      String(req.body?.password || "");

    if (
      !isValidEmail(email) ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        error:
          "Email and password are required."
      });
    }

    const result = await pool.query(
      `
        SELECT
          id,
          name,
          email,
          password_hash,
          balance,
          created_at
        FROM users
        WHERE email = $1
        LIMIT 1
      `,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error:
          "Invalid email or password."
      });
    }

    const user =
      result.rows[0];

    const passwordMatches =
      await bcrypt.compare(
        password,
        user.password_hash
      );

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        error:
          "Invalid email or password."
      });
    }

    const token =
      createSessionToken();

    const tokenHash =
      hashSessionToken(token);

    await pool.query(
      `
        INSERT INTO sessions
          (user_id, token_hash, expires_at)
        VALUES
          ($1, $2, NOW() + INTERVAL '30 days')
      `,
      [
        user.id,
        tokenHash
      ]
    );

    console.log(
      `TradeZora login successful: ${user.email}`
    );

    res.json({
      success: true,
      message:
        "Login successful.",
      session_token: token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        balance: Number(user.balance),
        created_at: user.created_at
      }
    });
  } catch (error) {
    console.error(
      "Login error:",
      error
    );

    res.status(500).json({
      success: false,
      error:
        "Could not log in."
    });
  }
});

/* =========================================================
   FORGOT PASSWORD
========================================================= */

app.post(
  "/api/auth/forgot-password",
  async (req, res) => {
    const genericResponse = {
      success: true,
      message:
        "If an account exists for that email, a password reset link has been sent."
    };

    try {
      const email =
        normalizeEmail(req.body?.email);

      if (!isValidEmail(email)) {
        return res.json(
          genericResponse
        );
      }

      const result =
        await pool.query(
          `
            SELECT
              id,
              name,
              email
            FROM users
            WHERE email = $1
            LIMIT 1
          `,
          [email]
        );

      if (result.rows.length === 0) {
        return res.json(
          genericResponse
        );
      }

      const user =
        result.rows[0];

      await pool.query(
        `
          DELETE FROM password_reset_tokens
          WHERE user_id = $1
            AND used_at IS NULL
        `,
        [user.id]
      );

      const rawToken =
        createPasswordResetToken();

      const tokenHash =
        hashPasswordResetToken(
          rawToken
        );

      await pool.query(
        `
          INSERT INTO password_reset_tokens
            (user_id, token_hash, expires_at)
          VALUES
            ($1, $2, NOW() + INTERVAL '30 minutes')
        `,
        [
          user.id,
          tokenHash
        ]
      );

      const resetUrl =
        `${FRONTEND_URL.replace(
          /\/$/,
          ""
        )}/reset-password.html?token=${encodeURIComponent(
          rawToken
        )}`;

      try {
        await sendPasswordResetEmail({
          to: user.email,
          name: user.name,
          resetUrl
        });
      } catch (emailError) {
        console.error(
          "Password reset email error:",
          emailError
        );

        await pool.query(
          `
            DELETE FROM password_reset_tokens
            WHERE token_hash = $1
          `,
          [tokenHash]
        );

        return res.status(500).json({
          success: false,
          error:
            "We could not send the password reset email. Please try again later."
        });
      }

      console.log(
        `Password reset email sent: ${user.email}`
      );

      return res.json(
        genericResponse
      );
    } catch (error) {
      console.error(
        "Forgot password error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Could not process the password reset request."
      });
    }
  }
);

/* =========================================================
   RESET PASSWORD
========================================================= */

app.post(
  "/api/auth/reset-password",
  async (req, res) => {
    try {
      const token =
        String(
          req.body?.token || ""
        ).trim();

      const password =
        String(
          req.body?.password || ""
        );

      if (!token) {
        return res.status(400).json({
          success: false,
          error:
            "Password reset token is required."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          success: false,
          error:
            "Password must be at least 8 characters."
        });
      }

      const tokenHash =
        hashPasswordResetToken(
          token
        );

      const tokenResult =
        await pool.query(
          `
            SELECT
              id,
              user_id
            FROM password_reset_tokens
            WHERE token_hash = $1
              AND used_at IS NULL
              AND expires_at > NOW()
            LIMIT 1
          `,
          [tokenHash]
        );

      if (
        tokenResult.rows.length === 0
      ) {
        return res.status(400).json({
          success: false,
          error:
            "This password reset link is invalid or has expired."
        });
      }

      const resetToken =
        tokenResult.rows[0];

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const client =
        await pool.connect();

      try {
        await client.query(
          "BEGIN"
        );

        await client.query(
          `
            UPDATE users
            SET
              password_hash = $1,
              updated_at = NOW()
            WHERE id = $2
          `,
          [
            passwordHash,
            resetToken.user_id
          ]
        );

        await client.query(
          `
            DELETE FROM sessions
            WHERE user_id = $1
          `,
          [resetToken.user_id]
        );

        await client.query(
          `
            UPDATE password_reset_tokens
            SET used_at = NOW()
            WHERE id = $1
          `,
          [resetToken.id]
        );

        await client.query(
          `
            UPDATE password_reset_tokens
            SET used_at = NOW()
            WHERE user_id = $1
              AND used_at IS NULL
              AND id <> $2
          `,
          [
            resetToken.user_id,
            resetToken.id
          ]
        );

        await client.query(
          "COMMIT"
        );
      } catch (error) {
        await client.query(
          "ROLLBACK"
        );

        throw error;
      } finally {
        client.release();
      }

      console.log(
        `TradeZora password reset completed for user ${resetToken.user_id}`
      );

      return res.json({
        success: true,
        message:
          "Password reset successfully. You can now log in with your new password."
      });
    } catch (error) {
      console.error(
        "Reset password error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Could not reset the password."
      });
    }
  }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/auth/me",
  async (req, res) => {
    const auth =
      await requireAuth(
        req,
        res
      );

    if (!auth) {
      return;
    }

    const user =
      auth.session;

    res.json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        balance: Number(
          user.balance
        ),
        created_at:
          user.created_at
      },
      session_expires_at:
        user.expires_at
    });
  }
);

/* =========================================================
   ACCOUNT
========================================================= */

app.get(
  "/api/account",
  async (req, res) => {
    const auth =
      await requireAuth(
        req,
        res
      );

    if (!auth) {
      return;
    }

    const user =
      auth.session;

    res.json({
      success: true,
      account: {
        id: user.id,
        name: user.name,
        email: user.email,
        balance: Number(
          user.balance
        ),
        currency: "USD",
        account_type: "demo",
        created_at:
          user.created_at
      }
    });
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/auth/logout",
  async (req, res) => {
    try {
      let token =
        req.get(
          "X-TradeZora-Session"
        ) || "";

      if (!token) {
        const authorization =
          req.get(
            "Authorization"
          ) || "";

        if (
          authorization.startsWith(
            "Bearer "
          )
        ) {
          token =
            authorization
              .slice(7)
              .trim();
        }
      }

      if (token) {
        const tokenHash =
          hashSessionToken(
            token
          );

        await pool.query(
          `
            DELETE FROM sessions
            WHERE token_hash = $1
          `,
          [tokenHash]
        );
      }

      res.json({
        success: true,
        message:
          "Logged out successfully."
      });
    } catch (error) {
      console.error(
        "Logout error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          "Could not log out."
      });
    }
  }
);

/* =========================================================
   CLEAN EXPIRED SESSIONS
========================================================= */

async function cleanExpiredSessions() {
  try {
    const result =
      await pool.query(
        `
          DELETE FROM sessions
          WHERE expires_at <= NOW()
        `
      );

    if (result.rowCount > 0) {
      console.log(
        `Removed ${result.rowCount} expired session(s).`
      );
    }

    const resetResult =
      await pool.query(
        `
          DELETE FROM password_reset_tokens
          WHERE expires_at <= NOW()
             OR used_at IS NOT NULL
        `
      );

    if (resetResult.rowCount > 0) {
      console.log(
        `Removed ${resetResult.rowCount} expired/used password reset token(s).`
      );
    }
  } catch (error) {
    console.error(
      "Session cleanup error:",
      error.message
    );
  }
}

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    await initializeDatabase();

    await cleanExpiredSessions();

    setInterval(
      cleanExpiredSessions,
      6 * 60 * 60 * 1000
    );

    app.listen(
      PORT,
      () => {
        console.log(
          `TradeZora backend running on port ${PORT}`
        );

        console.log(
          `CORS allowed origin: ${FRONTEND_ORIGIN}`
        );

        console.log(
          "Standalone demo account system enabled."
        );

        console.log(
          "Deriv integration is disabled."
        );

        console.log(
          `Password reset email sender: ${RESEND_FROM_EMAIL}`
        );
      }
    );
  } catch (error) {
    console.error(
      "Could not start TradeZora backend:",
      error
    );

    process.exit(1);
  }
}

startServer();
