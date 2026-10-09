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
  process.env.RESEND_FROM_EMAIL ||
  "TradeZora <onboarding@resend.dev>";

/*
=========================================================
OWNER ADMIN
=========================================================
*/

const ADMIN_EMAIL = "davieswaweru123@gmail.com";

/*
=========================================================
DATABASE
=========================================================
*/

if (!DATABASE_URL) {
  console.error("DATABASE_URL is not configured.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

/*
=========================================================
HELPERS
=========================================================
*/

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

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];

  if (typeof forwarded === "string" && forwarded.length > 0) {
    return forwarded.split(",")[0].trim();
  }

  return req.socket?.remoteAddress || null;
}

function getUserAgent(req) {
  return String(req.get("user-agent") || "").slice(0, 1000);
}

/*
=========================================================
CORS
=========================================================
*/

function addCors(res) {
  res.setHeader(
    "Access-Control-Allow-Origin",
    FRONTEND_ORIGIN
  );

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PATCH, OPTIONS"
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

app.use(
  express.json({
    limit: "1mb"
  })
);

/*
=========================================================
DATABASE INITIALIZATION
=========================================================
*/

async function initializeDatabase() {
  if (!DATABASE_URL) {
    throw new Error("DATABASE_URL is missing.");
  }

  /*
  -------------------------------------------------------
  USERS
  -------------------------------------------------------
  */

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

  /*
  -------------------------------------------------------
  USER ROLE
  -------------------------------------------------------
  */

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user';
  `);

  /*
  -------------------------------------------------------
  ACCOUNT STATUS
  -------------------------------------------------------
  */

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active';
  `);

  /*
  -------------------------------------------------------
  KYC STATUS
  -------------------------------------------------------
  */

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS kyc_status VARCHAR(20) NOT NULL DEFAULT 'not_submitted';
  `);

  /*
  -------------------------------------------------------
  LAST LOGIN
  -------------------------------------------------------
  */

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
  `);

  /*
  -------------------------------------------------------
  ONLY THE OWNER EMAIL CAN BE ADMIN
  -------------------------------------------------------
  */

  await pool.query(
    `
      UPDATE users
      SET role = 'user'
      WHERE LOWER(email) <> $1
        AND role = 'admin'
    `,
    [ADMIN_EMAIL]
  );

  await pool.query(
    `
      UPDATE users
      SET role = 'admin'
      WHERE LOWER(email) = $1
    `,
    [ADMIN_EMAIL]
  );

  /*
  -------------------------------------------------------
  SESSIONS
  -------------------------------------------------------
  */

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

  /*
  -------------------------------------------------------
  PASSWORD RESET TOKENS
  -------------------------------------------------------
  */

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

  /*
  -------------------------------------------------------
  KYC RECORDS
  -------------------------------------------------------
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS kyc_records (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      legal_name VARCHAR(200),
      date_of_birth DATE,
      country VARCHAR(100),
      document_type VARCHAR(50),
      document_reference TEXT,
      notes TEXT,
      rejection_reason TEXT,
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL
    );
  `);

  // Safe additive migrations for existing KYC tables.
  await pool.query(`ALTER TABLE kyc_records ADD COLUMN IF NOT EXISTS legal_name VARCHAR(200);`);
  await pool.query(`ALTER TABLE kyc_records ADD COLUMN IF NOT EXISTS date_of_birth DATE;`);
  await pool.query(`ALTER TABLE kyc_records ADD COLUMN IF NOT EXISTS country VARCHAR(100);`);
  await pool.query(`ALTER TABLE kyc_records ADD COLUMN IF NOT EXISTS rejection_reason TEXT;`);

  /*
  -------------------------------------------------------
  DEPOSITS
  -------------------------------------------------------
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS deposits (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(18, 2) NOT NULL,
      currency VARCHAR(10) NOT NULL DEFAULT 'USD',
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      provider VARCHAR(50),
      provider_reference VARCHAR(255),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  /*
  -------------------------------------------------------
  WITHDRAWALS
  -------------------------------------------------------
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS withdrawals (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(18, 2) NOT NULL,
      currency VARCHAR(10) NOT NULL DEFAULT 'USD',
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      destination_type VARCHAR(50),
      destination_reference TEXT,
      provider_reference VARCHAR(255),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  /*
  -------------------------------------------------------
  TRADES
  -------------------------------------------------------
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS trades (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      market VARCHAR(100),
      contract_type VARCHAR(100),
      direction VARCHAR(20),
      stake NUMERIC(18, 2) NOT NULL DEFAULT 0,
      entry_price NUMERIC(30, 10),
      exit_price NUMERIC(30, 10),
      profit_loss NUMERIC(18, 2) NOT NULL DEFAULT 0,
      status VARCHAR(20) NOT NULL DEFAULT 'open',
      opened_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      closed_at TIMESTAMPTZ
    );
  `);

  /*
  -------------------------------------------------------
  LEDGER
  -------------------------------------------------------
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ledger (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type VARCHAR(50) NOT NULL,
      amount NUMERIC(18, 2) NOT NULL,
      balance_before NUMERIC(18, 2),
      balance_after NUMERIC(18, 2),
      reference_type VARCHAR(50),
      reference_id BIGINT,
      description TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  /*
  -------------------------------------------------------
  ADMIN AUDIT LOG
  -------------------------------------------------------
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_audit_logs (
      id BIGSERIAL PRIMARY KEY,
      admin_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      action VARCHAR(100) NOT NULL,
      target_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      details JSONB,
      ip_address VARCHAR(100),
      user_agent TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS admin_audit_logs_created_at_idx
    ON admin_audit_logs(created_at DESC);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS admin_audit_logs_target_user_idx
    ON admin_audit_logs(target_user_id);
  `);

  console.log("TradeZora database initialized.");
}

/*
=========================================================
ADMIN AUDIT
=========================================================
*/

async function writeAdminAudit({
  adminUserId,
  action,
  targetUserId = null,
  details = {},
  req
}) {
  try {
    await pool.query(
      `
        INSERT INTO admin_audit_logs
        (
          admin_user_id,
          action,
          target_user_id,
          details,
          ip_address,
          user_agent
        )
        VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6
        )
      `,
      [
        adminUserId,
        action,
        targetUserId,
        JSON.stringify(details),
        getClientIp(req),
        getUserAgent(req)
      ]
    );
  } catch (error) {
    console.error(
      "Admin audit log error:",
      error
    );
  }
}

/*
=========================================================
AUTHENTICATION
=========================================================
*/

async function getSessionFromRequest(req) {
  let token =
    req.get("X-TradeZora-Session") || "";

  if (!token) {
    const authorization =
      req.get("Authorization") || "";

    if (authorization.startsWith("Bearer ")) {
      token = authorization
        .slice(7)
        .trim();
    }
  }

  if (!token) {
    return null;
  }

  const tokenHash =
    hashSessionToken(token);

  const result = await pool.query(
    `
      SELECT
        s.id AS session_id,
        s.expires_at,
        u.id,
        u.name,
        u.email,
        u.balance,
        u.created_at,
        u.updated_at,
        u.role,
        u.status,
        u.kyc_status,
        u.last_login_at
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
    const auth =
      await getSessionFromRequest(req);

    if (!auth) {
      res.status(401).json({
        success: false,
        error: "You are not logged in."
      });

      return null;
    }

    if (auth.session.status !== "active") {
      res.status(403).json({
        success: false,
        error: "This account is not active."
      });

      return null;
    }

    return auth;
  } catch (error) {
    console.error(
      "Authentication error:",
      error
    );

    res.status(500).json({
      success: false,
      error: "Authentication service error."
    });

    return null;
  }
}

/*
=========================================================
ADMIN AUTHENTICATION
=========================================================
*/

async function requireAdmin(req, res) {
  const auth =
    await requireAuth(req, res);

  if (!auth) {
    return null;
  }

  if (
    auth.session.role !== "admin" ||
    normalizeEmail(auth.session.email) !== ADMIN_EMAIL
  ) {
    res.status(403).json({
      success: false,
      error: "Admin access required."
    });

    return null;
  }

  return auth;
}

/*
=========================================================
PASSWORD RESET EMAIL
=========================================================
*/

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
        Authorization:
          `Bearer ${RESEND_API_KEY}`,
        "Content-Type":
          "application/json"
      },

      body: JSON.stringify({
        from: RESEND_FROM_EMAIL,
        to: [to],
        subject:
          "Reset your TradeZora password",

        html: `
          <div style="font-family:Arial,sans-serif;background:#050807;color:#eaf5ef;padding:32px">
            <div style="max-width:560px;margin:auto;background:#0c1210;border:1px solid #1c2923;border-radius:16px;padding:28px">

              <h2 style="margin-top:0;color:#16e58a">
                TradeZora
              </h2>

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
    const errorText =
      await response.text();

    throw new Error(
      `Resend email failed (${response.status}): ${errorText}`
    );
  }

  return response.json();
}

/*
=========================================================
HOME
=========================================================
*/

app.get("/", (req, res) => {
  res.json({
    name: "TradeZora Backend",
    status: "online",
    version: "3.0.0",
    mode: "standalone-demo",
    deriv_connected: false
  });
});

/*
=========================================================
HEALTH
=========================================================
*/

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
    console.error(
      "Health check error:",
      error
    );

    res.status(503).json({
      status: "error",
      database: "disconnected"
    });
  }
});

/*
=========================================================
REGISTER
=========================================================
*/

app.post(
  "/api/auth/register",
  async (req, res) => {
    try {
      const name =
        String(
          req.body?.name || ""
        ).trim();

      const email =
        normalizeEmail(
          req.body?.email
        );

      const password =
        String(
          req.body?.password || ""
        );

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

      const existing =
        await pool.query(
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
        await bcrypt.hash(
          password,
          12
        );

      const role =
        email === ADMIN_EMAIL
          ? "admin"
          : "user";

      const userResult =
        await pool.query(
          `
            INSERT INTO users
            (
              name,
              email,
              password_hash,
              balance,
              role,
              status,
              kyc_status
            )
            VALUES
            (
              $1,
              $2,
              $3,
              10000.00,
              $4,
              'active',
              'not_submitted'
            )
            RETURNING
              id,
              name,
              email,
              balance,
              role,
              status,
              kyc_status,
              created_at
          `,
          [
            name,
            email,
            passwordHash,
            role
          ]
        );

      const user =
        userResult.rows[0];

      const token =
        createSessionToken();

      const tokenHash =
        hashSessionToken(token);

      await pool.query(
        `
          INSERT INTO sessions
          (
            user_id,
            token_hash,
            expires_at
          )
          VALUES
          (
            $1,
            $2,
            NOW() + INTERVAL '30 days'
          )
        `,
        [
          user.id,
          tokenHash
        ]
      );

      console.log(
        `New TradeZora account created: ${user.email} (${user.role})`
      );

      res.status(201).json({
        success: true,

        message:
          "Account created successfully.",

        session_token:
          token,

        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          balance:
            Number(user.balance),
          role: user.role,
          status: user.status,
          kyc_status: user.kyc_status,
          created_at:
            user.created_at
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
  }
);

/*
=========================================================
LOGIN
=========================================================
*/

app.post(
  "/api/auth/login",
  async (req, res) => {
    try {
      const email =
        normalizeEmail(
          req.body?.email
        );

      const password =
        String(
          req.body?.password || ""
        );

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

      const result =
        await pool.query(
          `
            SELECT
              id,
              name,
              email,
              password_hash,
              balance,
              role,
              status,
              kyc_status,
              created_at,
              last_login_at
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

      /*
      -----------------------------------------------------
      KEEP OWNER EMAIL AS THE ONLY ADMIN
      -----------------------------------------------------
      */

      if (
        normalizeEmail(user.email) ===
        ADMIN_EMAIL
      ) {
        if (user.role !== "admin") {
          await pool.query(
            `
              UPDATE users
              SET role = 'admin'
              WHERE id = $1
            `,
            [user.id]
          );

          user.role = "admin";
        }
      } else if (
        user.role === "admin"
      ) {
        await pool.query(
          `
            UPDATE users
            SET role = 'user'
            WHERE id = $1
          `,
          [user.id]
        );

        user.role = "user";
      }

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

      if (user.status !== "active") {
        return res.status(403).json({
          success: false,
          error:
            "This account is not active."
        });
      }

      const token =
        createSessionToken();

      const tokenHash =
        hashSessionToken(token);

      await pool.query(
        `
          INSERT INTO sessions
          (
            user_id,
            token_hash,
            expires_at
          )
          VALUES
          (
            $1,
            $2,
            NOW() + INTERVAL '30 days'
          )
        `,
        [
          user.id,
          tokenHash
        ]
      );

      await pool.query(
        `
          UPDATE users
          SET
            last_login_at = NOW(),
            updated_at = NOW()
          WHERE id = $1
        `,
        [user.id]
      );

      console.log(
        `TradeZora login successful: ${user.email} (${user.role})`
      );

      res.json({
        success: true,

        message:
          "Login successful.",

        session_token:
          token,

        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          balance:
            Number(user.balance),
          role: user.role,
          status: user.status,
          kyc_status: user.kyc_status,
          created_at:
            user.created_at
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
  }
);

/*
=========================================================
FORGOT PASSWORD
=========================================================
*/

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
        normalizeEmail(
          req.body?.email
        );

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
          (
            user_id,
            token_hash,
            expires_at
          )
          VALUES
          (
            $1,
            $2,
            NOW() + INTERVAL '30 minutes'
          )
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

/*
=========================================================
RESET PASSWORD
=========================================================
*/

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

/*
=========================================================
CURRENT USER
=========================================================
*/

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
        balance:
          Number(user.balance),
        role: user.role,
        status: user.status,
        kyc_status: user.kyc_status,
        created_at:
          user.created_at,
        last_login_at:
          user.last_login_at
      },

      session_expires_at:
        user.expires_at
    });
  }
);

/*
=========================================================
ACCOUNT
=========================================================
*/

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
        balance:
          Number(user.balance),
        currency: "USD",
        account_type: "demo",
        role: user.role,
        status: user.status,
        kyc_status: user.kyc_status,
        created_at:
          user.created_at,
        last_login_at:
          user.last_login_at
      }
    });
  }
);

/*
=========================================================
CHANGE PASSWORD
=========================================================
*/

app.patch(
  "/api/account/password",
  async (req, res) => {
    const auth =
      await requireAuth(
        req,
        res
      );

    if (!auth) {
      return;
    }

    try {
      const currentPassword =
        String(
          req.body?.current_password || ""
        );

      const newPassword =
        String(
          req.body?.new_password || ""
        );

      const confirmPassword =
        String(
          req.body?.confirm_password || ""
        );

      if (!currentPassword) {
        return res.status(400).json({
          success: false,
          error:
            "Current password is required."
        });
      }

      if (newPassword.length < 8) {
        return res.status(400).json({
          success: false,
          error:
            "New password must be at least 8 characters."
        });
      }

      if (
        newPassword !==
        confirmPassword
      ) {
        return res.status(400).json({
          success: false,
          error:
            "New passwords do not match."
        });
      }

      if (
        currentPassword ===
        newPassword
      ) {
        return res.status(400).json({
          success: false,
          error:
            "New password must be different from your current password."
        });
      }

      const result =
        await pool.query(
          `
            SELECT
              id,
              password_hash
            FROM users
            WHERE id = $1
            LIMIT 1
          `,
          [auth.session.id]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Account not found."
        });
      }

      const user =
        result.rows[0];

      const passwordMatches =
        await bcrypt.compare(
          currentPassword,
          user.password_hash
        );

      if (!passwordMatches) {
        return res.status(401).json({
          success: false,
          error:
            "Current password is incorrect."
        });
      }

      const newPasswordHash =
        await bcrypt.hash(
          newPassword,
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
            newPasswordHash,
            auth.session.id
          ]
        );

        const currentTokenHash =
          hashSessionToken(
            auth.token
          );

        await client.query(
          `
            DELETE FROM sessions
            WHERE user_id = $1
              AND token_hash <> $2
          `,
          [
            auth.session.id,
            currentTokenHash
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
        `TradeZora password changed for user ${auth.session.id}`
      );

      return res.json({
        success: true,
        message:
          "Password changed successfully."
      });
    } catch (error) {
      console.error(
        "Change password error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Could not change your password."
      });
    }
  }
);

/*
=========================================================
CHANGE ACCOUNT NAME
=========================================================
*/

app.patch(
  "/api/account/name",
  async (req, res) => {
    const auth =
      await requireAuth(
        req,
        res
      );

    if (!auth) {
      return;
    }

    try {
      const name =
        String(
          req.body?.name || ""
        ).trim();

      if (!isValidName(name)) {
        return res.status(400).json({
          success: false,
          error:
            "Name must be between 2 and 80 characters."
        });
      }

      const result =
        await pool.query(
          `
            UPDATE users
            SET
              name = $1,
              updated_at = NOW()
            WHERE id = $2
            RETURNING
              id,
              name,
              email,
              balance,
              role,
              status,
              kyc_status,
              created_at
          `,
          [
            name,
            auth.session.id
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Account not found."
        });
      }

      const user =
        result.rows[0];

      console.log(
        `TradeZora account name updated: user ${user.id}`
      );

      return res.json({
        success: true,

        message:
          "Name updated successfully.",

        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          balance:
            Number(user.balance),
          role: user.role,
          status: user.status,
          kyc_status: user.kyc_status,
          created_at:
            user.created_at
        }
      });
    } catch (error) {
      console.error(
        "Change name error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Could not update your name."
      });
    }
  }
);

/*
=========================================================
ADMIN CHECK
=========================================================
*/

app.get(
  "/api/admin/me",
  async (req, res) => {
    try {
      const auth =
        await requireAdmin(
          req,
          res
        );

      if (!auth) {
        return;
      }

      res.json({
        success: true,

        admin: {
          id:
            auth.session.id,

          name:
            auth.session.name,

          email:
            auth.session.email,

          role:
            auth.session.role
        }
      });
    } catch (error) {
      console.error(
        "Admin check error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          "Failed to verify admin access."
      });
    }
  }
);

/*
=========================================================
ADMIN DASHBOARD STATISTICS
=========================================================
*/

app.get(
  "/api/admin/stats",
  async (req, res) => {
    try {
      const auth =
        await requireAdmin(
          req,
          res
        );

      if (!auth) {
        return;
      }

      const result =
        await pool.query(`
          SELECT
            (
              SELECT COUNT(*)
              FROM users
            ) AS total_users,

            (
              SELECT COUNT(*)
              FROM users
              WHERE status = 'active'
            ) AS active_users,

            (
              SELECT COUNT(*)
              FROM users
              WHERE status <> 'active'
            ) AS inactive_users,

            (
              SELECT COUNT(*)
              FROM users
              WHERE kyc_status = 'pending'
            ) AS pending_kyc,

            (
              SELECT COUNT(*)
              FROM users
              WHERE kyc_status = 'approved'
            ) AS approved_kyc,

            (
              SELECT COUNT(*)
              FROM deposits
              WHERE status = 'pending'
            ) AS pending_deposits,

            (
              SELECT COALESCE(SUM(amount), 0)
              FROM deposits
              WHERE status = 'pending'
            ) AS pending_deposit_amount,

            (
              SELECT COUNT(*)
              FROM withdrawals
              WHERE status = 'pending'
            ) AS pending_withdrawals,

            (
              SELECT COALESCE(SUM(amount), 0)
              FROM withdrawals
              WHERE status = 'pending'
            ) AS pending_withdrawal_amount,

            (
              SELECT COUNT(*)
              FROM trades
              WHERE status = 'open'
            ) AS open_trades,

            (
              SELECT COUNT(*)
              FROM trades
            ) AS total_trades,

            (
              SELECT COALESCE(SUM(profit_loss), 0)
              FROM trades
            ) AS total_trade_profit_loss,

            (
              SELECT COALESCE(SUM(balance), 0)
              FROM users
            ) AS total_demo_balance
        `);

      const stats =
        result.rows[0];

      await writeAdminAudit({
        adminUserId:
          auth.session.id,
        action:
          "VIEW_ADMIN_STATS",
        req
      });

      res.json({
        success: true,

        mode: "standalone-demo",

        stats: {
          total_users:
            Number(stats.total_users),

          active_users:
            Number(stats.active_users),

          inactive_users:
            Number(stats.inactive_users),

          pending_kyc:
            Number(stats.pending_kyc),

          approved_kyc:
            Number(stats.approved_kyc),

          pending_deposits:
            Number(stats.pending_deposits),

          pending_deposit_amount:
            Number(stats.pending_deposit_amount),

          pending_withdrawals:
            Number(stats.pending_withdrawals),

          pending_withdrawal_amount:
            Number(stats.pending_withdrawal_amount),

          open_trades:
            Number(stats.open_trades),

          total_trades:
            Number(stats.total_trades),

          total_trade_profit_loss:
            Number(stats.total_trade_profit_loss),

          total_demo_balance:
            Number(stats.total_demo_balance)
        }
      });
    } catch (error) {
      console.error(
        "Admin stats error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          "Could not load admin statistics."
      });
    }
  }
);

/*
=========================================================
ADMIN USERS
=========================================================
*/

app.get(
  "/api/admin/users",
  async (req, res) => {
    try {
      const auth =
        await requireAdmin(
          req,
          res
        );

      if (!auth) {
        return;
      }

      const search =
        String(
          req.query?.search || ""
        ).trim();

      const status =
        String(
          req.query?.status || ""
        ).trim().toLowerCase();

      const limitValue =
        Number(req.query?.limit || 50);

      const offsetValue =
        Number(req.query?.offset || 0);

      const limit =
        Math.min(
          Math.max(
            Number.isFinite(limitValue)
              ? Math.floor(limitValue)
              : 50,
            1
          ),
          100
        );

      const offset =
        Math.max(
          Number.isFinite(offsetValue)
            ? Math.floor(offsetValue)
            : 0,
          0
        );

      const params = [];

      const conditions = [];

      if (search) {
        params.push(
          `%${search}%`
        );

        const searchParam =
          `$${params.length}`;

        conditions.push(`
          (
            name ILIKE ${searchParam}
            OR email ILIKE ${searchParam}
          )
        `);
      }

      if (status) {
        params.push(status);

        conditions.push(
          `status = $${params.length}`
        );
      }

      const whereClause =
        conditions.length > 0
          ? `WHERE ${conditions.join(" AND ")}`
          : "";

      const countResult =
        await pool.query(
          `
            SELECT COUNT(*) AS count
            FROM users
            ${whereClause}
          `,
          params
        );

      const dataParams = [
        ...params,
        limit,
        offset
      ];

      const usersResult =
        await pool.query(
          `
            SELECT
              id,
              name,
              email,
              balance,
              role,
              status,
              kyc_status,
              created_at,
              updated_at,
              last_login_at
            FROM users
            ${whereClause}
            ORDER BY created_at DESC
            LIMIT $${dataParams.length - 1}
            OFFSET $${dataParams.length}
          `,
          dataParams
        );

      const users =
        usersResult.rows.map(
          (user) => ({
            id: user.id,
            name: user.name,
            email: user.email,
            balance:
              Number(user.balance),
            role: user.role,
            status: user.status,
            kyc_status:
              user.kyc_status,
            created_at:
              user.created_at,
            updated_at:
              user.updated_at,
            last_login_at:
              user.last_login_at
          })
        );

      await writeAdminAudit({
        adminUserId:
          auth.session.id,
        action:
          "VIEW_USERS",
        details: {
          search,
          status,
          limit,
          offset
        },
        req
      });

      res.json({
        success: true,

        users,

        pagination: {
          total:
            Number(
              countResult.rows[0].count
            ),

          limit,

          offset,

          has_more:
            offset + users.length <
            Number(
              countResult.rows[0].count
            )
        }
      });
    } catch (error) {
      console.error(
        "Admin users error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          "Could not load users."
      });
    }
  }
);

/*
=========================================================
ADMIN USER DETAILS
=========================================================
*/

app.get(
  "/api/admin/users/:id",
  async (req, res) => {
    try {
      const auth =
        await requireAdmin(
          req,
          res
        );

      if (!auth) {
        return;
      }

      const userId =
        Number(req.params.id);

      if (
        !Number.isInteger(userId) ||
        userId <= 0
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Invalid user ID."
        });
      }

      const userResult =
        await pool.query(
          `
            SELECT
              id,
              name,
              email,
              balance,
              role,
              status,
              kyc_status,
              created_at,
              updated_at,
              last_login_at
            FROM users
            WHERE id = $1
            LIMIT 1
          `,
          [userId]
        );

      if (
        userResult.rows.length === 0
      ) {
        return res.status(404).json({
          success: false,
          error:
            "User not found."
        });
      }

      const user =
        userResult.rows[0];

      const [
        tradesResult,
        depositsResult,
        withdrawalsResult,
        ledgerResult
      ] = await Promise.all([
        pool.query(
          `
            SELECT
              id,
              market,
              contract_type,
              direction,
              stake,
              entry_price,
              exit_price,
              profit_loss,
              status,
              opened_at,
              closed_at
            FROM trades
            WHERE user_id = $1
            ORDER BY opened_at DESC
            LIMIT 20
          `,
          [userId]
        ),

        pool.query(
          `
            SELECT
              id,
              amount,
              currency,
              status,
              provider,
              provider_reference,
              created_at,
              updated_at
            FROM deposits
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 20
          `,
          [userId]
        ),

        pool.query(
          `
            SELECT
              id,
              amount,
              currency,
              status,
              destination_type,
              destination_reference,
              provider_reference,
              created_at,
              updated_at
            FROM withdrawals
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 20
          `,
          [userId]
        ),

        pool.query(
          `
            SELECT
              id,
              type,
              amount,
              balance_before,
              balance_after,
              reference_type,
              reference_id,
              description,
              created_at
            FROM ledger
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 30
          `,
          [userId]
        )
      ]);

      await writeAdminAudit({
        adminUserId:
          auth.session.id,
        action:
          "VIEW_USER",
        targetUserId:
          userId,
        req
      });

      res.json({
        success: true,

        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          balance:
            Number(user.balance),
          role: user.role,
          status: user.status,
          kyc_status:
            user.kyc_status,
          created_at:
            user.created_at,
          updated_at:
            user.updated_at,
          last_login_at:
            user.last_login_at
        },

        trades:
          tradesResult.rows.map(
            (trade) => ({
              ...trade,
              stake:
                Number(trade.stake),
              entry_price:
                trade.entry_price === null
                  ? null
                  : Number(
                      trade.entry_price
                    ),
              exit_price:
                trade.exit_price === null
                  ? null
                  : Number(
                      trade.exit_price
                    ),
              profit_loss:
                Number(
                  trade.profit_loss
                )
            })
          ),

        deposits:
          depositsResult.rows.map(
            (deposit) => ({
              ...deposit,
              amount:
                Number(
                  deposit.amount
                )
            })
          ),

        withdrawals:
          withdrawalsResult.rows.map(
            (withdrawal) => ({
              ...withdrawal,
              amount:
                Number(
                  withdrawal.amount
                )
            })
          ),

        ledger:
          ledgerResult.rows.map(
            (entry) => ({
              ...entry,
              amount:
                Number(entry.amount),
              balance_before:
                entry.balance_before === null
                  ? null
                  : Number(
                      entry.balance_before
                    ),
              balance_after:
                entry.balance_after === null
                  ? null
                  : Number(
                      entry.balance_after
                    )
            })
          )
      });
    } catch (error) {
      console.error(
        "Admin user details error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          "Could not load user details."
      });
    }
  }
);


/*
=========================================================
IDENTITY VERIFICATION (KYC)
=========================================================
*/

app.get("/api/kyc", async (req, res) => {
  const auth = await requireAuth(req, res);
  if (!auth) return;

  try {
    const result = await pool.query(
      `SELECT id, status, legal_name, date_of_birth, country,
              document_type, notes, rejection_reason, submitted_at, reviewed_at
       FROM kyc_records WHERE user_id = $1 LIMIT 1`,
      [auth.session.id]
    );
    res.json({ success: true, application: result.rows[0] || null });
  } catch (error) {
    console.error("KYC status error:", error);
    res.status(500).json({ success: false, error: "Could not load identity verification status." });
  }
});

app.post("/api/kyc", async (req, res) => {
  const auth = await requireAuth(req, res);
  if (!auth) return;

  try {
    const legalName = String(req.body?.legal_name || "").trim();
    const dateOfBirth = String(req.body?.date_of_birth || "").trim();
    const country = String(req.body?.country || "").trim();
    const documentType = String(req.body?.document_type || "").trim();
    const documentReference = String(req.body?.document_reference || "").trim();
    const notes = String(req.body?.notes || "").trim();

    if (!legalName || legalName.length > 200 || !dateOfBirth || !country || country.length > 100 || !documentType) {
      return res.status(400).json({ success: false, error: "Enter your legal name, date of birth, country, and document type." });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateOfBirth) || Number.isNaN(Date.parse(dateOfBirth)) || new Date(dateOfBirth) >= new Date()) {
      return res.status(400).json({ success: false, error: "Enter a valid date of birth in YYYY-MM-DD format." });
    }
    if (!["national_id", "passport", "driving_licence", "other"].includes(documentType)) {
      return res.status(400).json({ success: false, error: "Choose a valid identity document type." });
    }
    if (documentReference.length > 80 || notes.length > 1000) {
      return res.status(400).json({ success: false, error: "The document reference or notes are too long." });
    }

    const existing = await pool.query(
      `SELECT status FROM kyc_records WHERE user_id = $1 LIMIT 1`,
      [auth.session.id]
    );
    if (existing.rows[0]?.status === "approved" || existing.rows[0]?.status === "verified") {
      return res.status(409).json({ success: false, error: "Your identity verification is already approved." });
    }

    const result = await pool.query(
      `INSERT INTO kyc_records
         (user_id, status, legal_name, date_of_birth, country, document_type, document_reference, notes, rejection_reason, submitted_at, reviewed_at, reviewed_by)
       VALUES ($1, 'pending', $2, $3::date, $4, $5, NULLIF($6, ''), NULLIF($7, ''), NULL, NOW(), NULL, NULL)
       ON CONFLICT (user_id) DO UPDATE SET
         status = 'pending', legal_name = EXCLUDED.legal_name,
         date_of_birth = EXCLUDED.date_of_birth, country = EXCLUDED.country,
         document_type = EXCLUDED.document_type, document_reference = EXCLUDED.document_reference,
         notes = EXCLUDED.notes, rejection_reason = NULL,
         submitted_at = NOW(), reviewed_at = NULL, reviewed_by = NULL
       RETURNING id, status, legal_name, date_of_birth, country, document_type, notes, submitted_at`,
      [auth.session.id, legalName, dateOfBirth, country, documentType, documentReference, notes]
    );

    await pool.query(
      `UPDATE users SET kyc_status = 'pending' WHERE id = $1`,
      [auth.session.id]
    );

    res.status(201).json({ success: true, message: "Identity verification submitted for review.", application: result.rows[0] });
  } catch (error) {
    console.error("KYC submission error:", error);
    res.status(500).json({ success: false, error: "Could not submit identity verification." });
  }
});

/*
=========================================================
ADMIN KYC REVIEW
=========================================================
*/

app.get("/api/admin/kyc", async (req, res) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;

    const status = String(req.query?.status || "").trim().toLowerCase();
    const search = String(req.query?.search || "").trim();
    const params = [];
    const conditions = [];
    if (status && ["pending", "approved", "rejected"].includes(status)) {
      params.push(status);
      conditions.push(`k.status = $${params.length}`);
    }
    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(u.name ILIKE $${params.length} OR u.email ILIKE $${params.length} OR k.legal_name ILIKE $${params.length})`);
    }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const result = await pool.query(
      `SELECT k.id, k.user_id, u.name AS account_name, u.email,
              k.status, k.legal_name, k.date_of_birth, k.country,
              k.document_type, k.document_reference, k.notes,
              k.rejection_reason, k.submitted_at, k.reviewed_at,
              reviewer.name AS reviewed_by_name
       FROM kyc_records k
       JOIN users u ON u.id = k.user_id
       LEFT JOIN users reviewer ON reviewer.id = k.reviewed_by
       ${where}
       ORDER BY CASE WHEN k.status = 'pending' THEN 0 ELSE 1 END, k.submitted_at DESC
       LIMIT 100`,
      params
    );
    res.json({ success: true, applications: result.rows });
  } catch (error) {
    console.error("Admin KYC list error:", error);
    res.status(500).json({ success: false, error: "Could not load identity verification applications." });
  }
});

app.patch("/api/admin/kyc/:id", async (req, res) => {
  try {
    const auth = await requireAdmin(req, res);
    if (!auth) return;

    const recordId = Number(req.params.id);
    const status = String(req.body?.status || "").trim().toLowerCase();
    const rejectionReason = String(req.body?.rejection_reason || "").trim();
    if (!Number.isSafeInteger(recordId) || recordId <= 0) {
      return res.status(400).json({ success: false, error: "Invalid application ID." });
    }
    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({ success: false, error: "Status must be approved or rejected." });
    }
    if (status === "rejected" && !rejectionReason) {
      return res.status(400).json({ success: false, error: "Provide a reason when rejecting an application." });
    }
    if (rejectionReason.length > 1000) {
      return res.status(400).json({ success: false, error: "Rejection reason is too long." });
    }

    const result = await pool.query(
      `UPDATE kyc_records SET status = $1, rejection_reason = $2,
              reviewed_at = NOW(), reviewed_by = $3
       WHERE id = $4
       RETURNING id, user_id, status, rejection_reason, reviewed_at`,
      [status, status === "rejected" ? rejectionReason : null, auth.session.id, recordId]
    );
    if (!result.rows.length) {
      return res.status(404).json({ success: false, error: "KYC application not found." });
    }

    const application = result.rows[0];
    await pool.query(`UPDATE users SET kyc_status = $1 WHERE id = $2`, [status, application.user_id]);
    await writeAdminAudit({
      adminUserId: auth.session.id,
      action: status === "approved" ? "kyc_approved" : "kyc_rejected",
      targetUserId: application.user_id,
      details: { kyc_record_id: application.id, status, rejection_reason: status === "rejected" ? rejectionReason : null },
      req
    });

    res.json({ success: true, message: `Identity verification ${status}.`, application });
  } catch (error) {
    console.error("Admin KYC review error:", error);
    res.status(500).json({ success: false, error: "Could not update identity verification status." });
  }
});

/*
=========================================================
ADMIN AUDIT LOGS
=========================================================
*/

app.get(
  "/api/admin/audit-logs",
  async (req, res) => {
    try {
      const auth =
        await requireAdmin(
          req,
          res
        );

      if (!auth) {
        return;
      }

      const limitValue =
        Number(
          req.query?.limit || 50
        );

      const limit =
        Math.min(
          Math.max(
            Number.isFinite(limitValue)
              ? Math.floor(limitValue)
              : 50,
            1
          ),
          100
        );

      const result =
        await pool.query(
          `
            SELECT
              a.id,
              a.action,
              a.target_user_id,
              a.details,
              a.ip_address,
              a.created_at,
              u.name AS admin_name,
              u.email AS admin_email
            FROM admin_audit_logs a
            LEFT JOIN users u
              ON u.id = a.admin_user_id
            ORDER BY a.created_at DESC
            LIMIT $1
          `,
          [limit]
        );

      res.json({
        success: true,

        logs:
          result.rows
      });
    } catch (error) {
      console.error(
        "Admin audit logs error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          "Could not load audit logs."
      });
    }
  }
);

/*
=========================================================
LOGOUT
=========================================================
*/

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

/*
=========================================================
CLEAN EXPIRED SESSIONS
=========================================================
*/

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

/*
=========================================================
404
=========================================================
*/

app.use(
  (req, res) => {
    res.status(404).json({
      success: false,
      error:
        "Endpoint not found."
    });
  }
);

/*
=========================================================
GLOBAL ERROR HANDLER
=========================================================
*/

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "Unhandled server error:",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      success: false,
      error:
        "Internal server error."
    });
  }
);

/*
=========================================================
START SERVER
=========================================================
*/

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
          `Owner admin email: ${ADMIN_EMAIL}`
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
