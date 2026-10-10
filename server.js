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
MPESA / REAL-MONEY ACCOUNT CONFIGURATION
=========================================================
*/
const MPESA_ENV = String(process.env.MPESA_ENV || "sandbox").toLowerCase();
const MPESA_CONSUMER_KEY = process.env.MPESA_CONSUMER_KEY || "";
const MPESA_CONSUMER_SECRET = process.env.MPESA_CONSUMER_SECRET || "";
const MPESA_SHORTCODE = process.env.MPESA_SHORTCODE || (MPESA_ENV === "sandbox" ? "174379" : "");
const MPESA_PASSKEY = process.env.MPESA_PASSKEY || "";
const MPESA_CALLBACK_URL = process.env.MPESA_CALLBACK_URL || "";
const USD_TO_KES_RATE = 129.40;
const MIN_DEPOSIT_USD_CENTS = 500;
const MAX_DEPOSIT_USD_CENTS = 190000;
const MPESA_API_BASE = MPESA_ENV === "production"
  ? "https://api.safaricom.co.ke"
  : "https://sandbox.safaricom.co.ke";

function parseUsdCents(value) {
  const raw = String(value ?? "").trim();
  if (!/^(?:0|[1-9]\\d*)(?:\\.\\d{1,2})?$/.test(raw)) return null;
  const [whole, fraction = ""] = raw.split(".");
  const cents = Number(whole) * 100 + Number((fraction + "00").slice(0, 2));
  return Number.isSafeInteger(cents) ? cents : null;
}

function usdFromKesCents(kesAmount) {
  // Daraja STK Push amounts are whole KES. Credit USD based on the
  // actual confirmed KES amount, rounded to the nearest USD cent.
  return Math.round((Number(kesAmount) / USD_TO_KES_RATE) * 100);
}

function formatUsdCents(cents) {
  return (Number(cents) / 100).toFixed(2);
}

function normalizeKenyanPhone(value) {
  let digits = String(value || "").replace(/\\D/g, "");
  if (digits.startsWith("0") && digits.length === 10) digits = "254" + digits.slice(1);
  if (digits.startsWith("7") && digits.length === 9) digits = "254" + digits;
  if (digits.startsWith("1") && digits.length === 9) digits = "254" + digits;
  return /^254[17]\\d{8}$/.test(digits) ? digits : null;
}

async function getMpesaAccessToken() {
  if (!MPESA_CONSUMER_KEY || !MPESA_CONSUMER_SECRET) {
    throw new Error("M-Pesa Consumer Key/Secret are not configured.");
  }
  const credentials = Buffer.from(`${MPESA_CONSUMER_KEY}:${MPESA_CONSUMER_SECRET}`).toString("base64");
  const response = await fetch(`${MPESA_API_BASE}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${credentials}` }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) {
    throw new Error(`M-Pesa OAuth failed (${response.status}).`);
  }
  return data.access_token;
}

async function queryMpesaStkStatus(checkoutRequestId) {
  if (!MPESA_SHORTCODE || !MPESA_PASSKEY) {
    throw new Error("M-Pesa shortcode/passkey are not configured.");
  }
  const accessToken = await getMpesaAccessToken();
  const timestamp = new Date().toISOString().replace(/\\D/g, "").slice(0, 14);
  const password = Buffer.from(`${MPESA_SHORTCODE}${MPESA_PASSKEY}${timestamp}`).toString("base64");
  const response = await fetch(`${MPESA_API_BASE}/mpesa/stkpushquery/v1/query`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      BusinessShortCode: MPESA_SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      CheckoutRequestID: checkoutRequestId
    })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || String(data.ResponseCode) !== "0") {
    throw new Error(data.errorMessage || data.ResponseDescription || `M-Pesa STK query failed (${response.status}).`);
  }
  return data;
}

async function requestMpesaStkPush({ phone, kesAmount, accountReference, description }) {
  if (!MPESA_SHORTCODE || !MPESA_PASSKEY || !MPESA_CALLBACK_URL) {
    throw new Error("MPESA_SHORTCODE, MPESA_PASSKEY, and MPESA_CALLBACK_URL must be configured.");
  }
  if (!MPESA_CALLBACK_URL.toLowerCase().startsWith("https://")) {
    throw new Error("MPESA_CALLBACK_URL must be a public HTTPS URL.");
  }
  const accessToken = await getMpesaAccessToken();
  const timestamp = new Date().toISOString().replace(/\\D/g, "").slice(0, 14);
  const password = Buffer.from(`${MPESA_SHORTCODE}${MPESA_PASSKEY}${timestamp}`).toString("base64");
  const response = await fetch(`${MPESA_API_BASE}/mpesa/stkpush/v1/processrequest`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      BusinessShortCode: MPESA_SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: "CustomerPayBillOnline",
      Amount: kesAmount,
      PartyA: phone,
      PartyB: MPESA_SHORTCODE,
      PhoneNumber: phone,
      CallBackURL: MPESA_CALLBACK_URL,
      AccountReference: String(accountReference).slice(0, 12),
      TransactionDesc: String(description).slice(0, 13)
    })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || Number(data.ResponseCode) !== 0 || !data.CheckoutRequestID) {
    throw new Error(data.errorMessage || data.ResponseDescription || `M-Pesa STK Push failed (${response.status}).`);
  }
  return data;
}

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

  // Real-money funds are always stored separately from the demo balance.
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS real_balance NUMERIC(18, 2) NOT NULL DEFAULT 0.00;
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

  await pool.query(`ALTER TABLE deposits ADD COLUMN IF NOT EXISTS kes_amount BIGINT;`);
  await pool.query(`ALTER TABLE deposits ADD COLUMN IF NOT EXISTS phone_number VARCHAR(20);`);
  await pool.query(`ALTER TABLE deposits ADD COLUMN IF NOT EXISTS checkout_request_id VARCHAR(120);`);
  await pool.query(`ALTER TABLE deposits ADD COLUMN IF NOT EXISTS merchant_request_id VARCHAR(120);`);
  await pool.query(`ALTER TABLE deposits ADD COLUMN IF NOT EXISTS mpesa_receipt_number VARCHAR(80);`);
  await pool.query(`ALTER TABLE deposits ADD COLUMN IF NOT EXISTS result_code INTEGER;`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS deposits_checkout_request_unique ON deposits(checkout_request_id) WHERE checkout_request_id IS NOT NULL;`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS deposits_mpesa_receipt_unique ON deposits(mpesa_receipt_number) WHERE mpesa_receipt_number IS NOT NULL;`);

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

  await pool.query(`ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS kes_amount BIGINT;`);
  await pool.query(`ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS phone_number VARCHAR(20);`);
  await pool.query(`ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL;`);
  await pool.query(`ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS review_note TEXT;`);

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
REAL-MONEY ACCOUNT AND M-PESA ROUTES
=========================================================
*/

// Read a user's real-money balance separately from the demo balance.
app.get("/api/real-account", async (req, res) => {
  const auth = await requireAuth(req, res);
  if (!auth) return;
  try {
    const result = await pool.query(
      `SELECT real_balance FROM users WHERE id = $1 LIMIT 1`,
      [auth.session.id]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, error: "Account not found." });
    res.json({
      success: true,
      account: {
        currency: "USD",
        account_type: "real",
        balance: Number(result.rows[0].real_balance),
        exchange_rate_usd_to_kes: USD_TO_KES_RATE,
        minimum_deposit_usd: 5,
        maximum_deposit_usd: 1900
      }
    });
  } catch (error) {
    console.error("Real account error:", error);
    res.status(500).json({ success: false, error: "Could not load real-money account." });
  }
});

// Create an M-Pesa STK Push. Deposit stays pending until a successful callback.
app.post("/api/payments/mpesa/deposit", async (req, res) => {
  const auth = await requireAuth(req, res);
  if (!auth) return;

  const amountCents = parseUsdCents(req.body?.amount_usd ?? req.body?.amount);
  const phone = normalizeKenyanPhone(req.body?.phone_number ?? req.body?.phone);
  if (amountCents === null || amountCents < MIN_DEPOSIT_USD_CENTS || amountCents > MAX_DEPOSIT_USD_CENTS) {
    return res.status(400).json({ success: false, error: "Deposit must be between $5.00 and $1,900.00 USD." });
  }
  if (!phone) {
    return res.status(400).json({ success: false, error: "Enter a valid Kenyan M-Pesa phone number, e.g. 07XXXXXXXX or 2547XXXXXXXX." });
  }
  if (MPESA_ENV !== "sandbox" && MPESA_ENV !== "production") {
    return res.status(503).json({ success: false, error: "MPESA_ENV must be sandbox or production." });
  }

  // Daraja requires a whole-number KES amount. We disclose that conversion before prompting.
  const kesAmount = Math.round((amountCents / 100) * USD_TO_KES_RATE);
  if (!Number.isSafeInteger(kesAmount) || kesAmount < 1) {
    return res.status(400).json({ success: false, error: "Invalid deposit amount." });
  }

  const client = await pool.connect();
  let deposit;
  try {
    await client.query("BEGIN");
    const inserted = await client.query(
      `INSERT INTO deposits
        (user_id, amount, currency, status, provider, kes_amount, phone_number)
       VALUES ($1, $2, 'USD', 'initiating', 'mpesa', $3, $4)
       RETURNING id, amount, kes_amount, status, created_at`,
      [auth.session.id, formatUsdCents(amountCents), kesAmount, phone]
    );
    deposit = inserted.rows[0];
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Deposit creation error:", error);
    client.release();
    return res.status(500).json({ success: false, error: "Could not create deposit request." });
  }
  client.release();

  try {
    const stk = await requestMpesaStkPush({
      phone,
      kesAmount,
      accountReference: `TZ${deposit.id}`,
      description: "TradeZora deposit"
    });
    await pool.query(
      `UPDATE deposits
       SET status = 'pending', checkout_request_id = $1, merchant_request_id = $2,
           provider_reference = $1, updated_at = NOW()
       WHERE id = $3 AND user_id = $4`,
      [stk.CheckoutRequestID, stk.MerchantRequestID || null, deposit.id, auth.session.id]
    );
    return res.status(202).json({
      success: true,
      message: "M-Pesa payment prompt sent. Complete it on your phone; your real balance updates only after payment confirmation.",
      deposit: {
        id: deposit.id,
        amount_usd: Number(deposit.amount),
        amount_kes: kesAmount,
        currency: "USD",
        exchange_rate_usd_to_kes: USD_TO_KES_RATE,
        status: "pending",
        checkout_request_id: stk.CheckoutRequestID
      }
    });
  } catch (error) {
    console.error("M-Pesa STK Push error:", error.message);
    await pool.query(
      `UPDATE deposits SET status = 'failed', updated_at = NOW() WHERE id = $1 AND status = 'initiating'`,
      [deposit.id]
    ).catch((dbError) => console.error("Deposit failure update error:", dbError));
    return res.status(502).json({
      success: false,
      error: "Could not start the M-Pesa payment. Check the server's Daraja configuration and try again."
    });
  }
});

// Daraja callback. A successful callback is matched to our pending checkout and credited once.
app.post("/api/payments/mpesa/callback", async (req, res) => {
  // Acknowledge the callback promptly; unknown or duplicate callbacks do not create credits.
  try {
    const callback = req.body?.Body?.stkCallback;
    if (!callback?.CheckoutRequestID) {
      return res.json({ ResultCode: 0, ResultDesc: "Callback received." });
    }

    const checkoutId = String(callback.CheckoutRequestID);
    const resultCode = Number(callback.ResultCode);
    const metadataItems = callback.CallbackMetadata?.Item || [];
    const meta = {};
    for (const item of metadataItems) {
      if (item?.Name) meta[item.Name] = item.Value;
    }

    const receipt = meta.MpesaReceiptNumber ? String(meta.MpesaReceiptNumber) : null;
    const paidKes = Number(meta.Amount);
    const callbackPhone = meta.PhoneNumber ? String(meta.PhoneNumber) : null;

    // Callback payloads are not treated as sufficient proof by themselves.
    // Confirm the checkout with Daraja before any account credit is made.
    let providerConfirmed = false;
    let providerQueryError = null;
    if (resultCode === 0) {
      try {
        const queryResult = await queryMpesaStkStatus(checkoutId);
        providerConfirmed = String(queryResult.ResultCode) === "0";
      } catch (queryError) {
        providerQueryError = queryError;
        console.error("M-Pesa STK query could not confirm callback:", queryError.message);
      }
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        `SELECT id, user_id, amount, kes_amount, phone_number, status
         FROM deposits WHERE checkout_request_id = $1 FOR UPDATE`,
        [checkoutId]
      );
      if (!found.rows.length) {
        await client.query("COMMIT");
        return res.json({ ResultCode: 0, ResultDesc: "Callback received." });
      }

      const deposit = found.rows[0];
      if (deposit.status === "completed" || deposit.status === "failed") {
        await client.query("COMMIT");
        return res.json({ ResultCode: 0, ResultDesc: "Callback already processed." });
      }

      if (resultCode !== 0) {
        await client.query(
          `UPDATE deposits SET status = 'failed', result_code = $1, updated_at = NOW() WHERE id = $2`,
          [Number.isFinite(resultCode) ? resultCode : -1, deposit.id]
        );
        await client.query("COMMIT");
        return res.json({ ResultCode: 0, ResultDesc: "Payment failure recorded." });
      }

      if (!providerConfirmed) {
        await client.query(
          `UPDATE deposits SET status = 'review', result_code = $1, updated_at = NOW() WHERE id = $2`,
          [resultCode, deposit.id]
        );
        await client.query("COMMIT");
        console.error(`M-Pesa deposit ${deposit.id} requires manual review; provider confirmation unavailable.`);
        return res.json({ ResultCode: 0, ResultDesc: "Payment received for review." });
      }

      // Do not credit when callback amount/phone does not match the initiated payment.
      if (!Number.isFinite(paidKes) || paidKes !== Number(deposit.kes_amount) ||
          (deposit.phone_number && callbackPhone && callbackPhone !== deposit.phone_number) ||
          !receipt) {
        await client.query(
          `UPDATE deposits SET status = 'review', result_code = $1, updated_at = NOW() WHERE id = $2`,
          [resultCode, deposit.id]
        );
        await client.query("COMMIT");
        console.error(`M-Pesa callback mismatch for deposit ${deposit.id}; left for manual review.`);
        return res.json({ ResultCode: 0, ResultDesc: "Payment received for review." });
      }

      const usdCents = usdFromKesCents(paidKes);
      if (usdCents < MIN_DEPOSIT_USD_CENTS || usdCents > MAX_DEPOSIT_USD_CENTS) {
        await client.query(
          `UPDATE deposits SET status = 'review', mpesa_receipt_number = $1, result_code = $2, updated_at = NOW() WHERE id = $3`,
          [receipt, resultCode, deposit.id]
        );
        await client.query("COMMIT");
        return res.json({ ResultCode: 0, ResultDesc: "Payment received for review." });
      }

      const duplicateReceipt = await client.query(
        `SELECT id FROM deposits WHERE mpesa_receipt_number = $1 AND id <> $2 LIMIT 1`,
        [receipt, deposit.id]
      );
      if (duplicateReceipt.rows.length) {
        await client.query("ROLLBACK");
        return res.json({ ResultCode: 0, ResultDesc: "Duplicate receipt ignored." });
      }

      const balanceResult = await client.query(
        `UPDATE users SET real_balance = real_balance + $1, updated_at = NOW()
         WHERE id = $2 RETURNING real_balance`,
        [formatUsdCents(usdCents), deposit.user_id]
      );
      if (!balanceResult.rows.length) throw new Error("Deposit user no longer exists.");

      await client.query(
        `UPDATE deposits SET amount = $1, status = 'completed', mpesa_receipt_number = $2,
           result_code = $3, updated_at = NOW() WHERE id = $4`,
        [formatUsdCents(usdCents), receipt, resultCode, deposit.id]
      );
      await client.query(
        `INSERT INTO ledger
          (user_id, type, amount, balance_before, balance_after, reference_type, reference_id, description)
         VALUES ($1, 'deposit', $2, $3, $4, 'deposit', $5, $6)`,
        [
          deposit.user_id,
          formatUsdCents(usdCents),
          (Number(balanceResult.rows[0].real_balance) - usdCents / 100).toFixed(2),
          Number(balanceResult.rows[0].real_balance).toFixed(2),
          deposit.id,
          `M-Pesa deposit ${receipt}; ${paidKes} KES at rate ${USD_TO_KES_RATE}`
        ]
      );
      await client.query("COMMIT");
      console.log(`M-Pesa deposit ${deposit.id} credited once; receipt ${receipt}.`);
      return res.json({ ResultCode: 0, ResultDesc: "Payment processed." });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("M-Pesa callback processing error:", error);
      return res.json({ ResultCode: 0, ResultDesc: "Callback received for processing." });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("M-Pesa callback error:", error);
    return res.json({ ResultCode: 0, ResultDesc: "Callback received." });
  }
});

// Check the authenticated user's latest deposits.
app.get("/api/payments/deposits", async (req, res) => {
  const auth = await requireAuth(req, res);
  if (!auth) return;
  try {
    const result = await pool.query(
      `SELECT id, amount, currency, status, provider, kes_amount, phone_number,
              mpesa_receipt_number, created_at, updated_at
       FROM deposits WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [auth.session.id]
    );
    res.json({ success: true, deposits: result.rows.map((d) => ({
      ...d, amount: Number(d.amount), kes_amount: d.kes_amount === null ? null : Number(d.kes_amount)
    })) });
  } catch (error) {
    console.error("Deposit history error:", error);
    res.status(500).json({ success: false, error: "Could not load deposit history." });
  }
});

// Withdrawal requests are reserved from the real balance and require admin review/manual payout.
// No automatic M-Pesa payout is initiated by this endpoint.
app.post("/api/payments/mpesa/withdrawal", async (req, res) => {
  const auth = await requireAuth(req, res);
  if (!auth) return;
  const amountCents = parseUsdCents(req.body?.amount_usd ?? req.body?.amount);
  const phone = normalizeKenyanPhone(req.body?.phone_number ?? req.body?.phone);
  if (amountCents === null || amountCents < 1) {
    return res.status(400).json({ success: false, error: "Enter a valid withdrawal amount in USD." });
  }
  if (!phone) {
    return res.status(400).json({ success: false, error: "Enter a valid Kenyan M-Pesa phone number." });
  }

  const kesAmount = Math.round((amountCents / 100) * USD_TO_KES_RATE);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const account = await client.query(
      `SELECT real_balance FROM users WHERE id = $1 FOR UPDATE`,
      [auth.session.id]
    );
    if (!account.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, error: "Account not found." });
    }
    const balanceCents = Math.round(Number(account.rows[0].real_balance) * 100);
    if (amountCents > balanceCents) {
      await client.query("ROLLBACK");
      return res.status(400).json({ success: false, error: "Insufficient real-money balance." });
    }
    const before = (balanceCents / 100).toFixed(2);
    const afterCents = balanceCents - amountCents;
    const updated = await client.query(
      `UPDATE users SET real_balance = $1, updated_at = NOW() WHERE id = $2 RETURNING real_balance`,
      [(afterCents / 100).toFixed(2), auth.session.id]
    );
    const withdrawal = await client.query(
      `INSERT INTO withdrawals
        (user_id, amount, currency, status, destination_type, destination_reference, phone_number, kes_amount)
       VALUES ($1, $2, 'USD', 'pending', 'mpesa', $3, $3, $4)
       RETURNING id, amount, currency, status, phone_number, kes_amount, created_at`,
      [auth.session.id, formatUsdCents(amountCents), phone, kesAmount]
    );
    await client.query(
      `INSERT INTO ledger
        (user_id, type, amount, balance_before, balance_after, reference_type, reference_id, description)
       VALUES ($1, 'withdrawal_hold', $2, $3, $4, 'withdrawal', $5, $6)`,
      [auth.session.id, formatUsdCents(amountCents), before, Number(updated.rows[0].real_balance).toFixed(2),
       withdrawal.rows[0].id, `Withdrawal request reserved; payout ${kesAmount} KES at rate ${USD_TO_KES_RATE}`]
    );
    await client.query("COMMIT");
    return res.status(201).json({
      success: true,
      message: "Withdrawal request submitted for review. M-Pesa payout is not automatic and will be processed after review.",
      withdrawal: { ...withdrawal.rows[0], amount: Number(withdrawal.rows[0].amount), kes_amount: Number(withdrawal.rows[0].kes_amount) }
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Withdrawal request error:", error);
    return res.status(500).json({ success: false, error: "Could not submit withdrawal request." });
  } finally {
    client.release();
  }
});

app.get("/api/payments/withdrawals", async (req, res) => {
  const auth = await requireAuth(req, res);
  if (!auth) return;
  try {
    const result = await pool.query(
      `SELECT id, amount, currency, status, destination_type, phone_number, kes_amount,
              provider_reference, review_note, created_at, updated_at
       FROM withdrawals WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [auth.session.id]
    );
    res.json({ success: true, withdrawals: result.rows.map((w) => ({
      ...w, amount: Number(w.amount), kes_amount: w.kes_amount === null ? null : Number(w.kes_amount)
    })) });
  } catch (error) {
    console.error("Withdrawal history error:", error);
    res.status(500).json({ success: false, error: "Could not load withdrawal history." });
  }
});

// Admin can reject and refund a held withdrawal, or mark it approved after an external payout.
app.patch("/api/admin/withdrawals/:id/review", async (req, res) => {
  const auth = await requireAdmin(req, res);
  if (!auth) return;
  const withdrawalId = Number(req.params.id);
  const status = String(req.body?.status || "").toLowerCase();
  const note = String(req.body?.note || "").trim().slice(0, 1000);
  if (!Number.isSafeInteger(withdrawalId) || withdrawalId <= 0) {
    return res.status(400).json({ success: false, error: "Invalid withdrawal ID." });
  }
  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({ success: false, error: "Status must be approved or rejected." });
  }
  if (status === "approved" && !String(req.body?.payout_reference || "").trim()) {
    return res.status(400).json({ success: false, error: "Record the M-Pesa payout receipt/reference after paying the customer." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const found = await client.query(
      `SELECT id, user_id, amount, status FROM withdrawals WHERE id = $1 FOR UPDATE`,
      [withdrawalId]
    );
    if (!found.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, error: "Withdrawal not found." });
    }
    const withdrawal = found.rows[0];
    if (withdrawal.status !== "pending") {
      await client.query("ROLLBACK");
      return res.status(409).json({ success: false, error: "This withdrawal has already been reviewed." });
    }
    const payoutReference = String(req.body?.payout_reference || "").trim().slice(0, 255) || null;
    if (status === "rejected") {
      const refund = await client.query(
        `UPDATE users SET real_balance = real_balance + $1, updated_at = NOW()
         WHERE id = $2 RETURNING real_balance`,
        [withdrawal.amount, withdrawal.user_id]
      );
      await client.query(
        `INSERT INTO ledger (user_id, type, amount, balance_before, balance_after, reference_type, reference_id, description)
         VALUES ($1, 'withdrawal_refund', $2, $3, $4, 'withdrawal', $5, $6)`,
        [withdrawal.user_id, withdrawal.amount,
         (Number(refund.rows[0].real_balance) - Number(withdrawal.amount)).toFixed(2),
         Number(refund.rows[0].real_balance).toFixed(2), withdrawal.id,
         `Withdrawal rejected and funds returned. ${note}`.trim()]
      );
    }
    const updated = await client.query(
      `UPDATE withdrawals SET status = $1, provider_reference = $2, review_note = NULLIF($3, ''),
          reviewed_at = NOW(), reviewed_by = $4, updated_at = NOW()
       WHERE id = $5 RETURNING id, user_id, amount, status, provider_reference, review_note, reviewed_at`,
      [status, payoutReference, note, auth.session.id, withdrawalId]
    );
    await client.query("COMMIT");
    await writeAdminAudit({
      adminUserId: auth.session.id,
      action: status === "approved" ? "withdrawal_approved_after_manual_payout" : "withdrawal_rejected_refunded",
      targetUserId: withdrawal.user_id,
      details: { withdrawal_id: withdrawalId, status, payout_reference: payoutReference, note },
      req
    });
    return res.json({
      success: true,
      message: status === "approved" ? "Withdrawal marked approved after manual M-Pesa payout." : "Withdrawal rejected and funds refunded.",
      withdrawal: updated.rows[0]
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Withdrawal review error:", error);
    return res.status(500).json({ success: false, error: "Could not review withdrawal." });
  } finally {
    client.release();
  }
});

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
