const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

// ===============================
// Environment
// ===============================

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

if (!JWT_SECRET) {
  console.warn("WARNING: JWT_SECRET is not configured.");
}

// ===============================
// PostgreSQL
// ===============================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

pool.on("error", (err) => {
  console.error("Unexpected PostgreSQL error:", err);
});

// ===============================
// Helpers
// ===============================

function generateReferralCode() {
  return crypto.randomBytes(5).toString("hex").toUpperCase();
}

function signUserToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      telegramId: user.telegram_id,
    },
    JWT_SECRET,
    {
      expiresIn: "30d",
    }
  );
}

// ===============================
// Telegram Mini App verification
// ===============================

function verifyTelegramInitData(initData) {
  if (!TELEGRAM_BOT_TOKEN) {
    throw new Error("TELEGRAM_BOT_TOKEN is not configured");
  }

  if (!initData || typeof initData !== "string") {
    throw new Error("Telegram initData is required");
  }

  const params = new URLSearchParams(initData);

  const receivedHash = params.get("hash");

  if (!receivedHash) {
    throw new Error("Telegram hash is missing");
  }

  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(TELEGRAM_BOT_TOKEN)
    .digest();

  const calculatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  const receivedBuffer = Buffer.from(receivedHash, "hex");
  const calculatedBuffer = Buffer.from(calculatedHash, "hex");

  if (
    receivedBuffer.length !== calculatedBuffer.length ||
    !crypto.timingSafeEqual(receivedBuffer, calculatedBuffer)
  ) {
    throw new Error("Invalid Telegram initData");
  }

  const authDate = Number(params.get("auth_date"));

  if (!authDate) {
    throw new Error("Telegram auth_date is missing");
  }

  const now = Math.floor(Date.now() / 1000);

  // Reject very old Telegram login data
  if (now - authDate > 86400) {
    throw new Error("Telegram initData has expired");
  }

  const userString = params.get("user");

  if (!userString) {
    throw new Error("Telegram user data is missing");
  }

  let telegramUser;

  try {
    telegramUser = JSON.parse(userString);
  } catch {
    throw new Error("Invalid Telegram user data");
  }

  if (!telegramUser.id) {
    throw new Error("Telegram user ID is missing");
  }

  return telegramUser;
}

// ===============================
// Authentication middleware
// ===============================

function authMiddleware(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        ok: false,
        error: "Authorization token required",
      });
    }

    const token = header.substring(7);

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      ok: false,
      error: "Invalid or expired token",
    });
  }
}

// ===============================
// Health check
// ===============================

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      service: "Money Hunter20 Backend",
      database: "connected",
      time: new Date().toISOString(),
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      ok: false,
      service: "Money Hunter20 Backend",
      database: "disconnected",
    });
  }
});

// ===============================
// Telegram Login
// ===============================

app.post("/api/auth/telegram", async (req, res) => {
  try {
    const { initData } = req.body;

    const telegramUser = verifyTelegramInitData(initData);

    const telegramId = String(telegramUser.id);

    const username =
      telegramUser.username ||
      null;

    const displayName =
      [telegramUser.first_name, telegramUser.last_name]
        .filter(Boolean)
        .join(" ") ||
      username ||
      "Telegram User";

    // Find existing user
    const existing = await pool.query(
      `
      SELECT *
      FROM users
      WHERE telegram_id = $1
      LIMIT 1
      `,
      [telegramId]
    );

    let user;

    if (existing.rows.length > 0) {
      const updated = await pool.query(
        `
        UPDATE users
        SET
          username = $2,
          display_name = $3
        WHERE telegram_id = $1
        RETURNING *
        `,
        [telegramId, username, displayName]
      );

      user = updated.rows[0];
    } else {
      let referralCode = generateReferralCode();

      // Make sure referral code is unique
      for (let i = 0; i < 5; i++) {
        const check = await pool.query(
          `
          SELECT id
          FROM users
          WHERE referral_code = $1
          LIMIT 1
          `,
          [referralCode]
        );

        if (check.rows.length === 0) break;

        referralCode = generateReferralCode();
      }

      const created = await pool.query(
        `
        INSERT INTO users
          (
            telegram_id,
            username,
            display_name,
            balance,
            total_earned,
            referral_code,
            status
          )
        VALUES
          ($1, $2, $3, 0, 0, $4, 'active')
        RETURNING *
        `,
        [
          telegramId,
          username,
          displayName,
          referralCode,
        ]
      );

      user = created.rows[0];
    }

    const token = signUserToken(user);

    return res.json({
      ok: true,
      token,
      user: {
        id: user.id,
        telegram_id: user.telegram_id,
        username: user.username,
        display_name: user.display_name,
        balance: user.balance,
        total_earned: user.total_earned,
        referral_code: user.referral_code,
        status: user.status,
      },
    });
  } catch (error) {
    console.error("Telegram authentication error:", error);

    return res.status(401).json({
      ok: false,
      error: error.message || "Telegram authentication failed",
    });
  }
});

// ===============================
// Current User
// ===============================

app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        telegram_id,
        username,
        display_name,
        balance,
        total_earned,
        referral_code,
        referred_by,
        status,
        created_at
      FROM users
      WHERE id = $1
      LIMIT 1
      `,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "User not found",
      });
    }

    res.json({
      ok: true,
      user: result.rows[0],
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      ok: false,
      error: "Failed to load user",
    });
  }
});

// ===============================
// User Activity
// ===============================

app.get("/api/activity", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        type,
        amount,
        description,
        created_at
      FROM earning_transactions
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 50
      `,
      [req.user.userId]
    );

    res.json({
      ok: true,
      activities: result.rows,
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      ok: false,
      error: "Failed to load activity",
    });
  }
});

// ===============================
// Start Monetag Ad
// ===============================

app.post("/api/ad/start", authMiddleware, async (req, res) => {
  console.log("🔥 /api/ad/start called:", {
  userId: req.user.userId,
  telegramId: req.user.telegramId
});
  try {
    const userResult = await pool.query(
      `
      SELECT id, telegram_id, status
      FROM users
      WHERE id = $1
      LIMIT 1
      `,
      [req.user.userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        ok: false,
        error: "User not found"
      });
    }

    const user = userResult.rows[0];

    if (user.status !== "active") {
      return res.status(403).json({
        ok: false,
        error: "User account is not active"
      });
    }

    // Create a unique Monetag event ID
    const ymid =
  "mh20_" +
  crypto.randomUUID();

console.log("🆔 Created Money Hunter20 ad ymid:", ymid);

await pool.query(
      `
      INSERT INTO ad_reward_events
        (
          ymid,
          user_id,
          telegram_id,
          provider,
          status
        )
      VALUES
        ($1, $2, $3, 'monetag', 'pending')
      `,
      [
        ymid,
        user.id,
        String(user.telegram_id)
      ]
    );

    res.json({
      ok: true,
      ymid
    });

  } catch (error) {
    console.error("Ad start error:", error);

    res.status(500).json({
      ok: false,
      error: "Could not start advertisement"
    });
  }
});

// ===============================
// Daily Bonus
// ===============================

app.post("/api/daily-bonus", authMiddleware, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const reward = 1.00;

    const inserted = await client.query(
      `
      INSERT INTO daily_bonuses
        (user_id, amount, bonus_date)
      VALUES
        ($1, $2, CURRENT_DATE)
      ON CONFLICT (user_id, bonus_date)
      DO NOTHING
      RETURNING id
      `,
      [req.user.userId, reward]
    );

    if (inserted.rows.length === 0) {
      await client.query("ROLLBACK");

      return res.status(409).json({
        ok: false,
        error: "Daily bonus already claimed today"
      });
    }

    await client.query(
      `
      INSERT INTO earning_transactions
        (user_id, type, amount, description)
      VALUES
        ($1, 'daily_bonus', $2, 'Daily Bonus')
      `,
      [req.user.userId, reward]
    );

    await client.query(
      `
      UPDATE users
      SET
        balance = balance + $1,
        total_earned = total_earned + $1
      WHERE id = $2
      `,
      [reward, req.user.userId]
    );

    await client.query("COMMIT");

    const user = await pool.query(
      `
      SELECT balance, total_earned
      FROM users
      WHERE id = $1
      `,
      [req.user.userId]
    );

    res.json({
      ok: true,
      reward,
      user: user.rows[0]
    });

  } catch (error) {

    await client.query("ROLLBACK").catch(() => {});

    console.error("Daily bonus error:", error);

    res.status(500).json({
      ok: false,
      error: "Could not claim daily bonus"
    });

  } finally {
    client.release();
  }
});

// ===============================
// Withdrawal Request
// ===============================

app.post("/api/withdrawals", authMiddleware, async (req, res) => {

  const {
    amount,
    method,
    accountNumber,
    accountName
  } = req.body;

  const requestedAmount = Number(amount);

  if (!Number.isFinite(requestedAmount) || requestedAmount <= 0) {
    return res.status(400).json({
      ok: false,
      error: "Invalid withdrawal amount"
    });
  }

  const payoutMethod = String(method || "").toLowerCase();

  if (!["bkash", "nagad"].includes(payoutMethod)) {
    return res.status(400).json({
      ok: false,
      error: "Only bKash and Nagad are currently supported"
    });
  }

  if (!accountNumber || String(accountNumber).trim().length < 8) {
    return res.status(400).json({
      ok: false,
      error: "Valid account number is required"
    });
  }

  // Minimum withdrawal
  const MIN_WITHDRAWAL = 50.00;

  if (requestedAmount < MIN_WITHDRAWAL) {
    return res.status(400).json({
      ok: false,
      error:
        `Minimum withdrawal is ${MIN_WITHDRAWAL.toFixed(2)} points`
    });
  }

  const client = await pool.connect();

  try {

    await client.query("BEGIN");

    const userResult = await client.query(
      `
      SELECT balance
      FROM users
      WHERE id = $1
      FOR UPDATE
      `,
      [req.user.userId]
    );

    if (userResult.rows.length === 0) {

      await client.query("ROLLBACK");

      return res.status(404).json({
        ok: false,
        error: "User not found"
      });
    }

    const balance = Number(userResult.rows[0].balance);

    if (requestedAmount > balance) {

      await client.query("ROLLBACK");

      return res.status(400).json({
        ok: false,
        error: "Insufficient balance"
      });
    }

    const payout = await client.query(
      `
      INSERT INTO payout_methods
        (
          user_id,
          method,
          account_number,
          account_name
        )
      VALUES
        ($1, $2, $3, $4)
      RETURNING id
      `,
      [
        req.user.userId,
        payoutMethod,
        String(accountNumber).trim(),
        accountName || null
      ]
    );

    const withdrawal = await client.query(
      `
      INSERT INTO withdrawals
        (
          user_id,
          amount,
          method,
          account_number,
          status
        )
      VALUES
        ($1, $2, $3, $4, 'pending')
      RETURNING
        id,
        amount,
        method,
        status,
        created_at
      `,
      [
        req.user.userId,
        requestedAmount,
        payoutMethod,
        String(accountNumber).trim()
      ]
    );

    // Reserve the requested balance
    await client.query(
      `
      UPDATE users
      SET balance = balance - $1
      WHERE id = $2
      `,
      [
        requestedAmount,
        req.user.userId
      ]
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
      withdrawal: withdrawal.rows[0],
      payout_method_id: payout.rows[0].id
    });

  } catch (error) {

    await client.query("ROLLBACK").catch(() => {});

    console.error("Withdrawal error:", error);

    res.status(500).json({
      ok: false,
      error: "Could not create withdrawal request"
    });

  } finally {

    client.release();

  }
});

// ===============================
// Monetag Postback
// ===============================

app.get("/postback", async (req, res) => {
  const {
    ymid,
    event,
    reward_event_type,
    zone_id,
    sub_zone_id,
    estimated_price,
    telegram_id
  } = req.query;

  console.log("Monetag Postback received:", {
    ymid,
    event,
    reward_event_type,
    zone_id,
    sub_zone_id,
    estimated_price,
    telegram_id
  });

  // Basic validation
  if (!telegram_id) {
    return res.status(400).json({
      ok: false,
      error: "Missing telegram_id"
    });
  }

  // Only accept our Monetag zone
  if (String(zone_id) !== "11762706") {
    console.warn("Invalid Monetag zone:", zone_id);

    return res.status(403).json({
      ok: false,
      error: "Invalid zone"
    });
  }

  // Do NOT reward ordinary impressions.
  // Reward only when Monetag reports valued event.
  if (String(reward_event_type).toLowerCase() !== "valued") {
    console.log(
      "Monetag event received but not rewarded:",
      reward_event_type
    );

    return res.json({
      ok: true,
      credited: false,
      message: "Event received but not a reward event"
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    /*
      Monetag is returning Telegram ID as ymid.

      Therefore:
      1. First try the exact ymid.
      2. If not found, find the newest pending ad
         belonging to this Telegram user.
    */

    let eventResult = await client.query(
      `
      SELECT
        id,
        user_id,
        telegram_id,
        status,
        reward
      FROM ad_reward_events
      WHERE ymid = $1
      FOR UPDATE
      `,
      [String(ymid || "")]
    );

    // If Monetag ymid does not match our internal ID,
    // find the latest pending ad for this Telegram user.
    if (eventResult.rows.length === 0) {
      eventResult = await client.query(
        `
        SELECT
          id,
          user_id,
          telegram_id,
          status,
          reward
        FROM ad_reward_events
        WHERE telegram_id = $1
          AND status = 'pending'
        ORDER BY created_at DESC
        LIMIT 1
        FOR UPDATE
        `,
        [String(telegram_id)]
      );
    }

    if (eventResult.rows.length === 0) {
      await client.query("ROLLBACK");

      console.warn(
        "No pending Monetag ad found for Telegram ID:",
        String(telegram_id)
      );

      return res.status(404).json({
        ok: false,
        error: "No pending ad event found"
      });
    }

    const adEvent = eventResult.rows[0];

    // Verify Telegram ID
    if (
      String(adEvent.telegram_id) !== String(telegram_id)
    ) {
      await client.query("ROLLBACK");

      console.warn(
        "Telegram ID mismatch:",
        String(telegram_id)
      );

      return res.status(403).json({
        ok: false,
        error: "Telegram ID mismatch"
      });
    }

    // Never reward an already credited event
    if (adEvent.status === "credited") {
      await client.query("ROLLBACK");

      console.log(
        "Duplicate Monetag reward ignored:",
        adEvent.id
      );

      return res.json({
        ok: true,
        credited: false,
        duplicate: true
      });
    }

    // Get user
    const userResult = await client.query(
      `
      SELECT
        id,
        telegram_id,
        balance,
        total_earned,
        status
      FROM users
      WHERE id = $1
      FOR UPDATE
      `,
      [adEvent.user_id]
    );

    if (userResult.rows.length === 0) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        ok: false,
        error: "User not found"
      });
    }

    const user = userResult.rows[0];

    if (user.status !== "active") {
      await client.query("ROLLBACK");

      return res.status(403).json({
        ok: false,
        error: "User account is not active"
      });
    }

    // Money Hunter20 controls the reward amount.
    const reward = Number(adEvent.reward);

    if (!Number.isFinite(reward) || reward <= 0) {
      await client.query("ROLLBACK");

      return res.status(500).json({
        ok: false,
        error: "Invalid reward amount"
      });
    }

    // Save Monetag event information
    await client.query(
      `
      UPDATE ad_reward_events
      SET
        event = $1,
        reward_event_type = $2,
        zone_id = $3,
        sub_zone_id = $4,
        estimated_price = $5,
        status = 'credited',
        credited_at = CURRENT_TIMESTAMP
      WHERE id = $6
      `,
      [
        event || null,
        reward_event_type || null,
        zone_id || null,
        sub_zone_id || null,
        estimated_price
          ? Number(estimated_price)
          : null,
        adEvent.id
      ]
    );

    // Create earning transaction
    await client.query(
      `
      INSERT INTO earning_transactions
        (
          user_id,
          type,
          amount,
          description
        )
      VALUES
        (
          $1,
          'ad_reward',
          $2,
          'Monetag Ad Reward'
        )
      `,
      [
        adEvent.user_id,
        reward
      ]
    );

    // Add reward to balance
    await client.query(
      `
      UPDATE users
      SET
        balance = balance + $1,
        total_earned = total_earned + $1
      WHERE id = $2
      `,
      [
        reward,
        adEvent.user_id
      ]
    );

    await client.query("COMMIT");

    console.log(
      `✅ Monetag reward credited: user=${adEvent.user_id}, reward=${reward}, telegram_id=${telegram_id}`
    );

    return res.json({
      ok: true,
      credited: true,
      reward
    });

  } catch (error) {

    await client.query("ROLLBACK").catch(() => {});

    console.error(
      "Monetag postback error:",
      error
    );

    return res.status(500).json({
      ok: false,
      error: "Internal server error"
    });

  } finally {
    client.release();
  }
});

// ===============================
// Root
// ===============================

app.get("/", (req, res) => {
  res.json({
    ok: true,
    message: "Money Hunter20 Backend is running 🚀",
    health: "/api/health",
  });
});

// ===============================
// 404
// ===============================

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: "Route not found",
  });
});

// ===============================
// Database Setup
// ===============================

async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        telegram_id VARCHAR(50) UNIQUE NOT NULL,
        username VARCHAR(255),
        display_name VARCHAR(255),
        email VARCHAR(255),
        balance NUMERIC(12,2) DEFAULT 0,
        total_earned NUMERIC(12,2) DEFAULT 0,
        referral_code VARCHAR(50) UNIQUE,
        referred_by INTEGER REFERENCES users(id),
        status VARCHAR(30) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS earning_transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(50) NOT NULL,
        amount NUMERIC(12,2) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS daily_bonuses (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount NUMERIC(12,2) NOT NULL,
        bonus_date DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, bonus_date)
      );

      CREATE TABLE IF NOT EXISTS ad_views (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        ad_provider VARCHAR(100),
        ad_unit VARCHAR(100),
        reward NUMERIC(12,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS ad_reward_events (
  id SERIAL PRIMARY KEY,
  ymid VARCHAR(255) UNIQUE NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  telegram_id VARCHAR(50) NOT NULL,
  provider VARCHAR(50) NOT NULL DEFAULT 'monetag',
  event VARCHAR(100),
  reward_event_type VARCHAR(100),
  zone_id VARCHAR(100),
  sub_zone_id VARCHAR(100),
  estimated_price NUMERIC(12,6),
  reward NUMERIC(12,2) NOT NULL DEFAULT 1.00,
  status VARCHAR(30) NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  credited_at TIMESTAMP
);

      CREATE TABLE IF NOT EXISTS referrals (
        id SERIAL PRIMARY KEY,
        referrer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        referred_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        reward NUMERIC(12,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(referrer_id, referred_user_id)
      );

      CREATE TABLE IF NOT EXISTS payout_methods (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        method VARCHAR(50) NOT NULL,
        account_number VARCHAR(255) NOT NULL,
        account_name VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS withdrawals (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount NUMERIC(12,2) NOT NULL,
        method VARCHAR(50),
        account_number VARCHAR(255),
        status VARCHAR(30) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS fraud_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        reason TEXT,
        ip_address VARCHAR(100),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_earning_transactions_user_id
        ON earning_transactions(user_id);

      CREATE INDEX IF NOT EXISTS idx_ad_views_user_id
        ON ad_views(user_id);

      CREATE INDEX IF NOT EXISTS idx_ad_reward_events_user_id
  ON ad_reward_events(user_id);

CREATE INDEX IF NOT EXISTS idx_ad_reward_events_telegram_id
  ON ad_reward_events(telegram_id);

      CREATE INDEX IF NOT EXISTS idx_withdrawals_user_id
        ON withdrawals(user_id);

      CREATE INDEX IF NOT EXISTS idx_referrals_referrer_id
        ON referrals(referrer_id);
        
            `);

    console.log("Database tables are ready ✅");

  } catch (error) {
    console.error("Database setup error:", error);
  }
}

// ===============================
// Start Server
// ===============================

initDatabase().then(() => {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Money Hunter20 Backend running on port ${PORT}`);
  });
});
