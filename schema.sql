CREATE TABLE users (
  id BIGSERIAL PRIMARY KEY,
  telegram_id BIGINT UNIQUE,
  username TEXT,
  display_name TEXT,
  email TEXT UNIQUE,
  balance NUMERIC(12,4) NOT NULL DEFAULT 0,
  total_earned NUMERIC(12,4) NOT NULL DEFAULT 0,
  referral_code TEXT UNIQUE NOT NULL,
  referred_by BIGINT REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE earning_transactions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  type TEXT NOT NULL,
  amount NUMERIC(12,4) NOT NULL CHECK (amount > 0),
  reference_id TEXT,
  status TEXT NOT NULL DEFAULT 'approved'
    CHECK (status IN ('pending','approved','rejected')),
  metadata JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE daily_bonuses (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  bonus_date DATE NOT NULL,
  amount NUMERIC(12,4) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, bonus_date)
);

CREATE TABLE ad_views (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  ad_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  event_id TEXT UNIQUE,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  reward NUMERIC(12,4) NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE referrals (
  id BIGSERIAL PRIMARY KEY,
  referrer_id BIGINT NOT NULL REFERENCES users(id),
  referred_user_id BIGINT UNIQUE NOT NULL REFERENCES users(id),
  reward NUMERIC(12,4) NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','rejected')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE payout_methods (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  method TEXT NOT NULL,
  destination TEXT NOT NULL,
  recipient_name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE withdrawals (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  payout_method_id BIGINT REFERENCES payout_methods(id),
  amount NUMERIC(12,4) NOT NULL CHECK (amount > 0),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','paid','rejected','cancelled')),
  admin_note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_at TIMESTAMPTZ
);

CREATE TABLE fraud_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id),
  event_type TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_transactions_user ON earning_transactions(user_id, created_at DESC);
CREATE INDEX idx_withdrawals_user ON withdrawals(user_id, created_at DESC);
CREATE INDEX idx_ad_views_user ON ad_views(user_id, created_at DESC);
