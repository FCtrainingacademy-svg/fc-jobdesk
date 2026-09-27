// Postgres connection + schema (created automatically on start)
const { Pool } = require("pg");

const url = process.env.DATABASE_URL;
if (!url) {
  console.error("DATABASE_URL is not set. Add it in Render > Environment.");
  process.exit(1);
}
const pool = new Pool({
  connectionString: url,
  ssl: /render\.com|sslmode=require/.test(url) ? { rejectUnauthorized: false } : false,
});

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  phone         TEXT,
  gas_safe_no   TEXT,
  role          TEXT NOT NULL CHECK (role IN ('office','engineer')),
  password_hash TEXT,
  active        BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS password_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  used       BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS availability (
  engineer_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  day         DATE NOT NULL,
  slot        TEXT NOT NULL CHECK (slot IN ('am','pm')),
  PRIMARY KEY (engineer_id, day, slot)
);

CREATE TABLE IF NOT EXISTS jobs (
  id              SERIAL PRIMARY KEY,
  ref             TEXT UNIQUE,
  source          TEXT NOT NULL DEFAULT 'manual',
  status          TEXT NOT NULL DEFAULT 'lead'
                  CHECK (status IN ('lead','offered','booked','completed','cancelled')),
  customer_name   TEXT NOT NULL,
  customer_phone  TEXT,
  customer_email  TEXT,
  address         TEXT,
  postcode        TEXT,
  job_type        TEXT NOT NULL,
  description     TEXT,
  appliance       TEXT,
  day             DATE,
  slot            TEXT CHECK (slot IN ('am','pm')),
  engineer_id     INT REFERENCES users(id),
  price_note      TEXT,
  office_notes    TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  booked_at       TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS offers (
  id           SERIAL PRIMARY KEY,
  job_id       INT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  engineer_id  INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token        TEXT NOT NULL UNIQUE,
  status       TEXT NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending','accepted','declined','closed','expired')),
  sent_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,
  responded_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS materials (
  job_id      INT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
  boiler      TEXT,
  lines       JSONB NOT NULL DEFAULT '[]',
  notes       TEXT,
  status      TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','ready','sent')),
  updated_by  INT REFERENCES users(id),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  sent_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS activity (
  id         SERIAL PRIMARY KEY,
  job_id     INT REFERENCES jobs(id) ON DELETE CASCADE,
  user_id    INT REFERENCES users(id),
  text       TEXT NOT NULL,
  at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS outbox (
  id        SERIAL PRIMARY KEY,
  to_addr   TEXT NOT NULL,
  subject   TEXT NOT NULL,
  body      TEXT NOT NULL,
  link      TEXT,
  sent      BOOLEAN NOT NULL DEFAULT FALSE,
  error     TEXT,
  at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS jobs_day_idx ON jobs(day);
CREATE INDEX IF NOT EXISTS offers_job_idx ON offers(job_id);
`;

async function migrate() {
  await pool.query(SCHEMA);
}

module.exports = { pool, migrate, q: (text, params) => pool.query(text, params) };
