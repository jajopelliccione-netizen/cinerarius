-- Cinerarius Admin — D1 schema
-- Applica con:  wrangler d1 execute cinerarius_admin --file=./schema.sql

CREATE TABLE IF NOT EXISTS users (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  email              TEXT UNIQUE NOT NULL,
  name               TEXT NOT NULL DEFAULT '',
  pass_hash          TEXT NOT NULL,
  pass_salt          TEXT NOT NULL,
  role               TEXT NOT NULL DEFAULT 'staff',     -- 'admin' | 'staff'
  must_change        INTEGER NOT NULL DEFAULT 1,
  perm_registrations INTEGER NOT NULL DEFAULT 0,
  perm_users         INTEGER NOT NULL DEFAULT 0,
  created_at         INTEGER NOT NULL,
  created_by         INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_exp  ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS registrations (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  nome        TEXT NOT NULL DEFAULT '',
  cognome     TEXT NOT NULL DEFAULT '',
  email       TEXT NOT NULL DEFAULT '',
  tel         TEXT NOT NULL DEFAULT '',
  ruolo       TEXT NOT NULL DEFAULT '',
  msg         TEXT NOT NULL DEFAULT '',
  source      TEXT NOT NULL DEFAULT 'sito',
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reg_created ON registrations(created_at);
