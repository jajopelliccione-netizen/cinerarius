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
  perm_users         INTEGER NOT NULL DEFAULT 0,
  perm_content       INTEGER NOT NULL DEFAULT 0,
  created_at         INTEGER NOT NULL,
  created_by         INTEGER
);
-- Aggiornamento di un DB già esistente (creato prima della gestione contenuti):
--   ALTER TABLE users ADD COLUMN perm_content INTEGER NOT NULL DEFAULT 0;
--   UPDATE users SET perm_content=1 WHERE role='admin';

CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_exp  ON sessions(expires_at);
