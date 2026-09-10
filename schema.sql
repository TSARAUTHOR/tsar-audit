CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id TEXT NOT NULL UNIQUE,

  kdf_salt TEXT NOT NULL,
  auth_hash TEXT NOT NULL,

  vault TEXT NOT NULL,

  registration_id INTEGER NOT NULL,
  identity_key TEXT NOT NULL,
  signed_prekey_id INTEGER NOT NULL,
  signed_prekey_pub TEXT NOT NULL,
  signed_prekey_sig TEXT NOT NULL,

  created_at INTEGER NOT NULL DEFAULT 0,

  auth_hash_a TEXT NOT NULL DEFAULT '',
  auth_hash_b TEXT NOT NULL DEFAULT '',
  wrap_b TEXT NOT NULL DEFAULT '',
  vault_a TEXT NOT NULL DEFAULT '',
  burned INTEGER NOT NULL DEFAULT 0,
  deadman_every INTEGER NOT NULL DEFAULT 0,
  deadman_until INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL,
  public_key TEXT NOT NULL,
  UNIQUE (user_id, key_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,

  session_id TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0,
  last_seen INTEGER NOT NULL DEFAULT 0,

  label TEXT NOT NULL DEFAULT '',

  door TEXT NOT NULL DEFAULT 'real'
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  msg_type INTEGER NOT NULL,
  ciphertext TEXT NOT NULL,
  from_box TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS archive (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  blob TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, name)
);

CREATE INDEX IF NOT EXISTS idx_prekeys_user ON one_time_prekeys(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_messages_inbox ON messages(recipient_id, id);
