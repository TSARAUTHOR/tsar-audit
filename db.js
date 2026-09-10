import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(__dirname, "data");
const dbPath = path.join(dataDir, "tsar.db");

fs.mkdirSync(dataDir, { recursive: true });

export const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

function columns(table) {
  return db
    .prepare(`PRAGMA table_info(${table})`)
    .all()
    .map((c) => c.name);
}

export function open(schema) {
  db.exec(schema);

  const sessionCols = columns("sessions");
  if (sessionCols.length) {
    if (!sessionCols.includes("session_id")) {
      db.exec("ALTER TABLE sessions ADD COLUMN session_id TEXT NOT NULL DEFAULT ''");
    }
    if (!sessionCols.includes("created_at")) {
      db.exec("ALTER TABLE sessions ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0");
    }
    if (!sessionCols.includes("last_seen")) {
      db.exec("ALTER TABLE sessions ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0");
    }
    if (!sessionCols.includes("label")) {
      db.exec("ALTER TABLE sessions ADD COLUMN label TEXT NOT NULL DEFAULT ''");
    }
    if (!columns("sessions").includes("door")) {
      db.exec("ALTER TABLE sessions ADD COLUMN door TEXT NOT NULL DEFAULT 'real'");
    }
  }

  if (columns("users").length) {
    const addUser = (name, sql) => {
      if (!columns("users").includes(name)) db.exec(sql);
    };
    addUser("auth_hash_a", "ALTER TABLE users ADD COLUMN auth_hash_a TEXT NOT NULL DEFAULT ''");
    addUser("auth_hash_b", "ALTER TABLE users ADD COLUMN auth_hash_b TEXT NOT NULL DEFAULT ''");
    addUser("wrap_b", "ALTER TABLE users ADD COLUMN wrap_b TEXT NOT NULL DEFAULT ''");
    addUser("vault_a", "ALTER TABLE users ADD COLUMN vault_a TEXT NOT NULL DEFAULT ''");
    addUser("burned", "ALTER TABLE users ADD COLUMN burned INTEGER NOT NULL DEFAULT 0");
    addUser("deadman_every", "ALTER TABLE users ADD COLUMN deadman_every INTEGER NOT NULL DEFAULT 0");
    addUser("deadman_until", "ALTER TABLE users ADD COLUMN deadman_until INTEGER NOT NULL DEFAULT 0");
    addUser("created_at", "ALTER TABLE users ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0");
  }

  const msgCols = columns("messages");
  if (msgCols.includes("sender_id")) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS messages_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        msg_type INTEGER NOT NULL,
        ciphertext TEXT NOT NULL,
        from_box TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL
      );
      INSERT INTO messages_v2 (id, recipient_id, msg_type, ciphertext, from_box, created_at)
      SELECT m.id, m.recipient_id, m.msg_type, m.ciphertext, '', m.created_at
        FROM messages m;
      DROP TABLE messages;
      ALTER TABLE messages_v2 RENAME TO messages;
      CREATE INDEX IF NOT EXISTS idx_messages_inbox ON messages(recipient_id, id);
    `);
  } else if (msgCols.length && !msgCols.includes("from_box")) {
    db.exec("ALTER TABLE messages ADD COLUMN from_box TEXT NOT NULL DEFAULT ''");
  }

  return db;
}

export { dbPath };
