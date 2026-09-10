import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import express from "express";
import { dbPath, open } from "./db.js";
import { globalLimit, limit, limitsOff } from "./limits.js";
import { hideFrom, hourStamp } from "./fromBox.js";

function loadEnv() {
  const file = path.join(path.dirname(fileURLToPath(import.meta.url)), ".env");
  if (!fs.existsSync(file)) return;
  for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const cut = line.indexOf("=");
    if (cut < 1) continue;
    const key = line.slice(0, cut).trim();
    let value = line.slice(cut + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

loadEnv();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const db = open(fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8"));

const insertUser = db.prepare(
  `INSERT INTO users (
     public_id, kdf_salt, auth_hash, vault,
     registration_id, identity_key,
     signed_prekey_id, signed_prekey_pub, signed_prekey_sig,
     created_at
   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
);
const findAuth = db.prepare(
  `SELECT id, public_id, kdf_salt, auth_hash, vault,
          auth_hash_a AS authHashA, auth_hash_b AS authHashB,
          wrap_b AS wrapB, vault_a AS vaultA, burned,
          deadman_every AS deadmanEvery, deadman_until AS deadmanUntil
     FROM users WHERE public_id = ?`,
);
const publicIdTaken = db.prepare("SELECT 1 FROM users WHERE public_id = ?");
const readVault = db.prepare("SELECT vault FROM users WHERE id = ?");
const writeVault = db.prepare("UPDATE users SET vault = ? WHERE id = ?");
const readBundle = db.prepare(
  `SELECT id, public_id, registration_id, identity_key,
          signed_prekey_id, signed_prekey_pub, signed_prekey_sig, burned
     FROM users WHERE public_id = ?`,
);

const insertPreKey = db.prepare(
  "INSERT OR IGNORE INTO one_time_prekeys (user_id, key_id, public_key) VALUES (?, ?, ?)",
);
const takePreKey = db.prepare(
  "SELECT id, key_id, public_key FROM one_time_prekeys WHERE user_id = ? ORDER BY id LIMIT 1",
);
const dropPreKey = db.prepare("DELETE FROM one_time_prekeys WHERE id = ?");
const countPreKeys = db.prepare(
  "SELECT COUNT(*) AS n FROM one_time_prekeys WHERE user_id = ?",
);

const readArchive = db.prepare(
  "SELECT name, blob, updated_at AS updatedAt FROM archive WHERE user_id = ?",
);
const countArchive = db.prepare("SELECT COUNT(*) AS n FROM archive WHERE user_id = ?");
const upsertArchive = db.prepare(
  `INSERT INTO archive (user_id, name, blob, updated_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id, name)
     DO UPDATE SET blob = excluded.blob, updated_at = excluded.updated_at`,
);
const dropArchive = db.prepare("DELETE FROM archive WHERE user_id = ?");
const dropArchiveRow = db.prepare("DELETE FROM archive WHERE user_id = ? AND name = ?");

const insertSession = db.prepare(
  `INSERT INTO sessions (token_hash, user_id, expires_at, session_id, created_at, last_seen, label, door)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
);
const findSession = db.prepare(
  `SELECT users.id, users.public_id,
          sessions.session_id AS sessionId,
          sessions.last_seen AS lastSeen,
          sessions.door AS door
     FROM sessions
     JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?`,
);
const deleteSession = db.prepare("DELETE FROM sessions WHERE token_hash = ?");
const sweepSessions = db.prepare("DELETE FROM sessions WHERE expires_at <= ?");
const touchSeen = db.prepare("UPDATE sessions SET last_seen = ? WHERE token_hash = ?");
const listSessions = db.prepare(
  `SELECT session_id AS id, label, created_at AS createdAt, last_seen AS lastSeen,
          expires_at AS expiresAt
     FROM sessions
    WHERE user_id = ? AND expires_at > ?
    ORDER BY last_seen DESC`,
);
const deleteSessionById = db.prepare(
  "DELETE FROM sessions WHERE user_id = ? AND session_id = ?",
);
const deleteOtherSessions = db.prepare(
  "DELETE FROM sessions WHERE user_id = ? AND session_id != ?",
);
const writeSessionLabel = db.prepare("UPDATE sessions SET label = ? WHERE token_hash = ?");

const insertMessage = db.prepare(
  `INSERT INTO messages (recipient_id, msg_type, ciphertext, from_box, created_at)
   VALUES (?, ?, ?, ?, ?)`,
);
const inbox = db.prepare(
  `SELECT m.id, m.msg_type AS type, m.ciphertext AS body, m.from_box AS fromBox, m.created_at AS at
     FROM messages m
    WHERE m.recipient_id = ?
    ORDER BY m.id ASC
    LIMIT 200`,
);
const dropMessage = db.prepare(
  "DELETE FROM messages WHERE id = ? AND recipient_id = ?",
);

const readDeadman = db.prepare(
  `SELECT deadman_every AS deadmanEvery, deadman_until AS deadmanUntil, burned
     FROM users WHERE id = ?`,
);
const writeDoorA = db.prepare("UPDATE users SET auth_hash_a = ?, vault_a = ? WHERE id = ?");
const writeDoorB = db.prepare("UPDATE users SET auth_hash_b = ?, wrap_b = ? WHERE id = ?");
const writeDeadman = db.prepare(
  "UPDATE users SET deadman_every = ?, deadman_until = ? WHERE id = ?",
);
const dropSessionsFor = db.prepare("DELETE FROM sessions WHERE user_id = ?");
const dropMailTo = db.prepare("DELETE FROM messages WHERE recipient_id = ?");
const dropPrekeysFor = db.prepare("DELETE FROM one_time_prekeys WHERE user_id = ?");
const burnUser = db.prepare(
  `UPDATE users SET
      burned = 1,
      auth_hash = ?,
      auth_hash_a = '',
      auth_hash_b = '',
      wrap_b = '',
      vault_a = '',
      vault = ?,
      deadman_every = 0,
      deadman_until = 0
    WHERE id = ?`,
);

const SESSION_MS = 1000 * 60 * 60 * 24 * 14;
const TICKET_MS = 1000 * 60 * 10;
const COOKIE = "tsar";

const tickets = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [id, ticket] of tickets) {
    if (now >= ticket.expiresAt) tickets.delete(id);
  }
  sweepSessions.run(now);
}, 60_000).unref();

function reservedNumbers() {
  return new Set([...tickets.values()].map((t) => t.publicId));
}

function allocateNumber() {
  const reserved = reservedNumbers();
  for (let i = 0; i < 40; i += 1) {
    const n = String(crypto.randomInt(100000, 1000000));
    if (!reserved.has(n) && !publicIdTaken.get(n)) return n;
  }
  return null;
}

export function parsePublicId(raw) {
  const digits = String(raw ?? "")
    .replace(/\s+/g, "");
  return /^\d{6}$/.test(digits) ? digits : null;
}

function isB64(value, maxLength) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maxLength &&
    /^[A-Za-z0-9+/=]+$/.test(value)
  );
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function isSealed(value, maxLength) {
  return (
    typeof value === "string" &&
    value.length >= 16 &&
    value.length <= maxLength &&
    value.includes(".")
  );
}

function matchesProof(proof, hash) {
  const target = hash && typeof hash === "string" && hash.length >= 20 ? hash : DUMMY_HASH;
  try {
    const ok = bcrypt.compareSync(proof, target);
    return target !== DUMMY_HASH && ok;
  } catch {
    return false;
  }
}

const HASH_COST = 12;
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(32).toString("hex"), HASH_COST);
const decoyFile = path.join(path.dirname(dbPath), ".decoy-key");
function decoySecret() {
  try {
    if (fs.existsSync(decoyFile)) return fs.readFileSync(decoyFile);
  } catch {
  }
  const buf = crypto.randomBytes(32);
  try {
    fs.writeFileSync(decoyFile, buf, { mode: 0o600 });
  } catch {
  }
  return buf;
}

const COOKIE_BASE = {
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production",
  path: "/",
};

const MISS = { error: "Unknown number, or wrong password." };
const DEADMAN_MS = new Set([
  0,
  3 * 24 * 60 * 60_000,
  7 * 24 * 60 * 60_000,
  14 * 24 * 60 * 60_000,
  30 * 24 * 60 * 60_000,
]);

function requireLive(req, res, decoy) {
  const me = requireUser(req, res);
  if (!me) return null;
  if (me.door === "a") {
    if (decoy != null) {
      const status = Number(decoy.status) || 200;
      const body = { ...decoy };
      delete body.status;
      res.status(status).json(body);
    } else {
      res.status(401).json({ error: "You are not signed in." });
    }
    return null;
  }
  return me;
}

function sessionLabel(raw) {
  return String(raw ?? "")
    .replace(/[\n\r\t]/g, " ")
    .trim()
    .slice(0, 40);
}

function startSession(res, userId, label = "", door = "real") {
  const token = crypto.randomBytes(32).toString("hex");
  const now = Date.now();
  const sessionId = crypto.randomBytes(16).toString("hex");
  insertSession.run(
    hashToken(token),
    userId,
    now + SESSION_MS,
    sessionId,
    now,
    now,
    sessionLabel(label),
    door === "a" || door === "b" ? door : "real",
  );
  res.cookie(COOKIE, token, {
    ...COOKIE_BASE,
    maxAge: SESSION_MS,
  });
}

function currentUser(req) {
  const token = req.cookies?.[COOKIE];
  if (!token) return null;
  const now = Date.now();
  const hash = hashToken(token);
  const row = findSession.get(hash, now);
  if (!row) return null;
  if (now - row.lastSeen > 20_000) touchSeen.run(now, hash);
  return row;
}

function requireUser(req, res) {
  const user = currentUser(req);
  if (!user) {
    res.status(401).json({ error: "You are not signed in." });
    return null;
  }
  return user;
}

const app = express();
app.disable("x-powered-by");
if (process.env.TSAR_TRUST_PROXY === "1") app.set("trust proxy", 1);
app.use(express.json({ limit: "512kb" }));
app.use(cookieParser());
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(self)");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  next();
});

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    limits: limitsOff ? "off" : "on",
  });
});

app.post(
  "/api/register/begin",
  globalLimit({ name: "register", limit: 60, windowMs: 60 * 60 * 1000 }),
  limit({
    name: "register-begin",
    limit: 5,
    windowMs: 60 * 60 * 1000,
    message: "Too many numbers requested from here. Try again later.",
  }),
  (_req, res) => {
    const publicId = allocateNumber();
    if (!publicId) {
      return res.status(503).json({ error: "No numbers free right now. Try again." });
    }
    const ticket = crypto.randomBytes(24).toString("hex");
    const salt = crypto.randomBytes(16).toString("base64");
    tickets.set(ticket, { publicId, salt, expiresAt: Date.now() + TICKET_MS });
    res.json({ publicId, salt, ticket });
  },
);

app.post(
  "/api/register/finish",
  limit({ name: "register-finish", limit: 10, windowMs: 60 * 60 * 1000 }),
  (req, res) => {
    const ticket = tickets.get(String(req.body?.ticket ?? ""));
    if (!ticket || Date.now() >= ticket.expiresAt) {
      return res.status(410).json({ error: "That number reservation expired. Start again." });
    }

    const { authProof, vault, bundle } = req.body ?? {};
    if (!isB64(authProof, 128)) {
      return res.status(400).json({ error: "Malformed sign-in proof." });
    }
    if (typeof vault !== "string" || vault.length < 16 || vault.length > 200_000) {
      return res.status(400).json({ error: "Malformed key vault." });
    }
    if (
      !bundle ||
      !Number.isInteger(bundle.registrationId) ||
      !isB64(bundle.identityKey, 200) ||
      !Number.isInteger(bundle.signedPreKey?.keyId) ||
      !isB64(bundle.signedPreKey?.publicKey, 200) ||
      !isB64(bundle.signedPreKey?.signature, 200) ||
      !Array.isArray(bundle.preKeys) ||
      bundle.preKeys.length === 0 ||
      bundle.preKeys.length > 120
    ) {
      return res.status(400).json({ error: "Malformed key bundle." });
    }

    tickets.delete(String(req.body.ticket));
    if (publicIdTaken.get(ticket.publicId)) {
      return res.status(409).json({ error: "That number was just taken. Start again." });
    }

    const create = db.transaction(() => {
      const info = insertUser.run(
        ticket.publicId,
        ticket.salt,
        bcrypt.hashSync(authProof, HASH_COST),
        vault,
        bundle.registrationId,
        bundle.identityKey,
        bundle.signedPreKey.keyId,
        bundle.signedPreKey.publicKey,
        bundle.signedPreKey.signature,
        Date.now(),
      );
      for (const key of bundle.preKeys) {
        if (Number.isInteger(key?.keyId) && isB64(key?.publicKey, 200)) {
          insertPreKey.run(info.lastInsertRowid, key.keyId, key.publicKey);
        }
      }
      return info.lastInsertRowid;
    });

    const userId = create();
    startSession(res, userId, req.body?.label);
    res.json({ publicId: ticket.publicId });
  },
);

const DECOY = decoySecret();

app.post(
  "/api/login/salt",
  limit({ name: "login-salt", limit: 30, windowMs: 15 * 60 * 1000 }),
  (req, res) => {
    const publicId = parsePublicId(req.body?.publicId);
    if (!publicId) return res.status(400).json({ error: "A TSAR number is six digits." });
    const row = findAuth.get(publicId);
    const salt =
      row && !row.burned
        ? row.kdf_salt
        : crypto.createHmac("sha256", DECOY).update(publicId).digest().subarray(0, 16).toString("base64");
    res.json({ salt });
  },
);

app.post(
  "/api/login",
  limit({
    name: "login",
    limit: 10,
    windowMs: 15 * 60 * 1000,
    by: "both",
    message: "Too many sign-in attempts. Wait a few minutes.",
  }),
  (req, res) => {
    const publicId = parsePublicId(req.body?.publicId);
    const authProof = String(req.body?.authProof ?? "");
    if (!publicId) return res.status(400).json({ error: "A TSAR number is six digits." });

    const user = findAuth.get(publicId);
    const real = matchesProof(authProof, user && !user.burned ? user.auth_hash : "");
    const doorA = matchesProof(authProof, user && !user.burned ? user.authHashA : "");
    const doorB = matchesProof(authProof, user && !user.burned ? user.authHashB : "");
    if (!user || user.burned || (!real && !doorA && !doorB)) {
      return res.status(401).json(MISS);
    }

    if (real) {
      const now = Date.now();
      const deadman =
        DEADMAN_MS.has(user.deadmanEvery) &&
        user.deadmanEvery > 0 &&
        user.deadmanUntil > 0 &&
        now > user.deadmanUntil;
      startSession(res, user.id, req.body?.label, "real");
      return res.json({
        publicId: user.public_id,
        vault: user.vault,
        door: "real",
        deadman: deadman || undefined,
      });
    }

    if (doorB) {
      if (!user.wrapB) return res.status(401).json(MISS);
      startSession(res, user.id, req.body?.label, "b");
      return res.json({
        publicId: user.public_id,
        vault: user.vault,
        door: "b",
        wrap: user.wrapB,
      });
    }

    if (doorA) {
      if (!user.vaultA) return res.status(401).json(MISS);
      startSession(res, user.id, req.body?.label, "a");
      return res.json({ publicId: user.public_id, vault: user.vaultA, door: "a" });
    }

    return res.status(401).json(MISS);
  },
);

app.post("/api/logout", (req, res) => {
  const token = req.cookies?.[COOKIE];
  if (token) deleteSession.run(hashToken(token));
  res.clearCookie(COOKIE, COOKIE_BASE);
  res.json({ ok: true });
});

app.get("/api/sessions", (req, res) => {
  const me = requireUser(req, res);
  if (!me) return;
  if (me.door === "a") {
    return res.json({
      sessions: [
        {
          id: me.sessionId,
          label: "",
          createdAt: Date.now(),
          lastSeen: Date.now(),
          expiresAt: Date.now() + SESSION_MS,
          mine: true,
        },
      ],
    });
  }
  sweepSessions.run(Date.now());
  const mine = me.sessionId;
  res.json({
    sessions: listSessions.all(me.id, Date.now()).map((row) => ({
      id: row.id,
      label: row.label,
      createdAt: row.createdAt,
      lastSeen: row.lastSeen,
      expiresAt: row.expiresAt,
      mine: row.id === mine,
    })),
  });
});

app.delete("/api/sessions/:id", (req, res) => {
  const me = requireUser(req, res);
  if (!me) return;
  const id = String(req.params.id ?? "");
  if (!/^[a-f0-9]{16,64}$/.test(id)) {
    return res.status(400).json({ error: "Unknown session." });
  }
  if (me.door === "a" && id !== me.sessionId) {
    return res.status(401).json({ error: "You are not signed in." });
  }
  deleteSessionById.run(me.id, id);
  if (id === me.sessionId) {
    res.clearCookie(COOKIE, COOKIE_BASE);
  }
  res.json({ ok: true });
});

app.post("/api/sessions/drop-others", (req, res) => {
  const me = requireLive(req, res, { ok: true });
  if (!me) return;
  deleteOtherSessions.run(me.id, me.sessionId);
  res.json({ ok: true });
});

app.post("/api/sessions/here", (req, res) => {
  const me = requireUser(req, res);
  if (!me) return;
  const token = req.cookies?.[COOKIE];
  const label = sessionLabel(req.body?.label);
  if (token && label) writeSessionLabel.run(label, hashToken(token));
  res.json({ ok: true });
});

app.post("/api/duress/a", (req, res) => {
  const me = requireUser(req, res);
  if (!me) return;
  if (me.door !== "real") return res.json({ ok: true, a: !req.body?.clear });
  if (req.body?.clear) {
    writeDoorA.run("", "", me.id);
    return res.json({ ok: true, a: false });
  }
  const authProof = String(req.body?.authProof ?? "");
  const vault = req.body?.vault;
  if (!isB64(authProof, 128) || !isSealed(vault, 200_000)) {
    return res.status(400).json({ error: "Malformed door." });
  }
  const user = findAuth.get(me.public_id);
  if (!user || matchesProof(authProof, user.auth_hash) || matchesProof(authProof, user.authHashB)) {
    return res.status(400).json({ error: "Pick a different password." });
  }
  writeDoorA.run(bcrypt.hashSync(authProof, HASH_COST), vault, me.id);
  res.json({ ok: true, a: true });
});

app.post("/api/duress/b", (req, res) => {
  const me = requireUser(req, res);
  if (!me) return;
  if (me.door !== "real") return res.json({ ok: true, b: !req.body?.clear });
  if (req.body?.clear) {
    writeDoorB.run("", "", me.id);
    return res.json({ ok: true, b: false });
  }
  const authProof = String(req.body?.authProof ?? "");
  const wrap = req.body?.wrap;
  if (!isB64(authProof, 128) || !isSealed(wrap, 8_000)) {
    return res.status(400).json({ error: "Malformed door." });
  }
  const user = findAuth.get(me.public_id);
  if (!user || matchesProof(authProof, user.auth_hash) || matchesProof(authProof, user.authHashA)) {
    return res.status(400).json({ error: "Pick a different password." });
  }
  writeDoorB.run(bcrypt.hashSync(authProof, HASH_COST), wrap, me.id);
  res.json({ ok: true, b: true });
});

app.post("/api/duress/deadman", (req, res) => {
  const me = requireUser(req, res);
  if (!me) return;
  if (me.door !== "real") {
    const every = Number(req.body?.every) || 0;
    return res.json({ ok: true, every: DEADMAN_MS.has(every) ? every : 0, until: 0 });
  }
  const every = Number(req.body?.every) || 0;
  if (!DEADMAN_MS.has(every)) {
    return res.status(400).json({ error: "That interval is not offered." });
  }
  const until = every > 0 ? Date.now() + every : 0;
  writeDeadman.run(every, until, me.id);
  res.json({ ok: true, every, until });
});

app.post("/api/duress/pulse", (req, res) => {
  const me = requireUser(req, res);
  if (!me) return;
  if (me.door !== "real") return res.json({ fire: false });
  const row = readDeadman.get(me.id);
  if (!row || row.burned || !row.deadmanEvery) return res.json({ fire: false });
  if (!DEADMAN_MS.has(row.deadmanEvery)) {
    writeDeadman.run(0, 0, me.id);
    return res.json({ fire: false });
  }
  const now = Date.now();
  if (row.deadmanUntil > 0 && now > row.deadmanUntil) {
    return res.json({ fire: true });
  }
  writeDeadman.run(row.deadmanEvery, now + row.deadmanEvery, me.id);
  res.json({ fire: false });
});

app.post(
  "/api/duress/burn",
  limit({ name: "duress-burn", limit: 8, windowMs: 15 * 60 * 1000 }),
  (req, res) => {
  const me = requireUser(req, res);
  if (!me) return;
  if (me.door === "a") return res.json({ ok: true });
  const gone = db.transaction(() => {
    burnUser.run(
      bcrypt.hashSync(crypto.randomBytes(32).toString("hex"), HASH_COST),
      crypto.randomBytes(64).toString("base64"),
      me.id,
    );
    dropSessionsFor.run(me.id);
    dropArchive.run(me.id);

    dropMailTo.run(me.id);
    dropPrekeysFor.run(me.id);
  });
  gone();
  res.clearCookie(COOKIE, COOKIE_BASE);
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const me = currentUser(req);
  if (!me) return res.status(401).json({ error: "You are not signed in." });
  if (me.door === "a") {
    const row = findAuth.get(me.public_id);
    if (!row?.vaultA) return res.status(401).json({ error: "You are not signed in." });
    return res.json({
      publicId: me.public_id,
      vault: row.vaultA,
    });
  }
  res.json({
    publicId: me.public_id,
    vault: readVault.get(me.id).vault,
  });
});

app.put("/api/vault", (req, res) => {
  const me = requireLive(req, res, { ok: true });
  if (!me) return;
  const vault = req.body?.vault;
  if (typeof vault !== "string" || vault.length < 16 || vault.length > 200_000) {
    return res.status(400).json({ error: "Malformed key vault." });
  }
  writeVault.run(vault, me.id);
  res.json({ ok: true });
});

const ARCHIVE_ROWS = 400;
const ARCHIVE_BLOB = 300_000;

app.get("/api/archive", (req, res) => {
  const me = requireUser(req, res);
  if (!me) return;
  if (me.door === "a") return res.json({ items: [] });
  res.json({ items: readArchive.all(me.id) });
});

app.put(
  "/api/archive/:name",
  limit({ name: "archive-put", limit: 600, windowMs: 60 * 1000 }),
  (req, res) => {
    const me = requireLive(req, res, { ok: true });
    if (!me) return;

    const name = String(req.params.name ?? "");
    if (!/^[a-f0-9]{64}$/.test(name)) {
      return res.status(400).json({ error: "Bad archive name." });
    }

    const blob = req.body?.blob;
    if (typeof blob !== "string" || blob.length < 16 || blob.length > ARCHIVE_BLOB) {
      return res.status(400).json({ error: "Malformed archive entry." });
    }

    if (countArchive.get(me.id).n >= ARCHIVE_ROWS) {
      const known = readArchive.all(me.id).some((row) => row.name === name);
      if (!known) return res.status(409).json({ error: "Archive is full." });
    }

    upsertArchive.run(me.id, name, blob, Date.now());
    res.json({ ok: true });
  },
);

app.delete("/api/archive/:name", (req, res) => {
  const me = requireLive(req, res, { ok: true });
  if (!me) return;
  const name = String(req.params.name ?? "");
  if (!/^[a-f0-9]{64}$/.test(name)) {
    return res.status(400).json({ error: "Bad archive name." });
  }
  dropArchiveRow.run(me.id, name);
  res.json({ ok: true });
});

app.delete("/api/archive", (req, res) => {
  const me = requireLive(req, res, { ok: true });
  if (!me) return;
  dropArchive.run(me.id);
  res.json({ ok: true });
});

app.get(
  "/api/keys/:publicId",
  limit({ name: "keys-take", limit: 40, windowMs: 60 * 60 * 1000 }),
  (req, res) => {
  const me = requireLive(req, res, { status: 404, error: "No such number." });
  if (!me) return;
  const publicId = parsePublicId(req.params.publicId);
  if (!publicId) return res.status(400).json({ error: "A TSAR number is six digits." });

  const other = readBundle.get(publicId);
  if (!other || other.burned) return res.status(404).json({ error: "No such number." });
  if (other.id === me.id) return res.status(400).json({ error: "That is your own number." });

  const oneTime = db.transaction(() => {
    const row = takePreKey.get(other.id);
    if (row) dropPreKey.run(row.id);
    return row;
  })();

  res.json({
    publicId: other.public_id,
    registrationId: other.registration_id,
    identityKey: other.identity_key,
    signedPreKey: {
      keyId: other.signed_prekey_id,
      publicKey: other.signed_prekey_pub,
      signature: other.signed_prekey_sig,
    },
    preKey: oneTime ? { keyId: oneTime.key_id, publicKey: oneTime.public_key } : null,
  });
});

app.post(
  "/api/keys/topup",
  limit({ name: "topup", limit: 20, windowMs: 60 * 60 * 1000 }),
  (req, res) => {
    const me = requireLive(req, res, { remaining: 0 });
    if (!me) return;
    const preKeys = req.body?.preKeys;
    if (!Array.isArray(preKeys) || preKeys.length === 0 || preKeys.length > 120) {
      return res.status(400).json({ error: "Malformed prekeys." });
    }
    const add = db.transaction(() => {
      for (const key of preKeys) {
        if (Number.isInteger(key?.keyId) && isB64(key?.publicKey, 200)) {
          insertPreKey.run(me.id, key.keyId, key.publicKey);
        }
      }
    });
    add();
    res.json({ remaining: countPreKeys.get(me.id).n });
  },
);

app.get("/api/keys", (req, res) => {
  const me = requireLive(req, res, { remaining: 0 });
  if (!me) return;
  res.json({ remaining: countPreKeys.get(me.id).n });
});

app.post(
  "/api/messages",
  limit({ name: "send", limit: 120, windowMs: 60 * 1000 }),
  async (req, res) => {
    const me = requireLive(req, res, { ok: true });
    if (!me) return;
    const publicId = parsePublicId(req.body?.to);
    const type = Number(req.body?.type);
    const body = req.body?.body;
    const ctrl = type === 11 || type === 13;

    if (!publicId) return res.status(400).json({ error: "A TSAR number is six digits." });
    if (type !== 1 && type !== 3 && !ctrl) return res.status(400).json({ error: "Bad envelope." });
    if (typeof body !== "string" || body.length === 0 || body.length > 100_000) {
      return res.status(400).json({ error: "Bad envelope." });
    }

    const other = readBundle.get(publicId);
    if (!other || other.burned) return res.status(404).json({ error: "No such number." });
    if (other.id === me.id) return res.status(400).json({ error: "That is your own number." });

    let fromBox = "";
    try {
      fromBox = await hideFrom(other.identity_key, me.public_id);
    } catch {
      return res.status(502).json({ error: "The envelope could not be sealed." });
    }
    insertMessage.run(other.id, type, body, fromBox, hourStamp());
    res.json({ ok: true });
  },
);

app.get("/api/messages", (req, res) => {
  const me = requireUser(req, res);
  if (!me) return;
  if (me.door === "a") return res.json({ messages: [] });
  res.json({ messages: inbox.all(me.id) });
});

app.post("/api/messages/ack", (req, res) => {
  const me = requireLive(req, res, { ok: true });
  if (!me) return;
  const ids = req.body?.ids;
  if (!Array.isArray(ids)) return res.status(400).json({ error: "Bad acknowledgement." });
  const clear = db.transaction(() => {
    for (const id of ids.slice(0, 200)) {
      if (Number.isInteger(id)) dropMessage.run(id, me.id);
    }
  });
  clear();
  res.json({ ok: true });
});

const port = Number(process.env.TSAR_PORT ?? 8787);
app.listen(port, "127.0.0.1", () => {
  const { n } = db.prepare("SELECT COUNT(*) AS n FROM users").get();
  console.log(`TSAR audit node on http://127.0.0.1:${port}`);
  console.log(`SQLite     ${dbPath}`);
  console.log(`Numbers    ${n}`);
});
