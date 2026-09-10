# TSAR Audit Edition

This is the node. Not the chat UI. Not the cash register. Not a cloak.

You install it. You read `schema.sql`. You query the SQLite. That is what an
operator sees when the iron is seized. If a claim in a post does not match
this tree, the post is lying.

Live messenger: [tsared.com](https://tsared.com). That machine also bills and
runs a desk. Those files are not here. You do not need them to prove the
mailbox.

**Do not call this zero-trace.** Do not call it unbreakable. Those words are
how you get eaten.

## Threat model: what we protect, and what we don't

If you want a spell that makes your body vanish from the wire, close this
tab. TSAR is not a network-anonymity tool. It is a cupboard built for one
job: **what remains after the server is seized.**

A mailbox, not a mixnet. A letter has to land in a box. The node therefore
knows who was addressed. That is not a bug. That is a mailbox.

### Out of scope (you cover this)

**1. Network traffic and IP addresses**

When you hit Send, TLS leaves your machine and hits the node. The payload
has no `sender_id`. The TCP peer is still an IP.

This process does not write IPs to SQLite. It does not write an access log.
Flood control may HMAC `req.ip` in RAM; that secret dies on restart.

**But:** a wire on the data-center cable, or a reverse proxy that logs, will
see an encrypted connection from your IP at that time. This tree is not
Tor. It is not a VPN. If traffic analysis is your threat, you bring Tor, a
hardened VPN, or a network that is not yours. That is on you.

**2. A dirty endpoint**

If the device is already owned — malware, a keylogger, a screen-grabber —
the cryptography is theatre. TSAR does not save a compromised OS.

**3. The other number**

We can hide the sender from the disk. We cannot make the recipient shut up,
lock their phone, or not take a screenshot.

### In scope (what the cupboard actually does)

**1. The blind mailbox, at rest**

`messages` has no `sender_id`. The row is: recipient, type, ciphertext,
`from_box`, hour. `db.js` will still notice a legacy `sender_id` and burn
it. That scar is intentional.

On disk, after seizure, you get a one-way jam: which numbers received how
many envelopes, in which hours. You do not get a sender–recipient graph from
that table.

**While the request is in the air:** `POST /api/messages` is an
authenticated session. The process knows who is dropping the envelope. It
does not write that number into the row. A patched node, or proxy logs,
can reconstruct who talked. This repo does not. Read that twice.

**2. Cryptographic sealing**

The **body** is Signal ciphertext from the browser. This repo is not the
Signal stack. It stores the envelope.

`from_box` is sealed here, in `fromBox.js`, to the recipient identity public
key:

- X25519 ephemeral key agreement
- HKDF-SHA-256 (`info`: `tsar/from-box/v1`) on v2
- AES-256-GCM

Wire: `v2.<ephPub>.<iv>.<ct>`. The identity private key lives in the vault.
The node cannot open the vault, so it cannot open `from_box`. v1 decrypt
is still accepted (DH bits as the AES key). New mail is v2 only.

**3. What a warrant gets from this SQLite**

A six-digit number. A bcrypt of a client-side proof — not the password. An
AES-GCM vault it cannot open. Public Signal keys. Hour-bucketed envelopes
it cannot read. No name. No email. No phone. No IP column.

That is not "zero forensic value." That is an empty cupboard with a pile of
closed envelopes addressed to numbers. If you wanted the operator blind to
the recipient too, you would be running an onion. This is not that project.

| Seizure of `data/tsar.db` | Live request / the wire | This tree |
| --- | --- | --- |
| Recipient | Authenticated sender on `POST /api/messages` | Stored: recipient. Not stored: sender. |
| `created_at` floored to the hour | Wall time in the process | Hour on disk |
| Ciphertext it cannot open | Same ciphertext | Signal body from the client |
| `from_box` it cannot open | Builds it from the sender number | Sealed to the recipient identity key |
| Who fetched whose prekeys | `GET /api/keys/:id` is a live edge | Not a table |
| TCP peer | Flood control HMAC in RAM | Not a SQL column |

## What is on disk

Read `schema.sql`. Then stop asking.

**`users`** — six-digit number, KDF salt, bcrypt of a client-side proof,
vault blob, public Signal bundle, duress hashes, dead-man timers,
registration time.

**`messages`** — `recipient_id`, `msg_type`, `ciphertext`, `from_box`,
`created_at`. No sender column.

**`sessions`** — hashed cookie, which number is open, which door, last seen.

**`archive`** — sealed blobs named with 64 hex. The node knows a number
stored a blob, and when.

**`one_time_prekeys`** — public one-time keys. Public by design.

## Bill of materials

`package.json` is the whole grocery list:

- `express`
- `better-sqlite3`
- `bcryptjs`
- `cookie-parser`

No payments SDK. No NOWPayments. No analytics. If you find a billing
dependency here, it is a bug — open an issue.

## Run

Node 22+.

```bash
npm install
npm start
```

Listens on `127.0.0.1:8787`. SQLite is created under `data/`.

```bash
curl -s http://127.0.0.1:8787/api/health
```

## License

TSAR Fair Use and Non-Commercial License. See `LICENSE.md`.

Read it. Run it. Audit it. Do not stand up a paid clone and put your name
on the hull.
