# TSAR Audit Edition

This is the node. Not the chat UI. Not the cash register. Not a speech.

You install it. You read `schema.sql`. You query the SQLite. That is what an
operator sees when the iron is seized. If a claim in a post does not match this
tree, the post is lying.

Live messenger: [tsared.com](https://tsared.com). That machine also bills and
runs a desk. Those files are not here. You do not need them to prove the
mailbox.

**Do not call this zero-trace.** Do not call it unbreakable. Those words are
how you get eaten.

## Threat model

This is an **offline mailbox**, not a P2P mesh, not Tor, not a mixnet.

A letter has to land in someone's box. The node therefore knows **who was
addressed**. It also knows **which hour** the envelope was accepted. That is
not a bug in the schema. That is what a mailbox is.

| Seizure of `data/tsar.db` | Operator watching a live request | This tree |
| --- | --- | --- |
| Recipient of each envelope | Authenticated sender on `POST /api/messages` | Stored: recipient. Not stored: sender. |
| `created_at` floored to the hour (`hourStamp`) | Exact wall time in the process | Hour on disk. Not a millisecond stamp. |
| Ciphertext it cannot open | Same ciphertext | Envelope body is Signal ciphertext from the client |
| `from_box` it cannot open | Builds `from_box` from the sender number | Sealed to the recipient identity key |
| Who fetched whose prekeys | `GET /api/keys/:id` is a live edge | Not written to a table |
| TCP peer | Flood control may HMAC `req.ip` in RAM | Not a SQL column. Secret dies on restart. |

If they seize the disk, they get a one-way traffic jam: which numbers received
how many envelopes, in which hours. They do not get a social graph from
`messages`, because there is no `sender_id`.

If they run the node, or they own the reverse proxy logs, they can see who
talked. **This process does not write an access log.** Your Caddy/nginx might.
That noose is yours.

The client still runs Signal in the browser. This repo is not the Signal
stack. It is the cupboard.

## What is on disk

Read `schema.sql`. Then stop asking.

**`users`** — six-digit number, KDF salt, bcrypt of a client-side proof (not
the password), an AES-GCM vault blob, public Signal bundle, duress hashes,
dead-man timers, registration time.

**`messages`** — `recipient_id`, `msg_type`, `ciphertext`, `from_box`,
`created_at`. No sender column. `db.js` will still notice a legacy
`sender_id` and burn it. That scar is intentional.

**`sessions`** — hashed cookie, which number is open, which door, last seen.

**`archive`** — named sealed blobs. The node does not know the names in
plain text (64 hex). It knows that a number stored a blob, and when.

**`one_time_prekeys`** — public one-time keys. Public by design.

## `from_box`

`fromBox.js`. Industry primitives. No homemade cipher.

- **X25519** ephemeral key agreement (WebCrypto)
- **HKDF-SHA-256** (`info`: `tsar/from-box/v1`) on v2
- **AES-256-GCM**

Wire format: `v2.<ephPub>.<iv>.<ct>`.

The node encrypts the sender's six digits to the **recipient's identity public
key**. Only the recipient's identity private key opens it. That private key
lives in the vault, which the node cannot open.

v1 decrypt is still accepted (DH bits used as the AES key, no HKDF). New
mail is v2 only. If you are grading homework, say v2 and sit down.

## What this node cannot see

- The password
- Message plaintext
- The sender column on disk
- The opened `from_box` (no identity private key)

## What this node can see, and will not deny

- The recipient
- That an envelope moved, and in which hour
- Envelope type (`msg_type`)
- That a signed-in number asked for another number's prekeys (live)
- How many envelopes a box is holding

If you wanted the operator to be blind to the recipient too, you would not
be running a mailbox on a machine you own. You would be running an onion.
This is not that project.

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

Read it. Run it. Audit it. Do not stand up a paid clone and put your name on
the hull.
