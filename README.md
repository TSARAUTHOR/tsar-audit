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

## Threat model: brutal honesty

If you expect magic network anonymity or buzzwords, leave. This node is a
cryptographic cupboard for one job: **what remains after seizure and a
database audit.**

Do not trust it until you can recite the limits.

A mailbox, not a mixnet. A letter has to land in a box. The node therefore
knows who was addressed. That is not a bug. That is a mailbox.

### Out of scope (the server knows; you cover this)

**1. Network and the reverse proxy (Caddy)**

Your IP connects to the machine. The JSON body has no `sender_id`. The
TCP peer is still an IP.

This Node process does not write IPs to SQLite and does not write an access
log. Flood control may HMAC `req.ip` in RAM; that secret dies on restart.
The live ship sits behind Caddy with `log { output discard }` — no access
log from that Caddyfile.

We do not own the data center or the ISP. A tap on the physical line still
sees TLS from your IP. This tree is not Tor. If traffic analysis is your
threat, you bring Tor. That is on you.

**2. The live session**

The database drops `sender_id`. Live memory does not.

`POST /api/messages` carries a valid session. For that slice of a second
the process knows who is dropping the envelope, and to whom. When the
handler returns, that mapping is not written to SQL. If the box is
already owned, or someone takes a RAM dump in that window, or someone adds
a `console.log`, the sender–recipient link can be captured before it is
discarded. We will not pretend otherwise.

**3. Endpoint and the other number**

A dirty OS, a keylogger, a screen-grabber, a recipient who talks: out of
scope. Cryptography does not save a compromised machine.

### In scope (what this tree actually delivers)

**1. The blind database**

`messages` has no `sender_id`. The row is recipient, type, ciphertext,
`from_box`, hour. `db.js` will still notice a legacy `sender_id` and burn
it. That scar is intentional.

Once the handler finishes and RAM moves on, the historical
sender–recipient graph is not in that table. What remains is a one-way
jam: which numbers received how many sealed envelopes, in which hours.

**2. Honest cryptography (this repo is not Signal)**

Do not grep this tree for a Double Ratchet. You will not find one. This
audit edition is the node. It stores envelopes. It does not implement
Signal.

`from_box` (`fromBox.js`) uses stock primitives, not a homemade cipher:

- X25519 ephemeral Diffie–Hellman
- HKDF-SHA-256 (`info`: `tsar/from-box/v1`) on v2
- AES-256-GCM

Wire: `v2.<ephPub>.<iv>.<ct>`. Sealed to the recipient identity public key.
The identity private key lives in the vault. The node cannot open the
vault, so it cannot open `from_box`. v1 decrypt is still accepted (DH bits
as the AES key). New mail is v2 only.

The live client at tsared.com still runs Signal on the **letter body**.
That client is not in this repository. If you are grading a ratchet, you
are in the wrong tree. If you are grading what the operator can read from
SQLite, you are in the right one.

**3. Forensic dead end (the disk, not the wire)**

A seized drive yields: six-digit numbers, bcrypt of a client-side proof
(not the password), AES-GCM vault blobs, public keys, hour-bucketed
envelopes the node cannot read. No IP column. No name. No email. No
plaintext. No sender column.

That is not "nothing." That is an empty cupboard with closed envelopes
addressed to numbers. If you wanted the operator blind to the recipient too,
you would be running an onion. This is not that project.

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
