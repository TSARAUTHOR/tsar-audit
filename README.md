# TSAR Audit Edition

This is the public node: registration, login proofs, Signal pre-key bundles, a blind mailbox, sealed vaults, duress doors. No UI. No payments. No office.

The production messenger at [tsared.com](https://tsared.com) runs this same routing and crypto. The live node also has billing and a desk. Those are not in this tree. You do not need them to prove the server is blind.

## What the node can see

- A six-digit number
- A password *proof* (bcrypt of a client-side PBKDF2). Not the password.
- An AES-GCM vault blob it cannot open
- Public Signal keys
- Ciphertext envelopes
- `from_box`: an X25519+AES-GCM wrapping of the sender id, openable only with the recipient identity key

There is no `sender_id` column on `messages`.

## What the node cannot see

- The password
- Message plaintext
- Who wrote a letter, unless it is the recipient opening `from_box` on their machine

## Run

```bash
npm install
node index.js
```

Listens on `127.0.0.1:8787`. SQLite is created under `data/`.

## Honest limits

This is not an onion router. The node still sees that an envelope moved, and when. It does not see the body or a sender column.

Licensed under the TSAR Fair Use and Non-Commercial License (`LICENSE.md`).
Personal use and security auditing only — no paid service, no competing
platform. Read `index.js`, `fromBox.js`, and `schema.sql`.
