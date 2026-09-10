
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toB64(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromB64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function curveRaw(buf) {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (u.length === 33 && u[0] === 5) return u.slice(1);
  if (u.length === 32) return u;
  throw new Error("Bad curve key.");
}

async function x25519Priv(raw) {
  return crypto.subtle.importKey("pkcs8", pkcs8FromRaw(raw), "X25519", false, ["deriveBits"]);
}

function pkcs8FromRaw(raw32) {
  const head = Uint8Array.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
  ]);
  const out = new Uint8Array(head.length + 32);
  out.set(head, 0);
  out.set(raw32, head.length);
  return out.buffer;
}

async function x25519Pub(raw) {
  return crypto.subtle.importKey("raw", raw, "X25519", false, []);
}

async function boxKey(bits, usage) {
  const ikm = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: encoder.encode("tsar/from-box/v1") },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

export async function hideFrom(identityPubB64, fromId) {
  const theirRaw = curveRaw(fromB64(identityPubB64));
  const eph = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const theirPub = await x25519Pub(theirRaw);
  const bits = await crypto.subtle.deriveBits({ name: "X25519", public: theirPub }, eph.privateKey, 256);
  const aes = await boxKey(bits, "encrypt");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, encoder.encode(fromId));
  const ephPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  return `v2.${toB64(ephPub)}.${toB64(iv)}.${toB64(ct)}`;
}

export async function showFrom(identityPrivB64, box) {
  const blob = String(box || "");
  if (blob.startsWith("open:")) throw new Error("Bad from-box.");
  const parts = blob.split(".");
  const ver = parts[0];
  if ((ver !== "v1" && ver !== "v2") || parts.length !== 4) throw new Error("Bad from-box.");
  const myRaw = curveRaw(fromB64(identityPrivB64));
  const myPriv = await x25519Priv(myRaw);
  const ephPub = await x25519Pub(fromB64(parts[1]));
  const bits = await crypto.subtle.deriveBits({ name: "X25519", public: ephPub }, myPriv, 256);
  const aes =
    ver === "v2"
      ? await boxKey(bits, "decrypt")
      : await crypto.subtle.importKey("raw", bits, { name: "AES-GCM" }, false, ["decrypt"]);
  const opened = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(parts[2]) },
    aes,
    fromB64(parts[3]),
  );
  const id = decoder.decode(opened).replace(/\D/g, "").slice(0, 6);
  if (!/^\d{6}$/.test(id)) throw new Error("Bad from-box.");
  return id;
}

export function hourStamp(ms = Date.now()) {
  return ms - (ms % (60 * 60 * 1000));
}
