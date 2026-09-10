import crypto from "node:crypto";

const SECRET = crypto.randomBytes(32);
const buckets = new Map();

export const limitsOff = process.env.TSAR_LIMITS === "off";

if (limitsOff) {
  console.warn("!! TSAR_LIMITS=off — flood control disabled. Local testing only.");
}

function tag(value) {
  return crypto.createHmac("sha256", SECRET).update(String(value)).digest("base64");
}

function hit(key, limit, windowMs) {
  const now = Date.now();
  const bucket = buckets.get(key);

  if (!bucket || now >= bucket.resetAt) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return { ok: true, retryAfter: 0 };
  }
  if (bucket.count >= limit) {
    return { ok: false, retryAfter: Math.ceil((bucket.resetAt - now) / 1000) };
  }
  bucket.count += 1;
  return { ok: true, retryAfter: 0 };
}

function sweep() {
  const now = Date.now();
  for (const [key, bucket] of buckets) {
    if (now >= bucket.resetAt) buckets.delete(key);
  }
}

setInterval(sweep, 60_000).unref();

export function limit({ name, limit: max, windowMs, by = "address", message }) {
  return (req, res, next) => {
    if (limitsOff) return next();
    const parts = [name];
    if (by === "address" || by === "both") {
      const session = req.cookies?.tsar;
      parts.push(tag(session || req.ip || "local"));
    }
    if (by === "number" || by === "both") parts.push(tag(req.body?.publicId ?? ""));

    const result = hit(parts.join("|"), max, windowMs);
    if (result.ok) return next();

    res.set("Retry-After", String(result.retryAfter));
    res.status(429).json({
      error: message ?? "Too many attempts. Wait a moment and try again.",
      retryAfter: result.retryAfter,
    });
  };
}

export function globalLimit({ name, limit: max, windowMs, message }) {
  return (req, res, next) => {
    if (limitsOff) return next();
    const result = hit(`global|${name}`, max, windowMs);
    if (result.ok) return next();
    res.set("Retry-After", String(result.retryAfter));
    res.status(429).json({
      error: message ?? "TSAR is busy issuing numbers. Try again shortly.",
      retryAfter: result.retryAfter,
    });
  };
}
