import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** Authenticator-app codes (TOTP, RFC 6238): HMAC-SHA1, 30-second steps, 6 digits, as every authenticator app expects. */
const STEP = 30;
const DIGITS = 6;
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = s.replace(/[\s=-]/g, "").toUpperCase();
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const i = B32.indexOf(ch);
    if (i < 0) throw new Error("Invalid base32");
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** 160-bit secret, base32, as recommended by RFC 4226. */
export const newTotpSecret = () => base32Encode(randomBytes(20));

export function totpAt(secretB32: string, step: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", base32Decode(secretB32)).update(msg).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** DIGITS).padStart(DIGITS, "0");
}

export const currentStep = (nowMs = Date.now()) => Math.floor(nowMs / 1000 / STEP);

/**
 * Checks a code against the current step and one step either side (clock drift). Returns the matched step, or null.
 * The caller stores the step and refuses any step at or below it, so a code can never be used twice.
 */
export function verifyTotp(secretB32: string, code: string, lastUsedStep: number, nowMs = Date.now()): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const now = currentStep(nowMs);
  for (const s of [now - 1, now, now + 1]) {
    if (s <= lastUsedStep) continue;
    const expected = Buffer.from(totpAt(secretB32, s));
    if (timingSafeEqual(expected, Buffer.from(code))) return s;
  }
  return null;
}

export function otpauthUri(secretB32: string, account: string, issuer = "Kenuxa Heimdall"): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP}`;
}

/** Ten single-use recovery codes like "k7q2-9xmd-4tpe": 60 bits each, shown once, stored as SHA-256. */
export function newRecoveryCodes(n = 10): string[] {
  const alphabet = "23456789abcdefghjkmnpqrstuvwxyz";
  return Array.from({ length: n }, () => {
    const b = randomBytes(12);
    let s = "";
    for (let i = 0; i < 12; i++) s += alphabet[b[i] % alphabet.length];
    return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`;
  });
}
export const normalizeRecoveryCode = (c: string) => c.trim().toLowerCase().replace(/[^a-z0-9]/g, "").replace(/^(.{4})(.{4})(.{4})$/, "$1-$2-$3");
