import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

const N = 16384,
  R = 8,
  P = 1,
  KEYLEN = 64;

function scryptAsync(password: string, salt: Buffer, n: number, r: number, p: number): Promise<Buffer> {
  return new Promise((res, rej) => scrypt(password, salt, KEYLEN, { N: n, r, p, maxmem: 64 * 1024 * 1024 }, (e, k) => (e ? rej(e) : res(k))));
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scryptAsync(password.normalize("NFKC"), salt, N, R, P);
  return `scrypt$${N}$${R}$${P}$${salt.toString("base64")}$${key.toString("base64")}`;
}

let dummy: Promise<string> | null = null;

/** Verifies a password. When the user does not exist (stored === null) a dummy hash is checked to equalise timing. */
export async function verifyPassword(password: string, stored: string | null): Promise<boolean> {
  dummy ??= hashPassword("dummy-password-for-timing-equalisation");
  const hash = stored ?? (await dummy);
  const [scheme, n, r, p, salt, key] = hash.split("$");
  if (scheme !== "scrypt") return false;
  const derived = await scryptAsync(password.normalize("NFKC"), Buffer.from(salt, "base64"), Number(n), Number(r), Number(p));
  const ok = timingSafeEqual(derived, Buffer.from(key, "base64"));
  return ok && stored !== null;
}

export const newSessionToken = () => randomBytes(32).toString("base64url");

/** Integration key: asg_<8 char public prefix>_<43 char secret>. Only sha256(full key) is stored. */
export function newIntegrationKey(): { key: string; prefix: string; hash: string } {
  let prefix = "";
  while (prefix.length < 8) prefix += randomBytes(8).toString("base64url").replace(/[^A-Za-z0-9]/g, "");
  prefix = prefix.slice(0, 8);
  const secret = randomBytes(32).toString("base64url");
  const key = `asg_${prefix}_${secret}`;
  return { key, prefix, hash: sha256(key) };
}

/** Device keys: hdv_<8 char prefix>_<43 char secret>. Used by the native companion; separate namespace from agent keys. */
export function newDeviceKey(): { key: string; prefix: string; hash: string } {
  const k = newIntegrationKey();
  const key = k.key.replace(/^asg_/, "hdv_");
  return { key, prefix: k.prefix, hash: sha256(key) };
}

export function parseDeviceKey(key: string): { prefix: string } | null {
  const m = /^hdv_([A-Za-z0-9]{8})_([A-Za-z0-9_-]{43})$/.exec(key);
  return m ? { prefix: m[1] } : null;
}

export function parseIntegrationKey(key: string): { prefix: string } | null {
  const m = /^asg_([A-Za-z0-9]{8})_([A-Za-z0-9_-]{43})$/.exec(key);
  return m ? { prefix: m[1] } : null;
}
