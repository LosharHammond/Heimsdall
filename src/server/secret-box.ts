import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import type { Config } from "./config.js";
import { log } from "./log.js";

/**
 * AES-256-GCM for secrets stored in the database (authenticator secrets, identity-provider client secrets, PKCE verifiers).
 * Format: v1.<iv>.<tag>.<ciphertext>, base64url. Outside production a fixed development key is used when AUTH_ENCRYPTION_KEY
 * is not set (with a warning); production refuses to start without one (config.ts).
 */
let warned = false;
function key(config: Config): Buffer {
  if (config.AUTH_ENCRYPTION_KEY) return Buffer.from(config.AUTH_ENCRYPTION_KEY, "base64");
  if (!warned && config.NODE_ENV !== "test") {
    log("warn", "AUTH_ENCRYPTION_KEY is not set: using a development-only key. Never run production like this.");
    warned = true;
  }
  return createHash("sha256").update("kenuxa-heimdall development-only key, never for production").digest();
}

export function seal(config: Config, plaintext: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key(config), iv);
  const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
  return ["v1", iv.toString("base64url"), c.getAuthTag().toString("base64url"), ct.toString("base64url")].join(".");
}

export function open(config: Config, sealed: string): string {
  const [v, iv, tag, ct] = sealed.split(".");
  if (v !== "v1" || !iv || !tag || ct === undefined) throw new Error("Unreadable sealed secret");
  const d = createDecipheriv("aes-256-gcm", key(config), Buffer.from(iv, "base64url"));
  d.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([d.update(Buffer.from(ct, "base64url")), d.final()]).toString("utf8");
}
