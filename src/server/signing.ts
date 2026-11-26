import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Config } from "./config.js";

export interface Signer {
  keyId: string;
  publicKeyPem: string;
  sign(data: string): string;
}

function fromPrivate(priv: ReturnType<typeof createPrivateKey>): Signer {
  const publicKeyPem = createPublicKey(priv).export({ type: "spki", format: "pem" }).toString();
  const keyId = createHash("sha256").update(publicKeyPem).digest("hex").slice(0, 16);
  return { keyId, publicKeyPem, sign: (data) => sign(null, Buffer.from(data), priv).toString("base64") };
}

/**
 * Production: POLICY_SIGNING_KEY (base64 PKCS#8 DER Ed25519). Development: a key persisted in DATA_DIR. Tests: ephemeral.
 * Returns undefined in production without a configured key, which disables offline bundles rather than inventing a key.
 */
export function loadSigner(config: Pick<Config, "NODE_ENV" | "POLICY_SIGNING_KEY" | "DATA_DIR">, opts: { ephemeral?: boolean } = {}): Signer | undefined {
  if (config.POLICY_SIGNING_KEY) return fromPrivate(createPrivateKey({ key: Buffer.from(config.POLICY_SIGNING_KEY, "base64"), format: "der", type: "pkcs8" }));
  if (config.NODE_ENV === "production") return undefined;
  if (opts.ephemeral || config.NODE_ENV === "test") return fromPrivate(generateKeyPairSync("ed25519").privateKey);
  const file = join(config.DATA_DIR, "policy-signing-key.pem");
  if (existsSync(file)) return fromPrivate(createPrivateKey(readFileSync(file)));
  mkdirSync(config.DATA_DIR, { recursive: true });
  const { privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(file, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  return fromPrivate(privateKey);
}

export function verifySignature(publicKeyPem: string, data: string, signatureB64: string): boolean {
  try {
    return verify(null, Buffer.from(data), createPublicKey(publicKeyPem), Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}

/** Helper for generating a production key: `node -e "..."` is documented in docs/DEPLOYMENT.md. */
export function generateSigningKeyB64(): string {
  return generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
}
