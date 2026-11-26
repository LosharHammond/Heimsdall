/**
 * Minimal, strict OpenID Connect relying party: discovery, authorization-code flow with PKCE (S256), and ID-token verification
 * against the provider's published keys. Used for "Continue with Google" and for per-organization SSO (Okta, Microsoft Entra ID,
 * Google Workspace, any standard OIDC provider).
 *
 * The ID token is accepted only if: the signature verifies with a key from the issuer's JWKS (RS256, PS256 or ES256; never
 * "none" or a shared-secret algorithm), iss equals the configured issuer, aud contains our client id (and azp is ours when
 * several audiences are listed), it is not expired (60 s leeway), and the nonce equals the one we generated for this sign-in.
 */
import { createHash, createPublicKey, randomBytes, verify as cryptoVerify, type webcrypto } from "node:crypto";
type JsonWebKey = webcrypto.JsonWebKey;
import { HttpError } from "./errors.js";

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nonce?: string;
  azp?: string;
  email?: string;
  email_verified?: boolean | string;
  name?: string;
  hd?: string;
  amr?: string[];
  [k: string]: unknown;
}

const b64url = (b: Buffer) => b.toString("base64url");
export const randomToken = (bytes = 32) => b64url(randomBytes(bytes));
export const pkceChallenge = (verifier: string) => b64url(createHash("sha256").update(verifier).digest());

const fail = (msg: string) => new HttpError(401, "SSO_FAILED", msg);

const discoveryCache = new Map<string, { at: number; doc: OidcDiscovery }>();
const jwksCache = new Map<string, { at: number; keys: Array<JsonWebKey & { kid?: string; alg?: string; use?: string }> }>();
const TTL = 10 * 60_000;

async function getJson(f: typeof fetch, url: string): Promise<any> {
  if (!url.startsWith("https://")) throw fail(`Identity provider endpoints must use https (${url})`);
  let r: Response;
  try {
    r = await f(url, { headers: { accept: "application/json" }, redirect: "error", signal: AbortSignal.timeout(8000) });
  } catch (e) {
    throw new HttpError(502, "SSO_PROVIDER_UNREACHABLE", `Could not reach the identity provider (${(e as Error).message}).`);
  }
  if (!r.ok) throw new HttpError(502, "SSO_PROVIDER_ERROR", `The identity provider answered ${r.status} for ${new URL(url).pathname}.`);
  return r.json();
}

export async function discover(f: typeof fetch, issuer: string): Promise<OidcDiscovery> {
  const hit = discoveryCache.get(issuer);
  if (hit && Date.now() - hit.at < TTL) return hit.doc;
  const doc = (await getJson(f, `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`)) as OidcDiscovery;
  // The discovery document must describe exactly this issuer (prevents one provider impersonating another).
  if (doc.issuer?.replace(/\/$/, "") !== issuer.replace(/\/$/, "")) throw fail("The identity provider's discovery document names a different issuer.");
  for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri"] as const) {
    if (typeof doc[k] !== "string" || !doc[k].startsWith("https://")) throw fail(`The identity provider's ${k} is missing or not https.`);
  }
  discoveryCache.set(issuer, { at: Date.now(), doc });
  return doc;
}

async function keysFor(f: typeof fetch, jwksUri: string, kid: string | undefined, refresh = false) {
  const hit = jwksCache.get(jwksUri);
  if (!refresh && hit && Date.now() - hit.at < TTL) return hit.keys;
  const body = await getJson(f, jwksUri);
  const keys = Array.isArray(body?.keys) ? body.keys : [];
  jwksCache.set(jwksUri, { at: Date.now(), keys });
  return keys;
}

const ALGS: Record<string, { hash: string; kty: string; opts?: Record<string, unknown> }> = {
  RS256: { hash: "sha256", kty: "RSA" },
  PS256: { hash: "sha256", kty: "RSA", opts: { padding: 6 /* RSA_PKCS1_PSS_PADDING */, saltLength: 32 } },
  ES256: { hash: "sha256", kty: "EC", opts: { dsaEncoding: "ieee-p1363" } },
};

export async function verifyIdToken(
  f: typeof fetch,
  token: string,
  expect: { issuer: string; clientId: string; nonce: string; jwksUri: string; now?: number },
): Promise<IdTokenClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw fail("Malformed ID token.");
  let header: { alg?: string; kid?: string; typ?: string };
  let claims: IdTokenClaims;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    throw fail("Malformed ID token.");
  }
  const alg = ALGS[header.alg ?? ""];
  if (!alg) throw fail(`ID token algorithm '${header.alg}' is not accepted.`);
  const signed = Buffer.from(`${parts[0]}.${parts[1]}`);
  const sig = Buffer.from(parts[2], "base64url");
  const check = async (refresh: boolean) => {
    const keys = await keysFor(f, expect.jwksUri, header.kid, refresh);
    const candidates = keys.filter((k: any) => k.kty === alg.kty && (!header.kid || k.kid === header.kid) && (!k.use || k.use === "sig") && (!k.alg || k.alg === header.alg));
    for (const jwk of candidates) {
      try {
        const key = createPublicKey({ key: jwk as JsonWebKey, format: "jwk" });
        if (cryptoVerify(alg.hash, signed, { key, ...(alg.opts ?? {}) } as any, sig)) return true;
      } catch {
        /* unusable key: try the next */
      }
    }
    return false;
  };
  // An unknown key id usually means the provider rotated its keys: fetch the set once more.
  if (!(await check(false)) && !(await check(true))) throw fail("The ID token signature does not verify.");

  const now = Math.floor((expect.now ?? Date.now()) / 1000);
  if (claims.iss?.replace(/\/$/, "") !== expect.issuer.replace(/\/$/, "")) throw fail("The ID token was issued by a different issuer.");
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(expect.clientId)) throw fail("The ID token is for a different application.");
  if (aud.length > 1 && claims.azp !== expect.clientId) throw fail("The ID token's authorized party is not this application.");
  if (typeof claims.exp !== "number" || claims.exp + 60 < now) throw fail("The ID token has expired.");
  if (typeof claims.iat === "number" && claims.iat - 60 > now) throw fail("The ID token is from the future.");
  if (!claims.nonce || claims.nonce !== expect.nonce) throw fail("The ID token does not belong to this sign-in (nonce mismatch).");
  if (typeof claims.sub !== "string" || !claims.sub) throw fail("The ID token has no subject.");
  return claims;
}

export async function exchangeCode(
  f: typeof fetch,
  tokenEndpoint: string,
  p: { code: string; redirectUri: string; clientId: string; clientSecret: string; codeVerifier: string },
): Promise<{ id_token: string }> {
  const body = new URLSearchParams({ grant_type: "authorization_code", code: p.code, redirect_uri: p.redirectUri, client_id: p.clientId, client_secret: p.clientSecret, code_verifier: p.codeVerifier });
  let r: Response;
  try {
    r = await f(tokenEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body, redirect: "error", signal: AbortSignal.timeout(8000) });
  } catch (e) {
    throw new HttpError(502, "SSO_PROVIDER_UNREACHABLE", `Could not reach the identity provider (${(e as Error).message}).`);
  }
  const j = (await r.json().catch(() => ({}))) as { id_token?: string; error?: string; error_description?: string };
  if (!r.ok || typeof j.id_token !== "string") throw fail(`The identity provider refused the sign-in code${j.error ? ` (${j.error})` : ""}.`);
  return { id_token: j.id_token };
}

/** Exposed for tests. */
export function clearOidcCaches() {
  discoveryCache.clear();
  jwksCache.clear();
}
