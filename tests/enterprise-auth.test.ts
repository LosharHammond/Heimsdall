/**
 * Enterprise sign-in, end to end through the real HTTP app: two-step verification, organization rules (required MFA, required
 * SSO), roles, sessions, and single sign-on with Google, Kenuxa Accounts and an organization's own OIDC provider. Identity
 * providers are fakes with real RSA keys and real PKCE checks, reached through the injected fetch.
 */
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../src/server/app.js";
import { loadConfig } from "../src/server/config.js";
import { createDb, type Db } from "../src/server/db.js";
import { setLogLevel } from "../src/server/log.js";
import { runMigrations } from "../src/server/migrate.js";
import { clearOidcCaches } from "../src/server/oidc.js";
import { loadSigner } from "../src/server/signing.js";
import { base32Decode, currentStep, totpAt } from "../src/server/totp.js";

// ---------------------------------------------------------------- fake identity providers

const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");
const challengeOf = (v: string) => b64u(createHash("sha256").update(v).digest());

class FakeOidc {
  keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  kid = b64u(randomBytes(6));
  codes = new Map<string, { nonce: string; challenge: string; clientId: string; claims: Record<string, unknown> }>();
  constructor(public issuer: string, public clientId: string, public clientSecret: string) {}
  jwk() {
    return { ...(this.keys.publicKey.export({ format: "jwk" }) as object), kid: this.kid, alg: "RS256", use: "sig" };
  }
  jwt(claims: Record<string, unknown>, key: KeyObject = this.keys.privateKey, kid = this.kid) {
    const h = b64u(JSON.stringify({ alg: "RS256", kid, typ: "JWT" }));
    const p = b64u(JSON.stringify(claims));
    return `${h}.${p}.${b64u(sign("sha256", Buffer.from(`${h}.${p}`), key))}`;
  }
  /** What the person's browser would do at the provider: sign in and come back with a code. */
  authorize(location: string, claims: Record<string, unknown>, tamper: (c: Record<string, unknown>) => Record<string, unknown> = (c) => c) {
    const u = new URL(location);
    expect(u.origin + u.pathname).toBe(`${this.issuer}/authorize`);
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    const code = b64u(randomBytes(16));
    const now = Math.floor(Date.now() / 1000);
    this.codes.set(code, {
      nonce: u.searchParams.get("nonce")!, challenge: u.searchParams.get("code_challenge")!, clientId: u.searchParams.get("client_id")!,
      claims: tamper({ iss: this.issuer, aud: this.clientId, iat: now, exp: now + 300, nonce: u.searchParams.get("nonce"), ...claims }),
    });
    return { code, state: u.searchParams.get("state")! };
  }
  async handle(url: URL, init?: RequestInit): Promise<Response | null> {
    if (url.origin !== new URL(this.issuer).origin) return null;
    if (url.pathname.endsWith("/.well-known/openid-configuration")) {
      return Response.json({ issuer: this.issuer, authorization_endpoint: `${this.issuer}/authorize`, token_endpoint: `${this.issuer}/token`, jwks_uri: `${this.issuer}/jwks` });
    }
    if (url.pathname.endsWith("/jwks")) return Response.json({ keys: [this.jwk()] });
    if (url.pathname.endsWith("/token")) {
      const f = new URLSearchParams(String(init?.body));
      const c = this.codes.get(f.get("code") ?? "");
      this.codes.delete(f.get("code") ?? "");
      if (!c || f.get("client_secret") !== this.clientSecret || f.get("client_id") !== c.clientId || challengeOf(f.get("code_verifier") ?? "") !== c.challenge) {
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }
      return Response.json({ id_token: this.jwt(c.claims), access_token: "x" });
    }
    return null;
  }
}

class FakeKenuxa {
  accounts = "https://accounts.kenuxa.test";
  supabase = "https://sb.kenuxa.test";
  codes = new Map<string, { challenge: string; redirectUri: string; user: Record<string, unknown> }>();
  tokens = new Map<string, Record<string, unknown>>();
  logouts = 0;
  authorize(location: string, user: Record<string, unknown>) {
    const u = new URL(location);
    expect(u.origin + u.pathname).toBe(`${this.accounts}/authorize`);
    expect(u.searchParams.get("client_id")).toBe("heimdall");
    const code = b64u(randomBytes(32));
    this.codes.set(code, { challenge: u.searchParams.get("code_challenge")!, redirectUri: u.searchParams.get("redirect_uri")!, user });
    return { code, state: u.searchParams.get("state")! };
  }
  async handle(url: URL, init?: RequestInit): Promise<Response | null> {
    if (url.origin !== this.supabase) return null;
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    if (url.pathname === "/functions/v1/accounts/token") {
      const c = this.codes.get(body.code);
      this.codes.delete(body.code);
      if (!c || body.clientId !== "heimdall" || body.redirectUri !== c.redirectUri || challengeOf(body.codeVerifier) !== c.challenge) {
        return Response.json({ message: "This sign-in link has expired or was already used." }, { status: 400 });
      }
      const tokenHash = b64u(randomBytes(20));
      this.tokens.set(tokenHash, c.user);
      return Response.json({ tokenHash, type: "magiclink" });
    }
    if (url.pathname === "/auth/v1/verify") {
      const user = this.tokens.get(body.token_hash);
      this.tokens.delete(body.token_hash);
      if (!user || body.type !== "magiclink") return Response.json({ msg: "Token has expired or is invalid" }, { status: 403 });
      return Response.json({ access_token: "sb-access", refresh_token: "sb-refresh", user });
    }
    if (url.pathname === "/auth/v1/logout") {
      this.logouts++;
      return new Response(null, { status: 204 });
    }
    return null;
  }
}

// ---------------------------------------------------------------- environment

const google = new FakeOidc("https://accounts.google.com", "google-client", "google-secret");
const acme = new FakeOidc("https://idp.acme.test", "acme-client", "acme-secret");
const kenuxa = new FakeKenuxa();
const dns = new Map<string, string[][]>();

let db: Db;
let app: ReturnType<typeof createApp>;
beforeAll(async () => {
  const config = loadConfig({
    NODE_ENV: "test", LOG_LEVEL: "error",
    GOOGLE_CLIENT_ID: google.clientId, GOOGLE_CLIENT_SECRET: google.clientSecret,
    KENUXA_ACCOUNTS_URL: kenuxa.accounts, KENUXA_SUPABASE_URL: kenuxa.supabase, KENUXA_SUPABASE_ANON_KEY: "anon",
  } as NodeJS.ProcessEnv);
  setLogLevel("error");
  db = await createDb(config, { memory: true });
  await runMigrations(db);
  const fakeFetch = (async (input: string, init?: RequestInit) => {
    const url = new URL(input);
    for (const p of [google, acme, kenuxa]) {
      const r = await p.handle(url, init);
      if (r) return r;
    }
    throw new TypeError(`unexpected fetch ${url}`);
  }) as unknown as typeof fetch;
  app = createApp({ db, config, signer: loadSigner(config, { ephemeral: true }), fetch: fakeFetch, resolveTxt: async (n) => dns.get(n) ?? [] }, { ipLimitsMultiplier: 1000 });
});
afterAll(async () => db.close());
beforeEach(() => clearOidcCaches());

let n = 0;
const uniq = (p: string) => `${p}${Date.now().toString(36)}${(n++).toString(36)}`;

/** A browser with a cookie jar. */
class Browser {
  jar = new Map<string, string>();
  async req(method: string, path: string, body?: unknown) {
    const cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
    const res = await app.request(path, { method, headers: { "content-type": "application/json", "x-asg-csrf": "1", ...(cookie ? { cookie } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
    for (const sc of res.headers.getSetCookie?.() ?? []) {
      const [kv, ...attrs] = sc.split(";");
      const [k, v] = kv.split("=");
      if (attrs.some((a) => /max-age=0/i.test(a)) || v === "") this.jar.delete(k.trim());
      else this.jar.set(k.trim(), v);
    }
    const text = await res.text();
    let json: any = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      /* redirect bodies */
    }
    return { status: res.status, body: json, location: res.headers.get("location") };
  }
  get = (p: string) => this.req("GET", p);
  post = (p: string, b?: unknown) => this.req("POST", p, b ?? {});
}

const PASSWORD = "correct horse battery staple";
async function signUp(label = "u") {
  const b = new Browser();
  const email = `${uniq(label)}@example.test`;
  expect((await b.post("/api/auth/register", { email, name: label, password: PASSWORD })).status).toBe(201);
  expect((await b.post("/api/auth/login", { email, password: PASSWORD })).status).toBe(200);
  return Object.assign(b, { email });
}
async function makeOrg(owner: Browser) {
  const r = await owner.post("/api/orgs", { name: uniq("Org") });
  expect(r.status).toBe(201);
  return r.body.id as string;
}
const code = (secret: string, offset = 0) => totpAt(secret, currentStep() + offset);

async function enableMfa(b: Browser) {
  const s = await b.post("/api/auth/mfa/setup", { password: PASSWORD });
  expect(s.status).toBe(200);
  expect(s.body.otpauth_uri).toMatch(/^otpauth:\/\/totp\/Kenuxa%20Heimdall/);
  const e = await b.post("/api/auth/mfa/enable", { code: code(s.body.secret) });
  expect(e.status).toBe(200);
  return { secret: s.body.secret as string, recovery: e.body.recovery_codes as string[] };
}

// ---------------------------------------------------------------- tests

describe("authenticator codes (RFC 6238)", () => {
  it("matches the RFC test vector", () => {
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // base32 of the RFC key "12345678901234567890"
    expect(base32Decode(secret).toString()).toBe("12345678901234567890");
    expect(totpAt(secret, Math.floor(59 / 30))).toBe("287082");
    expect(totpAt(secret, Math.floor(1111111109 / 30))).toBe("081804");
  });
});

describe("two-step verification", () => {
  it("enrolment, sign-in with a code, no code reuse, recovery codes work once", async () => {
    const b = await signUp("mfa");
    expect((await b.post("/api/auth/mfa/setup", { password: "wrong password!!" })).status).toBe(401);
    const { secret, recovery } = await enableMfa(b);
    expect(recovery).toHaveLength(10);
    expect((await b.get("/api/auth/mfa")).body).toMatchObject({ enabled: true, recovery_codes_left: 10, this_session_verified: true });

    // a new device: password alone is not enough
    const d = new Browser();
    const first = await d.post("/api/auth/login", { email: b.email, password: PASSWORD });
    expect(first.body).toMatchObject({ mfa_required: true });
    expect(d.jar.has("asg_session")).toBe(false);
    expect((await d.get("/api/auth/me")).status).toBe(401);
    expect((await d.post("/api/auth/mfa/verify", { code: "000000" })).status).toBe(401);
    const c = code(secret, 1); // the next step: not yet used
    const ok = await d.post("/api/auth/mfa/verify", { code: c });
    expect(ok.status).toBe(200);
    expect((await d.get("/api/auth/me")).body.session).toMatchObject({ mfa_verified: true, auth_method: "password" });

    // the same code cannot be used again
    const e = new Browser();
    await e.post("/api/auth/login", { email: b.email, password: PASSWORD });
    expect((await e.post("/api/auth/mfa/verify", { code: c })).status).toBe(401);
    // a recovery code works, once
    expect((await e.post("/api/auth/mfa/verify", { recovery_code: recovery[0].toUpperCase() })).status).toBe(200);
    const f = new Browser();
    await f.post("/api/auth/login", { email: b.email, password: PASSWORD });
    expect((await f.post("/api/auth/mfa/verify", { recovery_code: recovery[0] })).status).toBe(401);
    expect((await b.get("/api/auth/mfa")).body.recovery_codes_left).toBe(9);
  });

  it("five wrong codes end the pending sign-in", async () => {
    const b = await signUp("lock");
    const { secret } = await enableMfa(b);
    const d = new Browser();
    await d.post("/api/auth/login", { email: b.email, password: PASSWORD });
    for (let i = 0; i < 5; i++) expect((await d.post("/api/auth/mfa/verify", { code: "123456" })).status).toBe(401);
    expect((await d.post("/api/auth/mfa/verify", { code: code(secret, 1) })).status).toBe(401);
  });
});

describe("organization requires two-step verification", () => {
  it("cannot be switched on by an owner without it; members without it are stopped until they step up", async () => {
    const owner = await signUp("owner");
    const orgId = await makeOrg(owner);
    expect((await owner.req("PATCH", `/api/orgs/${orgId}/security`, { require_mfa: true })).body.error.code).toBe("MFA_SETUP_FIRST");
    await enableMfa(owner);
    expect((await owner.req("PATCH", `/api/orgs/${orgId}/security`, { require_mfa: true })).status).toBe(200);

    const member = await signUp("member");
    expect((await owner.post(`/api/orgs/${orgId}/members`, { email: member.email, role: "viewer" })).status).toBe(201);
    const blocked = await member.get(`/api/orgs/${orgId}/agents`);
    expect(blocked.status).toBe(403);
    expect(blocked.body.error.code).toBe("MFA_REQUIRED");
    const { secret } = await enableMfa(member); // enabling verifies this session
    expect((await member.get(`/api/orgs/${orgId}/agents`)).status).toBe(200);
    expect((await member.post("/api/auth/mfa/disable", { password: PASSWORD, code: code(secret, 1) })).body.error.code).toBe("MFA_REQUIRED_BY_ORG");
    expect((await owner.get(`/api/orgs/${orgId}/security`)).body).toMatchObject({ require_mfa: true, members: 2, members_with_mfa: 2 });
  });
});

describe("roles", () => {
  it("approver decides approvals and handles alerts but cannot change agents; auditor reads the audit log only", async () => {
    const owner = await signUp("owner");
    const orgId = await makeOrg(owner);
    const approver = await signUp("approver");
    const auditor = await signUp("auditor");
    const viewer = await signUp("viewer");
    for (const [b, role] of [[approver, "approver"], [auditor, "auditor"], [viewer, "viewer"]] as const) {
      expect((await owner.post(`/api/orgs/${orgId}/members`, { email: b.email, role })).status).toBe(201);
    }
    const agent = { name: "a", environment: "development", integration_type: "typescript_sdk", enforcement_mode: "enforce" };
    expect((await approver.post(`/api/orgs/${orgId}/agents`, agent)).status).toBe(403);
    expect((await auditor.post(`/api/orgs/${orgId}/agents`, agent)).status).toBe(403);
    expect((await auditor.get(`/api/orgs/${orgId}/audit`)).status).toBe(200);
    expect((await approver.get(`/api/orgs/${orgId}/audit`)).status).toBe(403);
    expect((await viewer.get(`/api/orgs/${orgId}/audit`)).status).toBe(403);
    // approving: an unknown approval is 404 for approvers (allowed to try), 403 for auditors and viewers
    const fake = "00000000-0000-4000-8000-000000000000";
    expect((await approver.post(`/api/orgs/${orgId}/approvals/${fake}/approve`, {})).status).toBe(404);
    expect((await auditor.post(`/api/orgs/${orgId}/approvals/${fake}/approve`, {})).status).toBe(403);
    expect((await viewer.post(`/api/orgs/${orgId}/approvals/${fake}/approve`, {})).status).toBe(403);
    expect((await approver.post(`/api/orgs/${orgId}/alerts/${fake}/resolve`, {})).status).toBe(404);
    expect((await auditor.post(`/api/orgs/${orgId}/alerts/${fake}/resolve`, {})).status).toBe(403);
  });
});

describe("sessions", () => {
  it("lists where you are signed in, and signs other devices out", async () => {
    const a = await signUp("sess");
    const b = new Browser();
    await b.post("/api/auth/login", { email: a.email, password: PASSWORD });
    const list = (await a.get("/api/auth/sessions")).body.items;
    expect(list).toHaveLength(2);
    expect(list.filter((s: any) => s.current)).toHaveLength(1);
    const other = list.find((s: any) => !s.current);
    expect((await a.req("DELETE", `/api/auth/sessions/${other.id}`)).status).toBe(200);
    expect((await b.get("/api/auth/me")).status).toBe(401);
    await b.post("/api/auth/login", { email: a.email, password: PASSWORD });
    expect((await a.post("/api/auth/sessions/revoke-others")).body.revoked).toBe(1);
    expect((await b.get("/api/auth/me")).status).toBe(401);
    expect((await a.get("/api/auth/me")).status).toBe(200);
  });
});

async function sso(b: Browser, query: string) {
  const r = await b.get(`/api/auth/sso/start?${query}`);
  expect(r.status).toBe(302);
  return r.location!;
}
const back = (b: Browser, p: { code: string; state: string }) => b.get(`/api/auth/sso/callback?code=${encodeURIComponent(p.code)}&state=${encodeURIComponent(p.state)}`);

describe("Continue with Google", () => {
  it("creates an account on first sign-in, finds it again by subject, and links a verified email to an existing account", async () => {
    expect((await new Browser().get("/api/auth/sso/providers")).body).toEqual({ google: true, kenuxa: true, organization_sso: true });
    const sub = uniq("g");
    const email = `${uniq("guser")}@gmail.test`;
    const b = new Browser();
    const done = await back(b, google.authorize(await sso(b, "provider=google&return_to=/agents"), { sub, email, email_verified: true, name: "Ama" }));
    expect(done.status).toBe(302);
    expect(done.location).toBe("http://localhost:5173/agents");
    const me = (await b.get("/api/auth/me")).body;
    expect(me.user).toMatchObject({ email, name: "Ama" });
    expect(me.session).toMatchObject({ auth_method: "google", mfa_verified: false });
    const [u] = await db.query<any>("SELECT password_hash FROM users WHERE email = $1", [email]);
    expect(u.password_hash).toBeNull();

    const again = new Browser();
    await back(again, google.authorize(await sso(again, "provider=google"), { sub, email, email_verified: true }));
    expect((await again.get("/api/auth/me")).body.user.id).toBe(me.user.id);

    // an existing password account with the same verified email is linked, not duplicated
    const pw = await signUp("linked");
    const c = new Browser();
    await back(c, google.authorize(await sso(c, "provider=google"), { sub: uniq("g"), email: pw.email, email_verified: true }));
    const meC = (await c.get("/api/auth/me")).body;
    expect(meC.user.email).toBe(pw.email);
    expect((await db.query<any>("SELECT count(*)::int AS n FROM users WHERE email = $1", [pw.email]))[0].n).toBe(1);
  });

  it("refuses unverified emails, a wrong nonce, a forged signature, a wrong audience, and a replayed state", async () => {
    const b = new Browser();
    const bad = (r: { status: number; location: string | null }, codeName: string) => {
      expect(r.status).toBe(302);
      expect(r.location).toContain(`sso_error=${codeName}`);
    };
    bad(await back(b, google.authorize(await sso(b, "provider=google"), { sub: "x1", email: "x1@gmail.test", email_verified: false })), "SSO_EMAIL_UNVERIFIED");
    bad(await back(b, google.authorize(await sso(b, "provider=google"), { sub: "x2", email: "x2@gmail.test", email_verified: true }, (c) => ({ ...c, nonce: "other" }))), "SSO_FAILED");
    bad(await back(b, google.authorize(await sso(b, "provider=google"), { sub: "x3", email: "x3@gmail.test", email_verified: true }, (c) => ({ ...c, aud: "someone-else" }))), "SSO_FAILED");
    bad(await back(b, google.authorize(await sso(b, "provider=google"), { sub: "x4", email: "x4@gmail.test", email_verified: true }, (c) => ({ ...c, exp: 1000 }))), "SSO_FAILED");
    // forged: signed with another key under the same key id
    const p = google.authorize(await sso(b, "provider=google"), { sub: "x5", email: "x5@gmail.test", email_verified: true });
    const entry = google.codes.get(p.code)!;
    const attacker = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const orig = google.jwt.bind(google);
    google.jwt = (claims) => orig(claims, attacker.privateKey);
    try {
      bad(await back(b, p), "SSO_FAILED");
    } finally {
      google.jwt = orig;
    }
    expect(entry).toBeTruthy();
    // replay: the same state twice
    const q = google.authorize(await sso(b, "provider=google"), { sub: "x6", email: "x6@gmail.test", email_verified: true });
    expect((await back(b, q)).location).toBe("http://localhost:5173/");
    bad(await back(new Browser(), q), "SSO_STATE");
    expect(await db.query("SELECT 1 FROM users WHERE email LIKE 'x_@gmail.test' AND email <> 'x6@gmail.test'")).toHaveLength(0);
  });

  it("an account with an authenticator still needs its code after Google, unless Google reports MFA", async () => {
    const pw = await signUp("both");
    const { secret } = await enableMfa(pw);
    const sub = uniq("g");
    const b = new Browser();
    const r = await back(b, google.authorize(await sso(b, "provider=google"), { sub, email: pw.email, email_verified: true }));
    expect(r.location).toContain("/login?mfa=1");
    expect((await b.get("/api/auth/me")).status).toBe(401);
    expect((await b.post("/api/auth/mfa/verify", { code: code(secret, 1) })).status).toBe(200);
    const c = new Browser();
    await back(c, google.authorize(await sso(c, "provider=google"), { sub, email: pw.email, email_verified: true, amr: ["pwd", "mfa"] }));
    expect((await c.get("/api/auth/me")).body.session).toMatchObject({ auth_method: "google", mfa_verified: true });
  });
});

describe("Continue with Kenuxa Account", () => {
  it("swaps the code at Kenuxa Accounts with the PKCE secret, confirms the account, and keeps no Kenuxa session", async () => {
    const id = crypto.randomUUID();
    const email = `${uniq("kx")}@kenuxa.test`;
    const b = new Browser();
    const start = await sso(b, "provider=kenuxa&return_to=/approvals");
    const r = await back(b, kenuxa.authorize(start, { id, email, email_confirmed_at: new Date().toISOString(), user_metadata: { full_name: "Kofi Mensah" } }));
    expect(r.location).toBe("http://localhost:5173/approvals");
    expect((await b.get("/api/auth/me")).body).toMatchObject({ user: { email, name: "Kofi Mensah" }, session: { auth_method: "kenuxa" } });
    await new Promise((res) => setTimeout(res, 10));
    expect(kenuxa.logouts).toBeGreaterThanOrEqual(1);
    const [link] = await db.query<any>("SELECT provider, subject FROM user_identities WHERE email = $1", [email]);
    expect(link).toEqual({ provider: "kenuxa", subject: id });
  });

  it("refuses an unconfirmed Kenuxa account and a code presented with the wrong PKCE secret", async () => {
    const b = new Browser();
    const r = await back(b, kenuxa.authorize(await sso(b, "provider=kenuxa"), { id: crypto.randomUUID(), email: `${uniq("kx")}@kenuxa.test`, email_confirmed_at: null }));
    expect(r.location).toContain("sso_error=SSO_EMAIL_UNVERIFIED");
    // a code stolen from another sign-in cannot be redeemed with this browser's verifier
    const victim = kenuxa.authorize(await sso(new Browser(), "provider=kenuxa"), { id: crypto.randomUUID(), email: `${uniq("kx")}@kenuxa.test`, email_confirmed_at: new Date().toISOString() });
    const mine = kenuxa.authorize(await sso(b, "provider=kenuxa"), { id: crypto.randomUUID(), email: "me@kenuxa.test", email_confirmed_at: new Date().toISOString() });
    const r2 = await back(b, { code: victim.code, state: mine.state });
    expect(r2.location).toContain("sso_error=SSO_FAILED");
  });
});

describe("organization single sign-on", () => {
  async function setupAcme() {
    const owner = await signUp("acmeowner");
    const orgId = await makeOrg(owner);
    const dom = `${uniq("acme")}.test`;
    const cfg = { issuer: acme.issuer, client_id: acme.clientId, client_secret: acme.clientSecret, allowed_domains: [dom], default_role: "approver" };
    expect((await owner.req("PUT", `/api/orgs/${orgId}/sso`, cfg)).body.error.code).toBe("DOMAIN_NOT_VERIFIED");
    const added = await owner.post(`/api/orgs/${orgId}/domains`, { domain: dom });
    expect(added.status).toBe(201);
    expect((await owner.post(`/api/orgs/${orgId}/domains/${dom}/verify`)).body.error.code).toBe("DOMAIN_NOT_VERIFIED");
    dns.set(added.body.dns.name, [[added.body.dns.value]]);
    expect((await owner.post(`/api/orgs/${orgId}/domains/${dom}/verify`)).status).toBe(200);
    expect((await owner.req("PUT", `/api/orgs/${orgId}/sso`, cfg)).status).toBe(200);
    return { owner, orgId, dom };
  }

  it("needs a DNS-verified domain; signs people in by email domain and adds them with the default role", async () => {
    const { orgId, dom } = await setupAcme();
    const b = new Browser();
    const start = await sso(b, `provider=oidc&email=ada@${dom}`);
    expect(new URL(start).searchParams.get("login_hint")).toBe(`ada@${dom}`);
    await back(b, acme.authorize(start, { sub: "ada-1", email: `ada@${dom}` }));
    const me = (await b.get("/api/auth/me")).body;
    expect(me.session).toMatchObject({ auth_method: "oidc", sso_org_id: orgId });
    expect(me.orgs).toEqual([expect.objectContaining({ id: orgId, role: "approver" })]);
  });

  it("another organization cannot claim a verified domain, and a provider cannot sign in outside its domains", async () => {
    const { dom } = await setupAcme();
    const other = await signUp("other");
    const otherOrg = await makeOrg(other);
    const r = await other.post(`/api/orgs/${otherOrg}/domains`, { domain: dom });
    expect(r.body.error.code).toBe("DOMAIN_IN_USE");
    const b = new Browser();
    const bad = await back(b, acme.authorize(await sso(b, `provider=oidc&email=x@${dom}`), { sub: "evil", email: "victim@gmail.test" }));
    expect(bad.location).toContain("sso_error=SSO_DOMAIN");
  });

  it("when SSO is required, password sessions of members are refused; owners keep break-glass access", async () => {
    const { owner, orgId, dom } = await setupAcme();
    const pwMember = await signUp("pw");
    await owner.post(`/api/orgs/${orgId}/members`, { email: pwMember.email, role: "viewer" });
    expect((await owner.req("PATCH", `/api/orgs/${orgId}/security`, { sso_enforced: true })).status).toBe(200);
    const refused = await pwMember.get(`/api/orgs/${orgId}/agents`);
    expect(refused.status).toBe(403);
    expect(refused.body.error.code).toBe("SSO_REQUIRED");
    expect((await owner.get(`/api/orgs/${orgId}/agents`)).status).toBe(200);
    const s = new Browser();
    await back(s, acme.authorize(await sso(s, `provider=oidc&org=${orgId}`), { sub: "bo-1", email: `bo@${dom}` }));
    expect((await s.get(`/api/orgs/${orgId}/agents`)).status).toBe(200);
  });
});
