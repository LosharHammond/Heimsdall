/**
 * Enterprise sign-in: sessions, two-step verification (authenticator app + recovery codes), single sign-on with Google,
 * Kenuxa Accounts and per-organization OIDC, and organization security settings. See docs/ENTERPRISE-AUTH.md.
 */
import { z } from "zod";
import type { Queryable } from "../db.js";
import { HttpError, badRequest, conflict, notFound, unauthorized } from "../errors.js";
import { discover, exchangeCode, pkceChallenge, randomToken, verifyIdToken, type IdTokenClaims } from "../oidc.js";
import { open, seal } from "../secret-box.js";
import { newSessionToken, sha256, verifyPassword } from "../security.js";
import { currentSession } from "../session-context.js";
import { newRecoveryCodes, newTotpSecret, normalizeRecoveryCode, otpauthUri, verifyTotp } from "../totp.js";
import { requireRole } from "./admin.js";
import { audit, type Ctx, type Role } from "./core.js";

export type AuthMethod = "password" | "google" | "kenuxa" | "oidc";
const PENDING_MINUTES = 10;
const MAX_MFA_ATTEMPTS = 5;
const GOOGLE_ISSUER = "https://accounts.google.com";

const fx = (ctx: Ctx) => ctx.fetch ?? fetch;
export const ssoRedirectUri = (ctx: Ctx) => `${ctx.config.APP_URL.replace(/\/$/, "")}/api/auth/sso/callback`;
/** Only same-site paths may be used as "where to go after signing in". */
export const safeReturnPath = (p: unknown) => (typeof p === "string" && /^\/(?![/\\])[\x21-\x7e]{0,300}$/.test(p) ? p : "/");

// ---------------------------------------------------------------- sessions

export interface SessionRow {
  id: string;
  user_id: string;
  email: string;
  name: string;
  auth_method: AuthMethod;
  sso_org_id: string | null;
  mfa_verified: boolean;
}

export async function createSession(
  ctx: Ctx,
  q: Queryable,
  userId: string,
  o: { method: AuthMethod; ssoOrgId?: string | null; mfaVerified: boolean; stage?: "active" | "mfa_pending"; ip?: string; userAgent?: string },
): Promise<string> {
  const token = newSessionToken();
  const hours = o.stage === "mfa_pending" ? null : ctx.config.SESSION_TTL_HOURS;
  await q.query(
    `INSERT INTO sessions (user_id, token_hash, expires_at, stage, auth_method, sso_org_id, mfa_verified, ip, user_agent, last_seen_at)
     VALUES ($1, $2, CASE WHEN $3::int IS NULL THEN now() + make_interval(mins => $4::int) ELSE now() + make_interval(hours => $3::int) END,
             $5, $6, $7, $8, $9, $10, now())`,
    [userId, sha256(token), hours, PENDING_MINUTES, o.stage ?? "active", o.method, o.ssoOrgId ?? null, o.mfaVerified, o.ip?.slice(0, 64) ?? null, o.userAgent?.slice(0, 300) ?? null],
  );
  return token;
}

export async function sessionForToken(ctx: Ctx, token: string): Promise<SessionRow | null> {
  const [s] = await ctx.db.query<SessionRow>(
    `UPDATE sessions s SET last_seen_at = now()
       FROM users u
      WHERE u.id = s.user_id AND s.token_hash = $1 AND s.stage = 'active' AND s.revoked_at IS NULL AND s.expires_at > now()
      RETURNING s.id, s.user_id, u.email, u.name, s.auth_method, s.sso_org_id, s.mfa_verified`,
    [sha256(token)],
  );
  return s ?? null;
}

export async function listSessions(ctx: Ctx, userId: string, currentId: string) {
  const rows = await ctx.db.query<any>(
    `SELECT id, auth_method, mfa_verified, ip, user_agent, created_at, last_seen_at, expires_at FROM sessions
      WHERE user_id = $1 AND stage = 'active' AND revoked_at IS NULL AND expires_at > now() ORDER BY last_seen_at DESC NULLS LAST`,
    [userId],
  );
  return rows.map((r) => ({ ...r, current: r.id === currentId }));
}

export async function revokeSession(ctx: Ctx, userId: string, sessionId: string) {
  if (!/^[0-9a-f-]{36}$/i.test(sessionId)) throw notFound("Session");
  const r = await ctx.db.query<{ id: string }>("UPDATE sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL RETURNING id", [sessionId, userId]);
  if (!r.length) throw notFound("Session");
  await audit(ctx.db, { orgId: null, actorType: "user", actorId: userId, action: "session.revoked", targetType: "session", targetId: sessionId });
}

export async function revokeOtherSessions(ctx: Ctx, userId: string, keepId: string) {
  const r = await ctx.db.query<{ id: string }>("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL RETURNING id", [userId, keepId]);
  await audit(ctx.db, { orgId: null, actorType: "user", actorId: userId, action: "session.revoked_others", metadata: { count: r.length } });
  return { revoked: r.length };
}

// ---------------------------------------------------------------- sign-in completion (password and SSO)

async function mfaEnabled(q: Queryable, userId: string) {
  const [m] = await q.query<{ enabled: boolean }>("SELECT enabled_at IS NOT NULL AS enabled FROM user_mfa WHERE user_id = $1", [userId]);
  return !!m?.enabled;
}

export type SignInResult =
  | { kind: "session"; token: string; user: { id: string; email: string; name: string } }
  | { kind: "mfa_required"; pendingToken: string; user: { id: string; email: string; name: string } };

/**
 * After the first factor (password or identity provider): a full session, or, when the person has an authenticator app and the
 * provider did not already report a second factor, a short-lived pending session that only /api/auth/mfa/verify accepts.
 */
export async function completeSignIn(
  ctx: Ctx,
  user: { id: string; email: string; name: string },
  o: { method: AuthMethod; ssoOrgId?: string | null; providerMfa?: boolean; ip?: string; userAgent?: string },
): Promise<SignInResult> {
  if (!o.providerMfa && (await mfaEnabled(ctx.db, user.id))) {
    const pendingToken = await createSession(ctx, ctx.db, user.id, { ...o, mfaVerified: false, stage: "mfa_pending" });
    return { kind: "mfa_required", pendingToken, user };
  }
  const token = await createSession(ctx, ctx.db, user.id, { ...o, mfaVerified: !!o.providerMfa });
  await audit(ctx.db, { orgId: null, actorType: "user", actorId: user.id, action: "user.login", metadata: { method: o.method, mfa: !!o.providerMfa } });
  return { kind: "session", token, user };
}

export async function passwordSignIn(ctx: Ctx, email: string, password: string, ip: string, userAgent?: string): Promise<SignInResult> {
  const [u] = await ctx.db.query<any>("SELECT id, email, name, password_hash FROM users WHERE email = $1", [email.toLowerCase()]);
  const ok = await verifyPassword(password, u?.password_hash ?? null);
  if (!ok || !u) {
    await audit(ctx.db, { orgId: null, actorType: "system", action: "user.login_failed", metadata: { ip } });
    throw unauthorized("Incorrect email or password");
  }
  return completeSignIn(ctx, { id: u.id, email: u.email, name: u.name }, { method: "password", ip, userAgent });
}

// ---------------------------------------------------------------- two-step verification

export const mfaCodeSchema = z.union([
  z.object({ code: z.string().trim().regex(/^\d{6}$/, "Enter the 6-digit code from your authenticator app") }).strict(),
  z.object({ recovery_code: z.string().trim().min(12).max(20) }).strict(),
]);
type MfaCode = z.infer<typeof mfaCodeSchema>;

/** Checks an authenticator code (once per 30-second step) or consumes a recovery code. Locks the row while it decides. */
async function checkSecondFactor(ctx: Ctx, q: Queryable, userId: string, input: MfaCode): Promise<"totp" | "recovery" | null> {
  const [m] = await q.query<{ secret_enc: string; last_used_step: string; enabled_at: Date | null }>("SELECT secret_enc, last_used_step, enabled_at FROM user_mfa WHERE user_id = $1 FOR UPDATE", [userId]);
  if (!m?.enabled_at) return null;
  if ("code" in input) {
    const step = verifyTotp(open(ctx.config, m.secret_enc), input.code, Number(m.last_used_step));
    if (step === null) return null;
    await q.query("UPDATE user_mfa SET last_used_step = $2 WHERE user_id = $1", [userId, step]);
    return "totp";
  }
  const used = await q.query<{ id: string }>(
    "UPDATE mfa_recovery_codes SET used_at = now() WHERE id = (SELECT id FROM mfa_recovery_codes WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL LIMIT 1) RETURNING id",
    [userId, sha256(normalizeRecoveryCode(input.recovery_code))],
  );
  return used.length ? "recovery" : null;
}

/** Second step of sign-in: turns a pending session into a full one. Five wrong codes end the pending session. */
export async function verifyPendingMfa(ctx: Ctx, pendingToken: string, input: MfaCode) {
  const out = await ctx.db.tx(async (q) => {
    const [p] = await q.query<any>(
      `SELECT s.id, s.user_id, s.auth_method, s.sso_org_id, s.ip, s.user_agent, s.mfa_attempts, u.email, u.name FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = $1 AND s.stage = 'mfa_pending' AND s.revoked_at IS NULL AND s.expires_at > now() FOR UPDATE OF s`,
      [sha256(pendingToken)],
    );
    if (!p) throw unauthorized("Your sign-in expired. Please sign in again.");
    const how = await checkSecondFactor(ctx, q, p.user_id, input);
    if (!how) {
      // Returned, not thrown: the failed attempt must be counted even though nothing else here is committed.
      const n = p.mfa_attempts + 1;
      await q.query(`UPDATE sessions SET mfa_attempts = $2${n >= MAX_MFA_ATTEMPTS ? ", revoked_at = now()" : ""} WHERE id = $1`, [p.id, n]);
      await audit(q, { orgId: null, actorType: "user", actorId: p.user_id, action: "user.mfa_failed", metadata: { attempt: n } });
      return { failed: n };
    }
    await q.query("UPDATE sessions SET revoked_at = now() WHERE id = $1", [p.id]); // the pending token never becomes the session token
    const token = await createSession(ctx, q, p.user_id, { method: p.auth_method, ssoOrgId: p.sso_org_id, mfaVerified: true, ip: p.ip, userAgent: p.user_agent });
    await audit(q, { orgId: null, actorType: "user", actorId: p.user_id, action: "user.login", metadata: { method: p.auth_method, mfa: how } });
    return { token, user: { id: p.user_id as string, email: p.email as string, name: p.name as string }, used: how };
  });
  if ("failed" in out) {
    throw new HttpError(401, "MFA_INVALID", out.failed >= MAX_MFA_ATTEMPTS ? "Too many wrong codes. Please sign in again." : "That code is not right. Try the current code from your app.");
  }
  return out;
}

/** Step-up for a signed-in session that has not passed a second factor (an organization now requires it). */
export async function stepUpMfa(ctx: Ctx, userId: string, sessionId: string, input: MfaCode) {
  await ctx.db.tx(async (q) => {
    const how = await checkSecondFactor(ctx, q, userId, input);
    if (!how) throw new HttpError(401, "MFA_INVALID", "That code is not right. Try the current code from your app.");
    await q.query("UPDATE sessions SET mfa_verified = true WHERE id = $1 AND user_id = $2", [sessionId, userId]);
    await audit(q, { orgId: null, actorType: "user", actorId: userId, action: "user.mfa_step_up", metadata: { via: how } });
  });
  return { ok: true };
}

export async function mfaStatus(ctx: Ctx, userId: string) {
  const [m] = await ctx.db.query<any>("SELECT enabled_at FROM user_mfa WHERE user_id = $1", [userId]);
  const [r] = await ctx.db.query<{ n: number }>("SELECT count(*)::int AS n FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL", [userId]);
  const [u] = await ctx.db.query<{ has_password: boolean }>("SELECT password_hash IS NOT NULL AS has_password FROM users WHERE id = $1", [userId]);
  const s = currentSession();
  return { enabled: !!m?.enabled_at, enabled_at: m?.enabled_at ?? null, recovery_codes_left: m?.enabled_at ? r.n : 0, has_password: !!u?.has_password, this_session_verified: !!s?.mfaVerified };
}

/**
 * Re-authentication before changing the second factor: the password (or, for accounts made by single sign-on, a fresh sign-in
 * within the last 10 minutes), plus the current code once MFA is on.
 */
async function reauth(ctx: Ctx, q: Queryable, userId: string, password: string | undefined) {
  const [u] = await q.query<{ password_hash: string | null }>("SELECT password_hash FROM users WHERE id = $1", [userId]);
  if (u?.password_hash) {
    if (!password || !(await verifyPassword(password, u.password_hash))) throw new HttpError(401, "REAUTH_FAILED", "Your password is not right.");
    return;
  }
  const s = currentSession();
  const [fresh] = s ? await q.query<{ ok: boolean }>("SELECT created_at > now() - interval '10 minutes' AS ok FROM sessions WHERE id = $1", [s.sessionId]) : [];
  if (!fresh?.ok) throw new HttpError(401, "REAUTH_REQUIRED", "For your security, sign in again, then retry within 10 minutes.");
}

export const mfaSetupSchema = z.object({ password: z.string().max(200).optional() }).strict();

/** Starts enrollment: a new secret (not active until confirmed). Re-running it replaces an unconfirmed secret. */
export async function beginMfaSetup(ctx: Ctx, userId: string, email: string, input: z.infer<typeof mfaSetupSchema>) {
  return ctx.db.tx(async (q) => {
    await reauth(ctx, q, userId, input.password);
    if (await mfaEnabled(q, userId)) throw conflict("MFA_ALREADY_ON", "Two-step verification is already on. Turn it off first to move to a new device.");
    const secret = newTotpSecret();
    await q.query(
      "INSERT INTO user_mfa (user_id, secret_enc) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, enabled_at = NULL, last_used_step = 0, created_at = now()",
      [userId, seal(ctx.config, secret)],
    );
    return { secret, otpauth_uri: otpauthUri(secret, email) };
  });
}

/** Confirms enrollment with a first code, turns MFA on, marks this session verified and returns ten recovery codes (shown once). */
export async function confirmMfaSetup(ctx: Ctx, userId: string, sessionId: string, code: string) {
  return ctx.db.tx(async (q) => {
    const [m] = await q.query<{ secret_enc: string; enabled_at: Date | null }>("SELECT secret_enc, enabled_at FROM user_mfa WHERE user_id = $1 FOR UPDATE", [userId]);
    if (!m) throw badRequest("MFA_NOT_STARTED", "Start setup first.");
    if (m.enabled_at) throw conflict("MFA_ALREADY_ON", "Two-step verification is already on.");
    const step = verifyTotp(open(ctx.config, m.secret_enc), code, 0);
    if (step === null) throw new HttpError(401, "MFA_INVALID", "That code is not right. Check the time on your phone and try the current code.");
    await q.query("UPDATE user_mfa SET enabled_at = now(), last_used_step = $2 WHERE user_id = $1", [userId, step]);
    const codes = await replaceRecoveryCodes(q, userId);
    await q.query("UPDATE sessions SET mfa_verified = true WHERE id = $1", [sessionId]);
    await audit(q, { orgId: null, actorType: "user", actorId: userId, action: "user.mfa_enabled" });
    return { recovery_codes: codes };
  });
}

async function replaceRecoveryCodes(q: Queryable, userId: string) {
  const codes = newRecoveryCodes();
  await q.query("DELETE FROM mfa_recovery_codes WHERE user_id = $1", [userId]);
  for (const c of codes) await q.query("INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)", [userId, sha256(c)]);
  return codes;
}

export const mfaChangeSchema = z.object({ password: z.string().max(200).optional(), code: z.string().trim().regex(/^\d{6}$/) }).strict();

export async function regenerateRecoveryCodes(ctx: Ctx, userId: string, input: z.infer<typeof mfaChangeSchema>) {
  return ctx.db.tx(async (q) => {
    await reauth(ctx, q, userId, input.password);
    if (!(await checkSecondFactor(ctx, q, userId, { code: input.code }))) throw new HttpError(401, "MFA_INVALID", "That code is not right.");
    const codes = await replaceRecoveryCodes(q, userId);
    await audit(q, { orgId: null, actorType: "user", actorId: userId, action: "user.mfa_recovery_regenerated" });
    return { recovery_codes: codes };
  });
}

/** Turning MFA off is refused while the person belongs to an organization that requires it. */
export async function disableMfa(ctx: Ctx, userId: string, input: z.infer<typeof mfaChangeSchema>) {
  await ctx.db.tx(async (q) => {
    await reauth(ctx, q, userId, input.password);
    if (!(await checkSecondFactor(ctx, q, userId, { code: input.code }))) throw new HttpError(401, "MFA_INVALID", "That code is not right.");
    const req = await q.query<{ name: string }>("SELECT o.name FROM memberships m JOIN organizations o ON o.id = m.org_id WHERE m.user_id = $1 AND o.require_mfa", [userId]);
    if (req.length) throw conflict("MFA_REQUIRED_BY_ORG", `${req.map((r) => r.name).join(", ")} requires two-step verification, so it cannot be turned off.`);
    await q.query("DELETE FROM user_mfa WHERE user_id = $1", [userId]);
    await q.query("DELETE FROM mfa_recovery_codes WHERE user_id = $1", [userId]);
    await audit(q, { orgId: null, actorType: "user", actorId: userId, action: "user.mfa_disabled" });
  });
  return { ok: true };
}

// ---------------------------------------------------------------- organization security settings

export const orgSecuritySchema = z.object({ require_mfa: z.boolean().optional(), sso_enforced: z.boolean().optional() }).strict();

export async function getOrgSecurity(ctx: Ctx, userId: string, orgId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const [o] = await ctx.db.query<any>("SELECT require_mfa, sso_enforced FROM organizations WHERE id = $1", [orgId]);
  const [sso] = await ctx.db.query<any>("SELECT issuer, client_id, allowed_domains, default_role, enabled, updated_at FROM org_sso_configs WHERE org_id = $1", [orgId]);
  const [cov] = await ctx.db.query<{ total: number; with_mfa: number }>(
    `SELECT count(*)::int AS total, count(um.enabled_at)::int AS with_mfa FROM memberships m LEFT JOIN user_mfa um ON um.user_id = m.user_id WHERE m.org_id = $1`,
    [orgId],
  );
  return { ...o, sso: sso ?? null, members: cov.total, members_with_mfa: cov.with_mfa };
}

/** Owner only. Requiring MFA needs the owner's own session to be verified, so an owner cannot lock themselves out. */
export async function setOrgSecurity(ctx: Ctx, userId: string, orgId: string, input: z.infer<typeof orgSecuritySchema>) {
  await ctx.db.tx(async (q) => {
    const role = await requireRole(q, userId, orgId, "owner");
    if (input.require_mfa && !currentSession()?.mfaVerified) {
      throw conflict("MFA_SETUP_FIRST", "Turn on two-step verification for your own account (and use it for this session) before requiring it for everyone.");
    }
    if (input.sso_enforced) {
      const [c] = await q.query<{ enabled: boolean }>("SELECT enabled FROM org_sso_configs WHERE org_id = $1", [orgId]);
      if (!c?.enabled) throw conflict("SSO_NOT_CONFIGURED", "Set up and enable single sign-on before requiring it.");
    }
    const sets: string[] = [];
    const params: unknown[] = [orgId];
    for (const k of ["require_mfa", "sso_enforced"] as const) {
      if (input[k] !== undefined) {
        params.push(input[k]);
        sets.push(`${k} = $${params.length}`);
      }
    }
    if (sets.length) await q.query(`UPDATE organizations SET ${sets.join(", ")} WHERE id = $1`, params);
    await audit(q, { orgId, actorType: "user", actorId: userId, action: "org.security_changed", targetType: "organization", targetId: orgId, metadata: { ...input, by_role: role } });
  });
  return getOrgSecurity(ctx, userId, orgId);
}

// ---------------------------------------------------------------- organization SSO configuration

const domain = z.string().trim().toLowerCase().regex(/^([a-z0-9-]+\.)+[a-z]{2,}$/, "Use a domain like example.com");
export const orgSsoSchema = z
  .object({
    issuer: z.string().trim().url().refine((s) => s.startsWith("https://"), "The issuer must be an https:// address"),
    client_id: z.string().trim().min(1).max(300),
    client_secret: z.string().min(1).max(1000).optional(),
    allowed_domains: z.array(domain).min(1).max(20),
    default_role: z.enum(["viewer", "auditor", "approver", "admin"]).default("viewer"),
    enabled: z.boolean().default(true),
  })
  .strict();

/** Owner only. The issuer is checked by fetching its discovery document before anything is saved. */
export async function setOrgSso(ctx: Ctx, userId: string, orgId: string, input: z.infer<typeof orgSsoSchema>) {
  await requireRole(ctx.db, userId, orgId, "owner");
  const verified = new Set((await ctx.db.query<{ domain: string }>("SELECT domain FROM org_domains WHERE org_id = $1 AND verified_at IS NOT NULL", [orgId])).map((r) => r.domain));
  const unverified = input.allowed_domains.filter((d) => !verified.has(d));
  if (unverified.length) throw conflict("DOMAIN_NOT_VERIFIED", `Verify ${unverified.join(", ")} first (Settings, Domains): single sign-on can only use domains this organization has proved it owns.`);
  await discover(fx(ctx), input.issuer);
  await ctx.db.tx(async (q) => {
    const [cur] = await q.query<{ client_secret_enc: string }>("SELECT client_secret_enc FROM org_sso_configs WHERE org_id = $1 FOR UPDATE", [orgId]);
    if (!cur && !input.client_secret) throw badRequest("SECRET_REQUIRED", "Enter the client secret from your identity provider.");
    const secretEnc = input.client_secret ? seal(ctx.config, input.client_secret) : cur!.client_secret_enc;
    await q.query(
      `INSERT INTO org_sso_configs (org_id, issuer, client_id, client_secret_enc, allowed_domains, default_role, enabled)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (org_id) DO UPDATE SET issuer = EXCLUDED.issuer, client_id = EXCLUDED.client_id, client_secret_enc = EXCLUDED.client_secret_enc,
         allowed_domains = EXCLUDED.allowed_domains, default_role = EXCLUDED.default_role, enabled = EXCLUDED.enabled, updated_at = now()`,
      [orgId, input.issuer.replace(/\/$/, ""), input.client_id, secretEnc, input.allowed_domains, input.default_role, input.enabled],
    );
    if (!input.enabled) await q.query("UPDATE organizations SET sso_enforced = false WHERE id = $1", [orgId]);
    await audit(q, { orgId, actorType: "user", actorId: userId, action: "org.sso_configured", targetType: "organization", targetId: orgId, metadata: { issuer: input.issuer, domains: input.allowed_domains, default_role: input.default_role, enabled: input.enabled } });
  });
  return getOrgSecurity(ctx, userId, orgId);
}

export async function deleteOrgSso(ctx: Ctx, userId: string, orgId: string) {
  await ctx.db.tx(async (q) => {
    await requireRole(q, userId, orgId, "owner");
    await q.query("DELETE FROM org_sso_configs WHERE org_id = $1", [orgId]);
    await q.query("UPDATE organizations SET sso_enforced = false WHERE id = $1", [orgId]);
    await audit(q, { orgId, actorType: "user", actorId: userId, action: "org.sso_removed", targetType: "organization", targetId: orgId });
  });
  return { ok: true };
}

// ---------------------------------------------------------------- single sign-on

export type Provider = "google" | "kenuxa" | "oidc";

export function availableProviders(ctx: Ctx) {
  return { google: !!ctx.config.GOOGLE_CLIENT_ID, kenuxa: !!ctx.config.KENUXA_ACCOUNTS_URL, organization_sso: true };
}

/** Starts a sign-in with an identity provider. Returns the provider URL to send the browser to. */
export async function startSso(ctx: Ctx, input: { provider: Provider; orgId?: string; email?: string; returnTo?: string }): Promise<string> {
  const state = randomToken(32);
  const nonce = randomToken(24);
  const verifier = randomToken(48);
  const redirectUri = ssoRedirectUri(ctx);
  let url: string;
  let orgId: string | null = null;

  if (input.provider === "google") {
    if (!ctx.config.GOOGLE_CLIENT_ID) throw notFound("Google sign-in");
    const d = await discover(fx(ctx), GOOGLE_ISSUER);
    url = `${d.authorization_endpoint}?${new URLSearchParams({
      client_id: ctx.config.GOOGLE_CLIENT_ID, redirect_uri: redirectUri, response_type: "code", scope: "openid email profile",
      state, nonce, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", prompt: "select_account",
    })}`;
  } else if (input.provider === "kenuxa") {
    if (!ctx.config.KENUXA_ACCOUNTS_URL) throw notFound("Kenuxa Accounts sign-in");
    url = `${ctx.config.KENUXA_ACCOUNTS_URL.replace(/\/$/, "")}/authorize?${new URLSearchParams({
      client_id: ctx.config.KENUXA_CLIENT_ID, redirect_uri: redirectUri, state, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256",
    })}`;
  } else {
    const cfg = await findOrgSso(ctx, input);
    orgId = cfg.org_id;
    const d = await discover(fx(ctx), cfg.issuer);
    const qs = new URLSearchParams({
      client_id: cfg.client_id, redirect_uri: redirectUri, response_type: "code", scope: "openid email profile",
      state, nonce, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256",
    });
    if (input.email) qs.set("login_hint", input.email);
    url = `${d.authorization_endpoint}?${qs}`;
  }
  await ctx.db.query("DELETE FROM sso_login_states WHERE expires_at < now()");
  await ctx.db.query(
    "INSERT INTO sso_login_states (state_hash, provider, org_id, nonce, code_verifier_enc, return_to, expires_at) VALUES ($1,$2,$3,$4,$5,$6, now() + interval '10 minutes')",
    [sha256(state), input.provider, orgId, nonce, seal(ctx.config, verifier), safeReturnPath(input.returnTo)],
  );
  return url;
}

async function findOrgSso(ctx: Ctx, input: { orgId?: string; email?: string }) {
  if (input.orgId) {
    if (!/^[0-9a-f-]{36}$/i.test(input.orgId)) throw notFound("Single sign-on for this organization");
    const [c] = await ctx.db.query<any>("SELECT * FROM org_sso_configs WHERE org_id = $1 AND enabled", [input.orgId]);
    if (!c) throw notFound("Single sign-on for this organization");
    return c;
  }
  const dom = input.email?.toLowerCase().split("@")[1];
  if (!dom) throw badRequest("EMAIL_REQUIRED", "Enter your work email to find your organization's sign-in.");
  const [c] = await ctx.db.query<any>("SELECT * FROM org_sso_configs WHERE enabled AND $1 = ANY(allowed_domains)", [dom]);
  if (!c) throw notFound("Single sign-on for this email domain");
  return c;
}

interface VerifiedIdentity {
  provider: string; // 'google' | 'kenuxa' | 'oidc:<org id>'
  subject: string;
  email: string;
  emailVerified: boolean;
  name: string;
  providerMfa: boolean;
}

const MFA_AMR = new Set(["mfa", "otp", "hwk", "swk", "fido", "sms", "totp"]);
const claimMfa = (c: IdTokenClaims) => Array.isArray(c.amr) && c.amr.some((a) => MFA_AMR.has(String(a).toLowerCase()));
const verifiedFlag = (v: unknown) => v === true || v === "true";

/** Completes a provider sign-in: checks state, exchanges the code, verifies the identity, links or creates the account. */
export async function finishSso(ctx: Ctx, params: { code?: string; state?: string; error?: string }, meta: { ip: string; userAgent?: string }): Promise<SignInResult & { returnTo: string }> {
  if (!params.state) throw new HttpError(400, "SSO_STATE", "This sign-in link is incomplete. Please start again.");
  const [st] = await ctx.db.query<any>("DELETE FROM sso_login_states WHERE state_hash = $1 RETURNING *, (expires_at < now()) AS expired", [sha256(params.state)]);
  if (!st || st.expired) throw new HttpError(400, "SSO_STATE", "This sign-in expired or was already used. Please start again.");
  if (params.error) throw new HttpError(401, "SSO_CANCELLED", "Sign-in was cancelled at the identity provider.");
  if (!params.code) throw new HttpError(400, "SSO_STATE", "The identity provider did not return a sign-in code.");
  const verifier = open(ctx.config, st.code_verifier_enc);
  const redirectUri = ssoRedirectUri(ctx);

  let id: VerifiedIdentity;
  let orgCfg: any = null;
  if (st.provider === "google") {
    const d = await discover(fx(ctx), GOOGLE_ISSUER);
    const t = await exchangeCode(fx(ctx), d.token_endpoint, { code: params.code, redirectUri, clientId: ctx.config.GOOGLE_CLIENT_ID!, clientSecret: ctx.config.GOOGLE_CLIENT_SECRET!, codeVerifier: verifier });
    const c = await verifyIdToken(fx(ctx), t.id_token, { issuer: GOOGLE_ISSUER, clientId: ctx.config.GOOGLE_CLIENT_ID!, nonce: st.nonce, jwksUri: d.jwks_uri });
    id = { provider: "google", subject: c.sub, email: String(c.email ?? "").toLowerCase(), emailVerified: verifiedFlag(c.email_verified), name: String(c.name ?? c.email ?? ""), providerMfa: claimMfa(c) };
  } else if (st.provider === "kenuxa") {
    id = await kenuxaIdentity(ctx, params.code, verifier, redirectUri);
  } else {
    [orgCfg] = await ctx.db.query<any>("SELECT * FROM org_sso_configs WHERE org_id = $1 AND enabled", [st.org_id]);
    if (!orgCfg) throw new HttpError(401, "SSO_FAILED", "Single sign-on is no longer enabled for this organization.");
    const d = await discover(fx(ctx), orgCfg.issuer);
    const t = await exchangeCode(fx(ctx), d.token_endpoint, { code: params.code, redirectUri, clientId: orgCfg.client_id, clientSecret: open(ctx.config, orgCfg.client_secret_enc), codeVerifier: verifier });
    const c = await verifyIdToken(fx(ctx), t.id_token, { issuer: orgCfg.issuer, clientId: orgCfg.client_id, nonce: st.nonce, jwksUri: d.jwks_uri });
    const email = String(c.email ?? c.preferred_username ?? "").toLowerCase();
    const dom = email.split("@")[1] ?? "";
    if (!orgCfg.allowed_domains.includes(dom)) throw new HttpError(403, "SSO_DOMAIN", `${dom || "This account"} is not an allowed email domain for this organization.`);
    // The organization proved it controls these domains (DNS), so its identity provider is authoritative for their addresses.
    const [ok] = await ctx.db.query("SELECT 1 FROM org_domains WHERE org_id = $1 AND domain = $2 AND verified_at IS NOT NULL", [orgCfg.org_id, dom]);
    if (!ok) throw new HttpError(403, "SSO_DOMAIN", `${dom} is no longer a verified domain of this organization.`);
    id = { provider: `oidc:${orgCfg.org_id}`, subject: c.sub, email, emailVerified: true, name: String(c.name ?? email), providerMfa: claimMfa(c) };
  }
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(id.email)) throw new HttpError(401, "SSO_FAILED", "The identity provider did not share an email address.");
  if (!id.emailVerified) throw new HttpError(401, "SSO_EMAIL_UNVERIFIED", "Verify your email address with your sign-in provider first.");

  const user = await linkOrCreateUser(ctx, id, orgCfg);
  const method: AuthMethod = st.provider === "oidc" ? "oidc" : st.provider;
  const res = await completeSignIn(ctx, user, { method, ssoOrgId: orgCfg?.org_id ?? null, providerMfa: id.providerMfa, ip: meta.ip, userAgent: meta.userAgent });
  return { ...res, returnTo: st.return_to };
}

/**
 * Kenuxa Accounts ("Sign in with Kenuxa"): swap the one-time code and PKCE verifier at the shared `accounts` edge function for a
 * single-use sign-in token, redeem it with Supabase Auth to learn the verified account, then end that Supabase session at once:
 * Heimdall keeps no Kenuxa session or refresh token.
 */
async function kenuxaIdentity(ctx: Ctx, code: string, verifier: string, redirectUri: string): Promise<VerifiedIdentity> {
  const c = ctx.config;
  const base = c.KENUXA_SUPABASE_URL!.replace(/\/$/, "");
  const headers = { "content-type": "application/json", apikey: c.KENUXA_SUPABASE_ANON_KEY!, authorization: `Bearer ${c.KENUXA_SUPABASE_ANON_KEY!}` };
  const post = async (url: string, body: unknown, h: Record<string, string> = headers) => {
    try {
      return await fx(ctx)(url, { method: "POST", headers: h, body: JSON.stringify(body), redirect: "error", signal: AbortSignal.timeout(8000) });
    } catch (e) {
      throw new HttpError(502, "SSO_PROVIDER_UNREACHABLE", `Could not reach Kenuxa Accounts (${(e as Error).message}).`);
    }
  };
  const tr = await post(`${base}/functions/v1/accounts/token`, { clientId: c.KENUXA_CLIENT_ID, redirectUri, code, codeVerifier: verifier });
  const tj = (await tr.json().catch(() => ({}))) as { tokenHash?: string; type?: string; message?: string };
  if (!tr.ok || !tj.tokenHash) throw new HttpError(401, "SSO_FAILED", tj.message || "Kenuxa Accounts refused the sign-in code.");
  const vr = await post(`${base}/auth/v1/verify`, { type: "magiclink", token_hash: tj.tokenHash });
  const vj = (await vr.json().catch(() => ({}))) as { access_token?: string; user?: { id?: string; email?: string; email_confirmed_at?: string | null; confirmed_at?: string | null; user_metadata?: Record<string, unknown> } };
  const u = vj.user;
  if (!vr.ok || !u?.id || !u.email) throw new HttpError(401, "SSO_FAILED", "Kenuxa Accounts could not confirm who you are. Please try again.");
  if (vj.access_token) {
    void post(`${base}/auth/v1/logout?scope=local`, {}, { ...headers, authorization: `Bearer ${vj.access_token}` }).catch(() => undefined);
  }
  const meta = u.user_metadata ?? {};
  return {
    provider: "kenuxa", subject: u.id, email: u.email.toLowerCase(), emailVerified: !!(u.email_confirmed_at || u.confirmed_at),
    name: String(meta.full_name ?? meta.name ?? meta.username ?? u.email), providerMfa: false,
  };
}

/**
 * Account linking:
 *  1. a known (provider, subject) signs in as its user;
 *  2. otherwise a verified email that matches an existing account links to it (recorded in the audit log);
 *  3. otherwise a new account without a password is created.
 * Organization SSO also adds the person to that organization with its default role the first time (just-in-time).
 */
async function linkOrCreateUser(ctx: Ctx, id: VerifiedIdentity, orgCfg: { org_id: string; default_role: Role } | null) {
  return ctx.db.tx(async (q) => {
    let [u] = await q.query<{ id: string; email: string; name: string }>(
      "SELECT u.id, u.email, u.name FROM user_identities i JOIN users u ON u.id = i.user_id WHERE i.provider = $1 AND i.subject = $2",
      [id.provider, id.subject],
    );
    if (u) {
      await q.query("UPDATE user_identities SET last_login_at = now(), email = $3 WHERE provider = $1 AND subject = $2", [id.provider, id.subject, id.email]);
    } else {
      [u] = await q.query<{ id: string; email: string; name: string }>("SELECT id, email, name FROM users WHERE email = $1", [id.email]);
      if (!u) {
        [u] = await q.query<{ id: string; email: string; name: string }>("INSERT INTO users (email, name, password_hash) VALUES ($1, $2, NULL) RETURNING id, email, name", [id.email, (id.name || id.email).slice(0, 120)]);
        await audit(q, { orgId: null, actorType: "user", actorId: u.id, action: "user.registered", metadata: { via: id.provider } });
      }
      await q.query("INSERT INTO user_identities (user_id, provider, subject, email, last_login_at) VALUES ($1,$2,$3,$4, now())", [u.id, id.provider, id.subject, id.email]);
      await audit(q, { orgId: orgCfg?.org_id ?? null, actorType: "user", actorId: u.id, action: "user.identity_linked", metadata: { provider: id.provider } });
    }
    if (orgCfg) {
      const added = await q.query("INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,$3) ON CONFLICT (org_id, user_id) DO NOTHING RETURNING user_id", [orgCfg.org_id, u.id, orgCfg.default_role]);
      if (added.length) await audit(q, { orgId: orgCfg.org_id, actorType: "system", action: "member.added_by_sso", targetType: "user", targetId: u.id, metadata: { role: orgCfg.default_role } });
    }
    return u;
  });
}

// ---------------------------------------------------------------- verified email domains

export const domainSchema = z.object({ domain }).strict();
const txtName = (d: string) => `_heimdall-verification.${d}`;
const txtValue = (token: string) => `heimdall-verification=${token}`;

export async function listDomains(ctx: Ctx, userId: string, orgId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const rows = await ctx.db.query<any>("SELECT domain, token, verified_at, created_at FROM org_domains WHERE org_id = $1 ORDER BY domain", [orgId]);
  return rows.map((r) => ({ domain: r.domain, verified_at: r.verified_at, created_at: r.created_at, dns: { type: "TXT", name: txtName(r.domain), value: txtValue(r.token) } }));
}

export async function addDomain(ctx: Ctx, userId: string, orgId: string, d: string) {
  await requireRole(ctx.db, userId, orgId, "owner");
  const [taken] = await ctx.db.query("SELECT 1 FROM org_domains WHERE domain = $1 AND verified_at IS NOT NULL AND org_id <> $2", [d, orgId]);
  if (taken) throw conflict("DOMAIN_IN_USE", "This domain is already verified by another organization.");
  await ctx.db.query("INSERT INTO org_domains (org_id, domain, token) VALUES ($1,$2,$3) ON CONFLICT (org_id, domain) DO NOTHING", [orgId, d, randomToken(18)]);
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "org.domain_added", metadata: { domain: d } });
  return (await listDomains(ctx, userId, orgId)).find((x) => x.domain === d);
}

/** Looks up the TXT record. Verification proves the organization controls the domain's DNS. */
export async function verifyDomain(ctx: Ctx, userId: string, orgId: string, d: string) {
  await requireRole(ctx.db, userId, orgId, "owner");
  const [row] = await ctx.db.query<{ token: string; verified_at: Date | null }>("SELECT token, verified_at FROM org_domains WHERE org_id = $1 AND domain = $2", [orgId, d]);
  if (!row) throw notFound("Domain");
  if (row.verified_at) return { verified: true };
  let records: string[][] = [];
  try {
    records = await (ctx.resolveTxt ?? (await import("node:dns/promises")).resolveTxt)(txtName(d));
  } catch {
    records = [];
  }
  const found = records.some((chunks) => chunks.join("") === txtValue(row.token));
  if (!found) throw new HttpError(409, "DOMAIN_NOT_VERIFIED", `No TXT record ${txtName(d)} with the expected value was found yet. DNS changes can take up to an hour.`);
  try {
    await ctx.db.query("UPDATE org_domains SET verified_at = now() WHERE org_id = $1 AND domain = $2", [orgId, d]);
  } catch (e) {
    if ((e as { code?: string }).code === "23505") throw conflict("DOMAIN_IN_USE", "This domain is already verified by another organization.");
    throw e;
  }
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "org.domain_verified", metadata: { domain: d } });
  return { verified: true };
}

export async function removeDomain(ctx: Ctx, userId: string, orgId: string, d: string) {
  await ctx.db.tx(async (q) => {
    await requireRole(q, userId, orgId, "owner");
    const [cfg] = await q.query<{ allowed_domains: string[] }>("SELECT allowed_domains FROM org_sso_configs WHERE org_id = $1", [orgId]);
    if (cfg?.allowed_domains.includes(d)) throw conflict("DOMAIN_IN_USE_BY_SSO", "Remove this domain from single sign-on first.");
    await q.query("DELETE FROM org_domains WHERE org_id = $1 AND domain = $2", [orgId, d]);
    await audit(q, { orgId, actorType: "user", actorId: userId, action: "org.domain_removed", metadata: { domain: d } });
  });
  return { ok: true };
}
