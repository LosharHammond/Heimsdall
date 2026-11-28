import { KENUXA_APPS, mergeKenuxaApps } from "../shared/kenuxa-apps.js";
import { createReadStream } from "node:fs";
import { timingSafeEqual } from "node:crypto";
import { Readable } from "node:stream";
import { existsSync, readFileSync } from "node:fs";
import { Hono, type Context, type Next } from "hono";
import { bodyLimit } from "hono/body-limit";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { serveStatic } from "@hono/node-server/serve-static";
import { getConnInfo } from "@hono/node-server/conninfo";
import { z } from "zod";
import { actionRequestSchema } from "../shared/action.js";
import { POLICY_EXAMPLES } from "../shared/policy.js";
import { HttpError, badRequest, forbidden, unauthorized } from "./errors.js";
import { log } from "./log.js";
import { RateLimiter } from "./ratelimit.js";
import { runMigrations } from "./migrate.js";
import * as admin from "./services/admin.js";
import * as auth from "./services/auth.js";
import * as notify from "./services/notify.js";
import * as exporter from "./services/export.js";
import * as setup from "./services/device-setup.js";
import * as discovery from "./services/discovery.js";
import * as browserGuard from "./services/browser-guard.js";
import { runWithSession, type SessionInfo } from "./session-context.js";
import * as authz from "./services/authz.js";
import * as queries from "./services/queries.js";
import * as devices from "./services/devices.js";
import * as offline from "./services/offline.js";
import { protection } from "./services/protection.js";
import type { Ctx } from "./services/core.js";

type Vars = { user: { id: string; email: string; name: string }; session: SessionInfo; sessionToken: string; cred: authz.CredentialAuth; reqId: string };
const COOKIE = "asg_session";
/** Holds the short-lived "password (or provider) accepted, second factor still needed" session. Only /api/auth/mfa/verify reads it. */
const MFA_COOKIE = "asg_mfa";

export interface AppOptions {
  /** Test hook: raise the per-IP limits so suites sharing one address are not throttled. */
  ipLimitsMultiplier?: number;
}

export function createApp(ctx: Ctx, opts: AppOptions = {}) {
  const m = opts.ipLimitsMultiplier ?? 1;
  const app = new Hono<{ Variables: Vars }>();
  const loginIp = new RateLimiter(30 * m, 15 * 60_000);
  const loginEmail = new RateLimiter(8, 15 * 60_000);
  const registerIp = new RateLimiter(10 * m, 60 * 60_000);
  const v1Ip = new RateLimiter(1200, 60_000);
  const v1Key = new RateLimiter(600, 60_000);
  const apiUser = new RateLimiter(600, 60_000);
  const secure = ctx.config.NODE_ENV === "production";
  const appOrigin = new URL(ctx.config.APP_URL).origin;

  const clientIp = (c: Context): string => {
    if (ctx.config.TRUST_PROXY === "1") {
      const xff = c.req.header("x-forwarded-for")?.split(",").map((s) => s.trim()).filter(Boolean);
      if (xff?.length) return xff[xff.length - 1];
    }
    try {
      return getConnInfo(c).remote.address ?? "unknown";
    } catch {
      return "unknown";
    }
  };

  // ---- cross-cutting middleware ----
  app.use("*", async (c, next) => {
    const reqId = crypto.randomUUID();
    c.set("reqId", reqId);
    const t0 = Date.now();
    await next();
    c.header("x-request-id", reqId);
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "DENY");
    c.header("Referrer-Policy", "no-referrer");
    c.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    c.header("Cross-Origin-Opener-Policy", "same-origin");
    c.header(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    );
    if (secure) c.header("Strict-Transport-Security", "max-age=15552000; includeSubDomains");
    const p = new URL(c.req.url).pathname;
    if (p.startsWith("/api/") || p.startsWith("/v1/")) c.header("Cache-Control", "no-store");
    if (p !== "/healthz") log("info", "request", { reqId, method: c.req.method, route: c.req.routePath, status: c.res.status, ms: Date.now() - t0 });
  });

  app.onError((err, c) => {
    if (err instanceof HttpError) {
      const body: Record<string, unknown> = { error: { code: err.code, message: err.message, details: err.details } };
      if (err.details && typeof err.details === "object" && "decision" in err.details) Object.assign(body, err.details);
      return c.json(body, err.status as 400);
    }
    const name = (err as Error).name;
    if (name === "SyntaxError") return c.json({ error: { code: "INVALID_JSON", message: "Request body is not valid JSON" } }, 400);
    log("error", "unhandled error", { reqId: c.get("reqId"), error: (err as Error).message, name });
    // Fail closed: integrations treat any non-2xx on /v1 as "not authorized".
    return c.json({ error: { code: "INTERNAL", message: "Something went wrong on our side. Nothing was executed." } }, 500);
  });
  app.notFound((c) => {
    const p = new URL(c.req.url).pathname;
    if (p.startsWith("/api/") || p.startsWith("/v1/")) return c.json({ error: { code: "NOT_FOUND", message: "Unknown endpoint" } }, 404);
    return c.text("Not found", 404);
  });

  const tooLarge = (c: Context) => c.json({ error: { code: "PAYLOAD_TOO_LARGE", message: "Request body is too large" } }, 413);
  // Background audit batches (fast path, offline sync) carry up to 500 records; every other /v1 call stays at 64 KiB.
  const v1Limit = bodyLimit({ maxSize: 64 * 1024, onError: tooLarge });
  const syncLimit = bodyLimit({ maxSize: 4 * 1024 * 1024, onError: tooLarge });
  app.use("/v1/*", (c, next) => (new URL(c.req.url).pathname === "/v1/offline-sync" ? syncLimit(c, next) : v1Limit(c, next)));
  app.use("/api/*", bodyLimit({ maxSize: 256 * 1024, onError: tooLarge }));

  // ---- health ----
  app.get("/healthz", (c) => c.json({ status: "ok" }));
  app.get("/readyz", async (c) => {
    try {
      const r = await Promise.race([
        ctx.db.query<{ n: number }>("SELECT count(*)::int AS n FROM schema_migrations"),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error("database timeout")), 2500)),
      ]);
      return c.json({ status: "ready", database: ctx.db.kind, migrations: r[0].n });
    } catch (e) {
      log("warn", "readiness failed", { error: (e as Error).message });
      return c.json({ status: "unavailable", database: "unreachable" }, 503);
    }
  });

  // ---- scheduled jobs (Vercel Cron / GitHub Actions). Off unless CRON_SECRET is set. ----
  const cron = async (c: Context) => {
    const secret = ctx.config.CRON_SECRET;
    const given = (c.req.header("authorization") ?? "").replace(/^Bearer\s+/i, "");
    if (!secret || !safeEqual(given, secret)) return c.json({ error: { code: "UNAUTHORIZED", message: "Missing or wrong cron secret" } }, 401);
    const { tick } = await import("./jobs.js");
    return c.json({ ok: true, ran: await tick(ctx, { retentionMinutes: ctx.config.RETENTION_INTERVAL_MINUTES || 1440 }) });
  };
  app.get("/api/cron/tick", cron);
  app.post("/api/cron/tick", cron);

  // ---- session auth + CSRF for /api ----
  const csrf = async (c: Context, next: Next) => {
    if (!["GET", "HEAD", "OPTIONS"].includes(c.req.method)) {
      const origin = c.req.header("origin");
      const own = new URL(c.req.url).origin;
      if (c.req.header("x-asg-csrf") !== "1" || (origin && origin !== appOrigin && origin !== own)) {
        throw forbidden("Cross-site request blocked");
      }
    }
    await next();
  };
  app.use("/api/*", csrf);

  const needUser = async (c: Context<{ Variables: Vars }>, next: Next) => {
    const token = getCookie(c, COOKIE);
    const s = token ? await auth.sessionForToken(ctx, token) : null;
    if (!s || !token) throw unauthorized();
    const user = { id: s.user_id, email: s.email, name: s.name };
    const info: SessionInfo = { sessionId: s.id, userId: s.user_id, authMethod: s.auth_method, mfaVerified: s.mfa_verified, ssoOrgId: s.sso_org_id };
    c.set("user", user);
    c.set("session", info);
    c.set("sessionToken", token);
    const rl = apiUser.check(user.id);
    if (!rl.ok) {
      c.header("Retry-After", String(rl.retryAfterSec));
      throw new HttpError(429, "RATE_LIMITED", "Too many requests. Please slow down.");
    }
    // Every service call below sees how this session signed in (organization MFA / SSO rules are enforced in requireRole).
    await runWithSession(info, () => next());
  };
  const setSession = (c: Context, token: string) => setCookie(c, COOKIE, token, { httpOnly: true, secure, sameSite: "Lax", path: "/", maxAge: ctx.config.SESSION_TTL_HOURS * 3600 });
  const setPending = (c: Context, token: string) => setCookie(c, MFA_COOKIE, token, { httpOnly: true, secure, sameSite: "Lax", path: "/api/auth", maxAge: 10 * 60 });
  const ssoStart = new RateLimiter(60 * m, 15 * 60_000);
  const mfaIp = new RateLimiter(30 * m, 15 * 60_000);

  const json = async <T extends z.ZodTypeAny>(c: Context, schema: T): Promise<z.infer<T>> => admin.parse(schema, await c.req.json().catch(() => { throw badRequest("INVALID_JSON", "Request body must be JSON"); }));
  const uid = (c: Context<{ Variables: Vars }>) => c.get("user").id;
  const q = (c: Context) => c.req.query() as Record<string, string | undefined>;

  // ---- auth ----
  app.post("/api/auth/register", async (c) => {
    const rl = registerIp.check(clientIp(c));
    if (!rl.ok) throw new HttpError(429, "RATE_LIMITED", "Too many sign-ups from this address. Try later.");
    const user = await admin.registerUser(ctx, await json(c, admin.registerSchema));
    return c.json({ user }, 201);
  });
  app.post("/api/auth/login", async (c) => {
    const body = await json(c, z.object({ email: z.string().max(254), password: z.string().max(200) }).strict());
    const ip = clientIp(c);
    const a = loginIp.check(ip);
    const b = loginEmail.check(body.email.toLowerCase());
    if (!a.ok || !b.ok) {
      c.header("Retry-After", String(Math.max(a.retryAfterSec, b.retryAfterSec)));
      throw new HttpError(429, "RATE_LIMITED", "Too many sign-in attempts. Try again later.");
    }
    const r = await auth.passwordSignIn(ctx, body.email, body.password, ip, c.req.header("user-agent"));
    if (r.kind === "mfa_required") {
      setPending(c, r.pendingToken);
      return c.json({ mfa_required: true, user: { name: r.user.name } });
    }
    setSession(c, r.token);
    return c.json({ user: r.user });
  });

  // ---- two-step verification ----
  app.post("/api/auth/mfa/verify", async (c) => {
    const a = mfaIp.check(clientIp(c));
    if (!a.ok) {
      c.header("Retry-After", String(a.retryAfterSec));
      throw new HttpError(429, "RATE_LIMITED", "Too many attempts. Try again later.");
    }
    const pending = getCookie(c, MFA_COOKIE);
    if (!pending) throw unauthorized("Your sign-in expired. Please sign in again.");
    const r = await auth.verifyPendingMfa(ctx, pending, await json(c, auth.mfaCodeSchema));
    deleteCookie(c, MFA_COOKIE, { path: "/api/auth" });
    setSession(c, r.token);
    return c.json({ user: r.user, used: r.used });
  });
  app.get("/api/auth/mfa", needUser, async (c) => c.json(await auth.mfaStatus(ctx, uid(c))));
  app.post("/api/auth/mfa/setup", needUser, async (c) => c.json(await auth.beginMfaSetup(ctx, uid(c), c.get("user").email, await json(c, auth.mfaSetupSchema))));
  app.post("/api/auth/mfa/enable", needUser, async (c) => {
    const body = await json(c, z.object({ code: z.string().trim().regex(/^\d{6}$/) }).strict());
    return c.json(await auth.confirmMfaSetup(ctx, uid(c), c.get("session").sessionId, body.code));
  });
  app.post("/api/auth/mfa/step-up", needUser, async (c) => {
    const a = mfaIp.check(clientIp(c));
    if (!a.ok) throw new HttpError(429, "RATE_LIMITED", "Too many attempts. Try again later.");
    return c.json(await auth.stepUpMfa(ctx, uid(c), c.get("session").sessionId, await json(c, auth.mfaCodeSchema)));
  });
  app.post("/api/auth/mfa/recovery-codes", needUser, async (c) => c.json(await auth.regenerateRecoveryCodes(ctx, uid(c), await json(c, auth.mfaChangeSchema))));
  app.post("/api/auth/mfa/disable", needUser, async (c) => c.json(await auth.disableMfa(ctx, uid(c), await json(c, auth.mfaChangeSchema))));

  // ---- sessions ----
  app.get("/api/auth/sessions", needUser, async (c) => c.json({ items: await auth.listSessions(ctx, uid(c), c.get("session").sessionId) }));
  app.delete("/api/auth/sessions/:sessionId", needUser, async (c) => {
    await auth.revokeSession(ctx, uid(c), c.req.param("sessionId") ?? "");
    return c.json({ ok: true });
  });
  app.post("/api/auth/sessions/revoke-others", needUser, async (c) => c.json(await auth.revokeOtherSessions(ctx, uid(c), c.get("session").sessionId)));

  // ---- single sign-on (Google, Kenuxa Accounts, organization OIDC) ----
  // Browser navigations, not API calls: errors come back to the sign-in page as ?sso_error=CODE.
  const appBase = ctx.config.APP_URL.replace(/\/$/, "");
  const toLogin = (c: Context, code: string) => c.redirect(`${appBase}/login?sso_error=${encodeURIComponent(code)}`, 302);
  app.get("/api/auth/sso/providers", (c) => c.json(auth.availableProviders(ctx)));
  // The Kenuxa app menu (nine dots): the same kenuxa_apps list Kenuxa Accounts and Bask show. Public and cached.
  app.get("/api/kenuxa/apps", async (c) => c.json(await kenuxaApps(ctx)));
  app.get("/api/auth/sso/start", async (c) => {
    const rl = ssoStart.check(clientIp(c));
    if (!rl.ok) return toLogin(c, "RATE_LIMITED");
    const p = c.req.query("provider");
    if (p !== "google" && p !== "kenuxa" && p !== "oidc") return toLogin(c, "SSO_PROVIDER");
    try {
      const url = await auth.startSso(ctx, { provider: p, orgId: c.req.query("org"), email: c.req.query("email")?.slice(0, 254), returnTo: c.req.query("return_to") });
      return c.redirect(url, 302);
    } catch (e) {
      return toLogin(c, e instanceof HttpError ? e.code : "SSO_FAILED");
    }
  });
  app.get("/api/auth/sso/callback", async (c) => {
    try {
      const r = await auth.finishSso(ctx, { code: c.req.query("code"), state: c.req.query("state"), error: c.req.query("error") }, { ip: clientIp(c), userAgent: c.req.header("user-agent") });
      if (r.kind === "mfa_required") {
        setPending(c, r.pendingToken);
        return c.redirect(`${appBase}/login?mfa=1&return_to=${encodeURIComponent(r.returnTo)}`, 302);
      }
      setSession(c, r.token);
      return c.redirect(`${appBase}${r.returnTo}`, 302);
    } catch (e) {
      if (!(e instanceof HttpError)) log("error", "sso callback failed", { error: (e as Error).message });
      return toLogin(c, e instanceof HttpError ? e.code : "SSO_FAILED");
    }
  });
  app.post("/api/auth/logout", async (c) => {
    const token = getCookie(c, COOKIE);
    if (token) await admin.logout(ctx, token);
    deleteCookie(c, MFA_COOKIE, { path: "/api/auth" });
    deleteCookie(c, COOKIE, { path: "/" });
    return c.json({ ok: true });
  });
  app.get("/api/auth/me", needUser, async (c) => {
    const s = c.get("session");
    return c.json({ user: c.get("user"), session: { auth_method: s.authMethod, mfa_verified: s.mfaVerified, sso_org_id: s.ssoOrgId }, orgs: await admin.myOrgs(ctx, uid(c)) });
  });

  app.get("/api/policy-examples", needUser, (c) => c.json({ items: POLICY_EXAMPLES }));

  // ---- organizations ----
  app.post("/api/orgs", needUser, async (c) => c.json(await admin.createOrg(ctx, uid(c), await json(c, admin.orgCreateSchema)), 201));
  const org = (path: string) => `/api/orgs/:orgId${path}`;
  const oid = (c: Context) => c.req.param("orgId") ?? "";
  const pid = (c: Context, name: string) => c.req.param(name) ?? "";

  app.get(org(""), needUser, async (c) => c.json(await admin.getOrg(ctx, uid(c), oid(c))));
  app.patch(org(""), needUser, async (c) => c.json(await admin.updateOrg(ctx, uid(c), oid(c), await json(c, admin.orgUpdateSchema))));
  app.get(org("/overview"), needUser, async (c) => c.json(await queries.overview(ctx, uid(c), oid(c), Number(q(c).hours) || 24)));

  app.get(org("/members"), needUser, async (c) => c.json({ items: await admin.listMembers(ctx, uid(c), oid(c)) }));
  app.post(org("/members"), needUser, async (c) => {
    await admin.addMember(ctx, uid(c), oid(c), await json(c, admin.memberAddSchema));
    return c.json({ ok: true }, 201);
  });
  app.patch(org("/members/:userId"), needUser, async (c) => {
    await admin.changeMemberRole(ctx, uid(c), oid(c), pid(c, "userId"), (await json(c, admin.memberRoleSchema)).role);
    return c.json({ ok: true });
  });
  app.delete(org("/members/:userId"), needUser, async (c) => {
    await admin.removeMember(ctx, uid(c), oid(c), pid(c, "userId"));
    return c.json({ ok: true });
  });

  // ---- organization security: required MFA, single sign-on, verified domains ----
  app.get(org("/security"), needUser, async (c) => c.json(await auth.getOrgSecurity(ctx, uid(c), oid(c))));
  app.patch(org("/security"), needUser, async (c) => c.json(await auth.setOrgSecurity(ctx, uid(c), oid(c), await json(c, auth.orgSecuritySchema))));
  app.put(org("/sso"), needUser, async (c) => c.json(await auth.setOrgSso(ctx, uid(c), oid(c), await json(c, auth.orgSsoSchema))));
  app.delete(org("/sso"), needUser, async (c) => c.json(await auth.deleteOrgSso(ctx, uid(c), oid(c))));
  app.get(org("/domains"), needUser, async (c) => c.json({ items: await auth.listDomains(ctx, uid(c), oid(c)) }));
  app.post(org("/domains"), needUser, async (c) => c.json(await auth.addDomain(ctx, uid(c), oid(c), (await json(c, auth.domainSchema)).domain), 201));
  app.post(org("/domains/:domain/verify"), needUser, async (c) => c.json(await auth.verifyDomain(ctx, uid(c), oid(c), (c.req.param("domain") ?? "").toLowerCase())));
  app.delete(org("/domains/:domain"), needUser, async (c) => c.json(await auth.removeDomain(ctx, uid(c), oid(c), (c.req.param("domain") ?? "").toLowerCase())));

  // ---- automatic device setup: this browser, and companion pairing ----
  const pairStartIp = new RateLimiter(10 * m, 15 * 60_000);
  const pairPollIp = new RateLimiter(600 * m, 15 * 60_000);
  app.get(org("/push-key"), needUser, async (c) => {
    await admin.requireRole(ctx.db, uid(c), oid(c), "viewer");
    return c.json({ vapid_public_key: (await setup.vapidKeys(ctx)).publicKey });
  });
  app.post(org("/browser-devices"), needUser, async (c) => c.json(await setup.addBrowserDevice(ctx, uid(c), oid(c), await json(c, setup.browserDeviceSchema)), 201));
  app.post(org("/browser-devices/:deviceId/push"), needUser, async (c) => c.json(await setup.setBrowserPush(ctx, uid(c), oid(c), pid(c, "deviceId"), await json(c, setup.pushSubscriptionSchema))));
  app.post(org("/browser-devices/:deviceId/heartbeat"), needUser, async (c) => c.json(await setup.browserHeartbeat(ctx, uid(c), oid(c), pid(c, "deviceId"))));
  app.post(org("/browser-devices/:deviceId/test"), needUser, async (c) => c.json(await setup.testBrowserPush(ctx, uid(c), oid(c), pid(c, "deviceId"))));
  app.get("/api/device-pairings/:code", needUser, async (c) => c.json(await setup.describePairing(ctx, uid(c), pid(c, "code"), clientIp(c))));
  app.post("/api/device-pairings/decide", needUser, async (c) => c.json(await setup.decidePairing(ctx, uid(c), await json(c, setup.pairDecisionSchema))));
  app.get(org("/discovered"), needUser, async (c) => c.json(await discovery.listDiscovered(ctx, uid(c), oid(c))));
  app.put(org("/auto-protect"), needUser, async (c) => c.json(await discovery.setAutoProtect(ctx, uid(c), oid(c), await json(c, discovery.autoProtectSchema))));
  app.get(org("/browser-guard"), needUser, async (c) => c.json(await browserGuard.status(ctx, uid(c), oid(c))));
  app.post(org("/browser-guard"), needUser, async (c) => c.json(await browserGuard.connect(ctx, uid(c), oid(c), await json(c, browserGuard.connectSchema)), 201));
  app.get(org("/installer"), needUser, async (c) => c.json(await setup.installerInfo(ctx, uid(c), oid(c))));
  app.post(org("/device-installs"), needUser, async (c) => c.json(await setup.createInstallToken(ctx, uid(c), oid(c)), 201));
  app.put(org("/device-settings"), needUser, async (c) => c.json(await setup.setDeviceSettings(ctx, uid(c), oid(c), await json(c, setup.deviceSettingsSchema))));
  app.get("/api/device-installs/:token/download", needUser, async (c) => {
    const f = await setup.downloadInstaller(ctx, uid(c), pid(c, "token"));
    if ("script" in f) return new Response(f.script, { headers: {
      "content-type": "application/octet-stream", "content-disposition": `attachment; filename="${f.filename}"`,
      "cache-control": "no-store", "x-content-type-options": "nosniff",
    } });
    const body = Readable.toWeb(createReadStream(f.path)) as unknown as ReadableStream;
    return new Response(body, { headers: {
      "content-type": "application/vnd.microsoft.portable-executable", "content-length": String(f.size),
      "content-disposition": `attachment; filename="${f.filename}"`, "cache-control": "no-store", "x-content-type-options": "nosniff",
    } });
  });
  const claimIp = new RateLimiter(20 * m, 15 * 60_000);
  app.post("/v1/device/install/claim", async (c) => {
    const rl = claimIp.check(clientIp(c));
    if (!rl.ok) throw new HttpError(429, "RATE_LIMITED", "Too many attempts from this network. Try again later.");
    const r = await setup.claimInstall(ctx, await json(c, setup.installClaimSchema), clientIp(c));
    return c.json(r.body, r.status);
  });
  app.post("/v1/device/pair/start", async (c) => {
    const rl = pairStartIp.check(clientIp(c));
    if (!rl.ok) {
      c.header("Retry-After", String(rl.retryAfterSec));
      throw new HttpError(429, "RATE_LIMITED", "Too many pairing requests from this network. Try again later.");
    }
    return c.json(await setup.startPairing(ctx, await json(c, setup.pairStartSchema), clientIp(c)), 201);
  });
  app.post("/v1/device/pair/poll", async (c) => {
    const rl = pairPollIp.check(clientIp(c));
    if (!rl.ok) throw new HttpError(429, "RATE_LIMITED", "Slow down.");
    const r = await setup.pollPairing(ctx, await json(c, setup.pairPollSchema));
    return c.json(r.body, r.status);
  });

  // ---- alert channels (Slack, email) and exports ----
  app.get(org("/channels"), needUser, async (c) => c.json(await notify.listChannels(ctx, uid(c), oid(c))));
  app.post(org("/channels"), needUser, async (c) => c.json(await notify.createChannel(ctx, uid(c), oid(c), await json(c, notify.channelSchema)), 201));
  app.put(org("/channels/:channelId"), needUser, async (c) => c.json(await notify.updateChannel(ctx, uid(c), oid(c), pid(c, "channelId"), await json(c, notify.channelSchema))));
  app.delete(org("/channels/:channelId"), needUser, async (c) => c.json(await notify.deleteChannel(ctx, uid(c), oid(c), pid(c, "channelId"))));
  app.post(org("/channels/:channelId/test"), needUser, async (c) => c.json(await notify.testChannel(ctx, uid(c), oid(c), pid(c, "channelId"))));
  app.get(org("/export"), needUser, async (c) => {
    const parsed = exporter.exportQuery.safeParse(q(c));
    if (!parsed.success) throw new HttpError(400, "VALIDATION_FAILED", "Choose what to export (audit or activity), a format (csv or jsonl) and a valid period.");
    const r = await exporter.exportData(ctx, uid(c), oid(c), parsed.data);
    return new Response(r.body, { headers: { "content-type": r.contentType, "content-disposition": `attachment; filename="${r.filename}"`, "cache-control": "no-store" } });
  });

  // ---- agents ----
  app.get(org("/agents"), needUser, async (c) => c.json(await queries.listAgents(ctx, uid(c), oid(c), q(c))));
  app.post(org("/agents"), needUser, async (c) => c.json(await admin.createAgent(ctx, uid(c), oid(c), await json(c, admin.agentCreateSchema)), 201));
  app.get(org("/agents/:agentId"), needUser, async (c) => c.json(await queries.getAgent(ctx, uid(c), oid(c), pid(c, "agentId"))));
  app.patch(org("/agents/:agentId"), needUser, async (c) => {
    await admin.updateAgent(ctx, uid(c), oid(c), pid(c, "agentId"), await json(c, admin.agentUpdateSchema));
    return c.json({ ok: true });
  });
  app.post(org("/agents/:agentId/revoke"), needUser, async (c) => {
    await admin.revokeAgent(ctx, uid(c), oid(c), pid(c, "agentId"));
    return c.json({ ok: true });
  });

  // ---- credentials ----
  app.get(org("/credentials"), needUser, async (c) => c.json({ items: await queries.listCredentials(ctx, uid(c), oid(c)) }));
  app.post(org("/credentials"), needUser, async (c) => c.json(await admin.createCredential(ctx, uid(c), oid(c), await json(c, admin.credentialCreateSchema)), 201));
  app.post(org("/credentials/:credId/revoke"), needUser, async (c) => {
    await admin.revokeCredential(ctx, uid(c), oid(c), pid(c, "credId"));
    return c.json({ ok: true });
  });
  app.post(org("/credentials/:credId/replace"), needUser, async (c) => c.json(await admin.replaceCredential(ctx, uid(c), oid(c), pid(c, "credId")), 201));

  // ---- policies ----
  app.get(org("/policies"), needUser, async (c) => c.json({ items: await queries.listPolicies(ctx, uid(c), oid(c)) }));
  app.post(org("/policies"), needUser, async (c) => c.json(await admin.createPolicy(ctx, uid(c), oid(c), await json(c, admin.policyCreateSchema)), 201));
  app.post(org("/policies/simulate"), needUser, async (c) => {
    await admin.requireRole(ctx.db, uid(c), oid(c), "viewer");
    return c.json(admin.simulatePolicy(await json(c, admin.simulateSchema)));
  });
  app.get(org("/policies/:policyId"), needUser, async (c) => c.json(await queries.getPolicy(ctx, uid(c), oid(c), pid(c, "policyId"))));
  app.put(org("/policies/:policyId"), needUser, async (c) => c.json(await admin.updatePolicy(ctx, uid(c), oid(c), pid(c, "policyId"), await json(c, admin.policyUpdateSchema))));

  // ---- activity, approvals, alerts, audit ----
  app.get(org("/live"), needUser, async (c) => c.json(await queries.live(ctx, uid(c), oid(c), q(c))));
  app.get(org("/actions"), needUser, async (c) => c.json(await queries.listActions(ctx, uid(c), oid(c), q(c))));
  app.get(org("/actions/:actionId"), needUser, async (c) => c.json(await queries.getActionDetail(ctx, uid(c), oid(c), pid(c, "actionId"))));
  app.get(org("/observations"), needUser, async (c) => c.json(await queries.listObservations(ctx, uid(c), oid(c), q(c))));
  app.get(org("/approvals"), needUser, async (c) => c.json(await queries.listApprovals(ctx, uid(c), oid(c), q(c))));
  for (const verdict of ["approve", "reject"] as const) {
    app.post(org(`/approvals/:approvalId/${verdict}`), needUser, async (c) => {
      const body = await json(c, admin.approvalDecisionSchema);
      await admin.decideApproval(ctx, uid(c), oid(c), pid(c, "approvalId"), verdict, body.note);
      return c.json({ ok: true });
    });
  }
  app.get(org("/alerts"), needUser, async (c) => c.json(await queries.listAlerts(ctx, uid(c), oid(c), q(c))));
  for (const status of ["acknowledged", "resolved"] as const) {
    app.post(org(`/alerts/:alertId/${status === "acknowledged" ? "acknowledge" : "resolve"}`), needUser, async (c) => {
      await admin.setAlertStatus(ctx, uid(c), oid(c), pid(c, "alertId"), status);
      return c.json({ ok: true });
    });
  }
  app.get(org("/audit"), needUser, async (c) => c.json(await queries.listAudit(ctx, uid(c), oid(c), q(c))));

  // ---- protection center, devices, notifications (dashboard side) ----
  app.get(org("/protection"), needUser, async (c) => c.json(await protection(ctx, uid(c), oid(c))));
  app.get(org("/devices"), needUser, async (c) => c.json({ items: await devices.listDevices(ctx, uid(c), oid(c)) }));
  app.post(org("/devices"), needUser, async (c) => c.json(await devices.createDevice(ctx, uid(c), oid(c), await json(c, devices.deviceCreateSchema)), 201));
  app.get(org("/devices/:deviceId"), needUser, async (c) => c.json(await devices.getDevice(ctx, uid(c), oid(c), pid(c, "deviceId"))));
  app.post(org("/devices/:deviceId/revoke"), needUser, async (c) => {
    await devices.revokeDevice(ctx, uid(c), oid(c), pid(c, "deviceId"));
    return c.json({ ok: true });
  });
  app.post(org("/devices/:deviceId/commands"), needUser, async (c) => c.json(await devices.queueCommand(ctx, uid(c), oid(c), pid(c, "deviceId"), (await json(c, devices.commandSchema)).kind), 201));
  app.get(org("/incidents"), needUser, async (c) => c.json(await devices.dashboardIncidents(ctx, uid(c), oid(c), q(c).since)));

  // ---- device API (native companion; hdv_ keys; separate from agent keys) ----
  const needDevice = (kinds: Array<"enrollment" | "device">) => async (c: Context<{ Variables: Vars & { dev: devices.DeviceAuth } }>, next: Next) => {
    const ip = v1Ip.check(clientIp(c));
    if (!ip.ok) {
      c.header("Retry-After", String(ip.retryAfterSec));
      throw new HttpError(429, "RATE_LIMITED", "Too many requests");
    }
    c.set("dev", await devices.authenticateDevice(ctx, c.req.header("authorization"), kinds));
    await next();
  };
  const dapp = app as unknown as Hono<{ Variables: Vars & { dev: devices.DeviceAuth } }>;
  dapp.post("/v1/device/enroll", needDevice(["enrollment"]), async (c) => c.json(await devices.enroll(ctx, c.get("dev"), await json(c, devices.enrollSchema)), 201));
  dapp.post("/v1/device/discovery", needDevice(["device"]), async (c) => c.json(await discovery.reportDiscovery(ctx, c.get("dev"), await json(c, discovery.discoverySchema))));
  dapp.post("/v1/device/heartbeat", needDevice(["device"]), async (c) => c.json(await devices.heartbeat(ctx, c.get("dev"), await json(c, devices.heartbeatSchema))));
  dapp.get("/v1/device/notifications", needDevice(["device"]), async (c) => c.json(await devices.pendingNotifications(ctx, c.get("dev"))));
  dapp.post("/v1/device/notifications/ack", needDevice(["device"]), async (c) => c.json(await devices.acknowledge(ctx, c.get("dev"), await json(c, devices.ackSchema))));
  dapp.post("/v1/device/commands/:commandId/result", needDevice(["device"]), async (c) => c.json(await devices.commandResult(ctx, c.get("dev"), pid(c, "commandId"), await json(c, devices.commandResultSchema))));
  dapp.post("/v1/device/unenroll", needDevice(["device"]), async (c) => c.json(await devices.unenroll(ctx, c.get("dev"))));
  app.get("/v1/signing-key", (c) => (ctx.signer ? c.json({ key_id: ctx.signer.keyId, public_key_pem: ctx.signer.publicKeyPem }) : c.json({ error: { code: "SIGNING_UNAVAILABLE", message: "No policy signing key is configured" } }, 503)));

  // ---- integration API (credential bearer; a credential can never reach /api) ----
  const needKey = (scope: "actions" | "events") => async (c: Context<{ Variables: Vars }>, next: Next) => {
    const ip = v1Ip.check(clientIp(c));
    if (!ip.ok) {
      c.header("Retry-After", String(ip.retryAfterSec));
      throw new HttpError(429, "RATE_LIMITED", "Too many requests");
    }
    const header = c.req.header("authorization");
    const prefix = /^Bearer asg_([A-Za-z0-9]{8})_/.exec(header ?? "")?.[1];
    if (prefix) {
      const k = v1Key.check(prefix);
      if (!k.ok) {
        c.header("Retry-After", String(k.retryAfterSec));
        throw new HttpError(429, "RATE_LIMITED", "Too many requests for this key");
      }
    }
    c.set("cred", await authz.authenticateKey(ctx, header, scope));
    await next();
  };
  const reqIdParam = (c: Context) => {
    const id = c.req.param("requestId") ?? "";
    if (!/^[A-Za-z0-9_.:-]{8,128}$/.test(id)) throw badRequest("INVALID_REQUEST_ID", "Invalid request id");
    return id;
  };

  app.get("/v1/whoami", needKey("actions"), (c) => {
    const k = c.get("cred");
    return c.json({ agent_id: k.agentId, agent_name: k.agent.name, scopes: k.scopes, enforcement_mode: k.agent.enforcement_mode, policy_assigned: !!k.agent.policy_id });
  });
  app.post("/v1/authorize", needKey("actions"), async (c) => c.json(await authz.authorize(ctx, c.get("cred"), await json(c, actionRequestSchema))));
  app.get("/v1/actions/:requestId", needKey("actions"), async (c) => c.json(await authz.getAction(ctx, c.get("cred"), reqIdParam(c))));
  app.post("/v1/actions/:requestId/claim", needKey("actions"), async (c) => {
    const body = await json(c, z.object({ action_digest: z.string().regex(/^[0-9a-f]{64}$/) }).strict());
    const r = await authz.claim(ctx, c.get("cred"), reqIdParam(c), body.action_digest);
    if (!r.ok) {
      return c.json({ permitted: false, decision: "deny", reason_code: r.code, error: { code: r.code, message: r.message } }, r.status);
    }
    return c.json({ permitted: true, ...r.claim });
  });
  app.post("/v1/actions/:requestId/outcome", needKey("actions"), async (c) => c.json(await authz.reportOutcome(ctx, c.get("cred"), reqIdParam(c), await json(c, authz.outcomeSchema))));
  app.get("/v1/policy-bundle", needKey("actions"), async (c) => c.json(await offline.issueBundle(ctx, c.get("cred"))));
  app.get("/v1/policy-state", needKey("actions"), async (c) => c.json(await offline.policyState(ctx, c.get("cred"))));
  app.post("/v1/executor/report", needKey("actions"), async (c) => c.json(await offline.reportExecutor(ctx, c.get("cred"), await json(c, offline.executorReportSchema))));
  app.post("/v1/offline-sync", needKey("actions"), async (c) => c.json(await offline.syncOffline(ctx, c.get("cred"), await json(c, offline.offlineSyncSchema))));
  app.post("/v1/events", needKey("events"), async (c) => c.json(await authz.recordEvent(ctx, c.get("cred"), await json(c, authz.eventSchema)), 201));

  // ---- built web app (production) ----
  if (existsSync("dist/web/index.html")) {
    const indexHtml = readFileSync("dist/web/index.html", "utf8");
    app.use("/assets/*", serveStatic({ root: "./dist/web" }));
    // The service worker must be served from the site root so it can show notifications for the whole app. It contains no secrets.
    const swJs = existsSync("dist/web/sw.js") ? readFileSync("dist/web/sw.js", "utf8") : null;
    if (swJs) app.get("/sw.js", (c) => c.body(swJs, 200, { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-cache" }));
    app.get("*", (c) => {
      const p = new URL(c.req.url).pathname;
      if (p.startsWith("/api/") || p.startsWith("/v1/")) return c.notFound();
      return c.html(indexHtml);
    });
  }
  return app;
}

export { runMigrations };

function safeEqual(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}


const FALLBACK_APPS = KENUXA_APPS;
let appsCache: { at: number; apps: unknown[] } = { at: 0, apps: [] };
async function kenuxaApps(ctx: Ctx) {
  const f: typeof fetch = (ctx as any).fetch ?? fetch;
  if (Date.now() - appsCache.at < 10 * 60_000 && appsCache.apps.length) return appsCache.apps;
  let apps: unknown[] = FALLBACK_APPS;
  const base = ctx.config.KENUXA_SUPABASE_URL?.replace(/\/$/, "");
  const key = ctx.config.KENUXA_SUPABASE_ANON_KEY;
  if (base && key) {
    try {
      const r = await f(`${base}/rest/v1/kenuxa_apps?select=client_id,name,home_url,icon_url,sort&active=eq.true&order=sort`, {
        headers: { apikey: key, authorization: `Bearer ${key}` }, redirect: "error", signal: AbortSignal.timeout(4000),
      });
      const j = r.ok ? await r.json() : null;
      if (Array.isArray(j) && j.length) apps = j;
    } catch { /* offline: the built-in list */ }
  }
  apps = mergeKenuxaApps(apps);
  appsCache = { at: Date.now(), apps };
  return apps;
}
