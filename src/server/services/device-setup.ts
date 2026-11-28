/**
 * Automatic device setup (docs/DEVICES.md).
 *
 * Browsers: the dashboard asks "Add this device?". Yes creates an active browser device for this person, the browser subscribes
 * to Web Push, and from then on approval requests (for people who can approve) and incident alerts reach it even when Heimdall
 * is not open. Nothing to copy, nothing to install.
 *
 * Companion app: on first start the app calls /v1/device/pair/start, shows a short code and opens the dashboard at /pair. A
 * signed-in administrator checks the code and chooses the organization; the app, polling, receives its device key once, saves
 * it, sets itself to start at sign-in and starts protecting. No enrollment token is copied by hand.
 */
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { HttpError, conflict, notFound } from "../errors.js";
import { log } from "../log.js";
import { open, seal } from "../secret-box.js";
import { newDeviceKey, safeEqual, sha256 } from "../security.js";
import { can, audit, type Ctx, type Role } from "./core.js";
import { requireRole } from "./admin.js";
import { INCIDENT_KINDS, deviceView } from "./devices.js";

const PLATFORMS = ["windows", "linux", "macos", "android", "ios", "other"] as const;

// ---------------------------------------------------------------- Web Push keys (generated once, kept encrypted)

let vapidCache: { publicKey: string; privateKey: string } | null = null;
export async function vapidKeys(ctx: Ctx) {
  if (vapidCache) return vapidCache;
  const [row] = await ctx.db.query<{ value_enc: string }>("SELECT value_enc FROM server_secrets WHERE name = 'vapid'");
  if (row) return (vapidCache = JSON.parse(open(ctx.config, row.value_enc)));
  const webpush = (await import("web-push")).default;
  const k = webpush.generateVAPIDKeys();
  await ctx.db.query("INSERT INTO server_secrets (name, value_enc) VALUES ('vapid', $1) ON CONFLICT (name) DO NOTHING", [seal(ctx.config, JSON.stringify(k))]);
  const [again] = await ctx.db.query<{ value_enc: string }>("SELECT value_enc FROM server_secrets WHERE name = 'vapid'");
  return (vapidCache = JSON.parse(open(ctx.config, again.value_enc)));
}
export const resetVapidCache = () => (vapidCache = null);

// ---------------------------------------------------------------- browser devices

export const browserDeviceSchema = z.object({
  label: z.string().trim().min(1).max(60),          // "Chrome on Windows"
  platform: z.enum(PLATFORMS).default("other"),
}).strict();

/** Adds this browser for the signed-in person. Active at once: the session is the proof. */
export async function addBrowserDevice(ctx: Ctx, userId: string, orgId: string, input: z.infer<typeof browserDeviceSchema>) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const [u] = await ctx.db.query<{ name: string }>("SELECT name FROM users WHERE id = $1", [userId]);
  const first = (u?.name || "My").split(/\s+/)[0].slice(0, 30);
  const base = `${first}'s ${input.label}`.slice(0, 110);
  let d: any;
  for (let i = 1; i <= 50 && !d; i++) {
    const name = i === 1 ? base : `${base} (${i})`;
    try {
      [d] = await ctx.db.query<any>(
        `INSERT INTO devices (org_id, name, platform, kind, user_id, status, enrolled_by, enrolled_at, last_heartbeat_at, companion_version)
         VALUES ($1,$2,$3,'browser',$4,'active',$4, now(), now(), 'browser') RETURNING *`,
        [orgId, name, input.platform, userId],
      );
    } catch (e) {
      if ((e as { code?: string }).code !== "23505") throw e;
    }
  }
  if (!d) throw conflict("DEVICE_EXISTS", "Too many devices with this name.");
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "device.browser_added", targetType: "device", targetId: d.id, metadata: { name: d.name } });
  return { device: deviceView(d), vapid_public_key: (await vapidKeys(ctx)).publicKey };
}

async function ownBrowser(ctx: Ctx, userId: string, orgId: string, deviceId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  if (!/^[0-9a-f-]{36}$/i.test(deviceId)) throw notFound("Device");
  const [d] = await ctx.db.query<any>("SELECT * FROM devices WHERE id = $1 AND org_id = $2 AND kind = 'browser' AND user_id = $3", [deviceId, orgId, userId]);
  if (!d) throw notFound("Device");
  return d;
}

export const pushSubscriptionSchema = z.object({
  subscription: z.object({
    endpoint: z.string().url().max(1000).refine((u) => u.startsWith("https://"), "push endpoints are https"),
    expirationTime: z.number().nullable().optional(),
    keys: z.object({ p256dh: z.string().min(20).max(200), auth: z.string().min(8).max(100) }).strict(),
  }).strict().nullable(),
  permission: z.enum(["granted", "denied", "default", "unsupported"]),
}).strict();

/** Saves (or clears) this browser's push subscription and its notification permission. */
export async function setBrowserPush(ctx: Ctx, userId: string, orgId: string, deviceId: string, input: z.infer<typeof pushSubscriptionSchema>) {
  const d = await ownBrowser(ctx, userId, orgId, deviceId);
  if (d.status !== "active") throw conflict("DEVICE_NOT_ACTIVE", "This device was removed. Add it again.");
  const s = input.subscription;
  if (s) {
    await ctx.db.query(
      `INSERT INTO push_subscriptions (device_id, org_id, endpoint, p256dh, auth) VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (device_id) DO UPDATE SET endpoint = EXCLUDED.endpoint, p256dh = EXCLUDED.p256dh, auth = EXCLUDED.auth, created_at = now()`,
      [deviceId, orgId, s.endpoint, s.keys.p256dh, s.keys.auth],
    );
  } else {
    await ctx.db.query("DELETE FROM push_subscriptions WHERE device_id = $1", [deviceId]);
  }
  const state = s && input.permission === "granted" ? "enabled" : input.permission === "denied" ? "disabled_for_user" : input.permission === "unsupported" ? "unsupported" : "unknown";
  await ctx.db.query("UPDATE devices SET notification_state = $2, notification_checked_at = now(), last_heartbeat_at = now() WHERE id = $1", [deviceId, state]);
  return { notification_state: state };
}

/** Called while the dashboard is open in this browser. Answers whether the device is still active (it may have been removed). */
export async function browserHeartbeat(ctx: Ctx, userId: string, orgId: string, deviceId: string) {
  const d = await ownBrowser(ctx, userId, orgId, deviceId);
  if (d.status === "active") await ctx.db.query("UPDATE devices SET last_heartbeat_at = now() WHERE id = $1", [deviceId]);
  return { status: d.status, notification_state: d.notification_state };
}

export async function testBrowserPush(ctx: Ctx, userId: string, orgId: string, deviceId: string) {
  await ownBrowser(ctx, userId, orgId, deviceId);
  const [sub] = await ctx.db.query<any>("SELECT * FROM push_subscriptions WHERE device_id = $1", [deviceId]);
  if (!sub) throw conflict("PUSH_NOT_ENABLED", "Notifications are not on in this browser. Allow them, then try again.");
  const r = await pushOne(ctx, sub, { title: "Kenuxa Heimdall", body: "Test notification: this browser will be told about approvals and incidents.", url: "/protection", tag: "test" });
  if (r !== "sent") throw new HttpError(502, "PUSH_FAILED", r === "gone" ? "The browser no longer accepts notifications. Allow them again in this browser." : "The browser's push service did not accept the message.");
  return { ok: true };
}

// ---------------------------------------------------------------- push dispatch

async function pushOne(ctx: Ctx, sub: { device_id: string; endpoint: string; p256dh: string; auth: string }, msg: { title: string; body: string; url: string; tag: string }): Promise<"sent" | "gone" | "failed"> {
  try {
    const payload = JSON.stringify(msg);
    const target = { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } };
    let status: number;
    if (ctx.webPush) status = (await ctx.webPush(target, payload)).statusCode;
    else {
      const webpush = (await import("web-push")).default;
      const k = await vapidKeys(ctx);
      const subject = ctx.config.APP_URL.startsWith("https://") ? ctx.config.APP_URL : `mailto:${/<([^>]+)>/.exec(ctx.config.EMAIL_FROM)?.[1] ?? "alerts@heimdall.local"}`;
      status = (await webpush.sendNotification(target, payload, { vapidDetails: { subject, publicKey: k.publicKey, privateKey: k.privateKey }, TTL: 6 * 3600, urgency: "high", timeout: 8000 })).statusCode;
    }
    if (status >= 200 && status < 300) {
      await ctx.db.query("UPDATE push_subscriptions SET last_success_at = now() WHERE device_id = $1", [sub.device_id]);
      return "sent";
    }
    return "failed";
  } catch (e) {
    const code = (e as { statusCode?: number }).statusCode;
    if (code === 404 || code === 410) {
      // The browser unsubscribed or the subscription expired: stop sending, show it on the device.
      await ctx.db.query("DELETE FROM push_subscriptions WHERE device_id = $1", [sub.device_id]);
      await ctx.db.query("UPDATE devices SET notification_state = 'disabled_for_user', notification_checked_at = now() WHERE id = $1", [sub.device_id]);
      return "gone";
    }
    log("warn", "web push failed", { device: sub.device_id, error: (e as Error).message });
    return "failed";
  }
}

/**
 * Pushes new incident alerts to every member's browsers and new approval requests to the browsers of people who can approve
 * them. Each item reaches each browser once (push_deliveries). Only items from the last 30 minutes are considered.
 */
export async function dispatchPushes(ctx: Ctx) {
  const items = await ctx.db.query<any>(
    `SELECT s.*, d.user_id, m.role, 'alert:' || a.id AS ref, a.title, a.detail AS body, '/alerts' AS url, 'alert' AS kind, NULL AS required_role
       FROM alerts a JOIN devices d ON d.org_id = a.org_id AND d.kind = 'browser' AND d.status = 'active'
       JOIN push_subscriptions s ON s.device_id = d.id
       JOIN memberships m ON m.org_id = a.org_id AND m.user_id = d.user_id
      WHERE a.status = 'open' AND NOT a.is_demo AND a.kind = ANY($1::text[]) AND a.created_at > now() - interval '30 minutes'
        AND NOT EXISTS (SELECT 1 FROM push_deliveries p WHERE p.device_id = d.id AND p.ref = 'alert:' || a.id)
     UNION ALL
     SELECT s.*, d.user_id, m.role, 'approval:' || ap.id AS ref, 'Approval needed: ' || ar.tool || ' ' || replace(ar.operation, '_', ' ') AS title,
            ag.name || ' wants to ' || replace(ar.operation, '_', ' ') || ' ' || ar.resource AS body, '/approvals' AS url, 'approval' AS kind, ap.required_role
       FROM approvals ap JOIN action_requests ar ON ar.id = ap.action_request_id JOIN agents ag ON ag.id = ar.agent_id
       JOIN devices d ON d.org_id = ap.org_id AND d.kind = 'browser' AND d.status = 'active'
       JOIN push_subscriptions s ON s.device_id = d.id
       JOIN memberships m ON m.org_id = ap.org_id AND m.user_id = d.user_id
      WHERE ap.status = 'pending' AND ap.expires_at > now() AND NOT ar.is_demo AND ap.requested_at > now() - interval '30 minutes'
        AND NOT EXISTS (SELECT 1 FROM push_deliveries p WHERE p.device_id = d.id AND p.ref = 'approval:' || ap.id)
     LIMIT 200`,
    [INCIDENT_KINDS],
  );
  let sent = 0;
  for (const it of items) {
    if (it.kind === "approval" && (!can(it.role as Role, "approvals.decide") || (it.required_role === "owner" && it.role !== "owner"))) continue;
    // Claim first, so two dispatchers never push the same item twice.
    const claimed = await ctx.db.query("INSERT INTO push_deliveries (device_id, ref, state) VALUES ($1,$2,'failed') ON CONFLICT DO NOTHING RETURNING device_id", [it.device_id, it.ref]);
    if (!claimed.length) continue;
    const r = await pushOne(ctx, it, { title: String(it.title).slice(0, 120), body: String(it.body ?? "").slice(0, 240), url: it.url, tag: it.ref });
    await ctx.db.query("UPDATE push_deliveries SET state = $3 WHERE device_id = $1 AND ref = $2", [it.device_id, it.ref, r]);
    if (r === "sent") sent++;
  }
  return { sent };
}

// ---------------------------------------------------------------- companion pairing

const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const newUserCode = () => {
  const b = randomBytes(8);
  let s = "";
  for (let i = 0; i < 8; i++) s += CODE_ALPHABET[b[i] % CODE_ALPHABET.length];
  return `${s.slice(0, 4)}-${s.slice(4)}`;
};
const normCode = (c: string) => c.toUpperCase().replace(/[^A-Z0-9]/g, "").replace(/^(.{4})(.{4})$/, "$1-$2");

export const pairStartSchema = z.object({
  device_name: z.string().trim().min(1).max(100),
  platform: z.enum(PLATFORMS).default("windows"),
  companion_version: z.string().max(32),
}).strict();

/** The companion asks to be added. Unauthenticated (it has nothing yet); rate-limited per IP by the route. */
export async function startPairing(ctx: Ctx, input: z.infer<typeof pairStartSchema>, ip: string) {
  await ctx.db.query("UPDATE device_pairings SET status = 'expired' WHERE status IN ('pending','approved') AND expires_at < now()");
  const poll = randomBytes(32).toString("base64url");
  let code = "";
  for (let i = 0; i < 5; i++) {
    code = newUserCode();
    try {
      const [p] = await ctx.db.query<{ id: string; expires_at: Date }>(
        `INSERT INTO device_pairings (user_code, poll_secret_hash, device_name, platform, companion_version, request_ip, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6, now() + interval '10 minutes') RETURNING id, expires_at`,
        [code, sha256(poll), input.device_name, input.platform, input.companion_version, ip],
      );
      const verify = `${ctx.config.APP_URL.replace(/\/$/, "")}/pair?code=${encodeURIComponent(code)}`;
      return { pairing_id: p.id, poll_secret: poll, user_code: code, verify_url: verify, expires_at: p.expires_at, interval_s: 2 };
    } catch (e) {
      if ((e as { code?: string }).code !== "23505") throw e;
    }
  }
  throw new HttpError(503, "PAIRING_BUSY", "Could not start pairing. Try again.");
}

/** What the dashboard shows before someone confirms. */
export async function describePairing(ctx: Ctx, userId: string, code: string, ip: string) {
  const [p] = await ctx.db.query<any>("SELECT * FROM device_pairings WHERE user_code = $1", [normCode(code)]);
  if (!p || p.expires_at < new Date() || p.status !== "pending") throw notFound("Pairing request (it may have expired: start the app again)");
  const orgs = await ctx.db.query<any>("SELECT o.id, o.name, m.role FROM memberships m JOIN organizations o ON o.id = m.org_id WHERE m.user_id = $1 AND m.role IN ('owner','admin') ORDER BY o.name", [userId]);
  return {
    user_code: p.user_code, device_name: p.device_name, platform: p.platform, companion_version: p.companion_version, requested_at: p.created_at,
    expires_at: p.expires_at, same_network: !!p.request_ip && p.request_ip === ip, orgs,
  };
}

export const pairDecisionSchema = z.object({ code: z.string().min(8).max(12), org_id: z.uuid().optional(), approve: z.boolean() }).strict();

/** An administrator approves (device created, active, key prepared for the app) or refuses. */
export async function decidePairing(ctx: Ctx, userId: string, input: z.infer<typeof pairDecisionSchema>) {
  return ctx.db.tx(async (q) => {
    const [p] = await q.query<any>("SELECT * FROM device_pairings WHERE user_code = $1 FOR UPDATE", [normCode(input.code)]);
    if (!p || p.expires_at < new Date() || p.status !== "pending") throw notFound("Pairing request (it may have expired: start the app again)");
    if (!input.approve) {
      await q.query("UPDATE device_pairings SET status = 'denied', decided_at = now(), approved_by = $2 WHERE id = $1", [p.id, userId]);
      return { approved: false };
    }
    if (!input.org_id) throw new HttpError(400, "ORG_REQUIRED", "Choose the organization to add this computer to.");
    await requireRole(q, userId, input.org_id, "admin");
    const { d, key } = await insertCompanionDevice(q, input.org_id, p.device_name, p.platform, userId, p.companion_version);
    const k = { key };
    // The key waits, encrypted, for the app's next poll, then is erased.
    await q.query("UPDATE device_pairings SET status = 'approved', decided_at = now(), approved_by = $2, org_id = $3, device_id = $4, device_key_enc = $5 WHERE id = $1", [p.id, userId, input.org_id, d.id, seal(ctx.config, k.key)]);
    await audit(q, { orgId: input.org_id, actorType: "user", actorId: userId, action: "device.paired", targetType: "device", targetId: d.id, metadata: { name: d.name, platform: d.platform, code: p.user_code } });
    return { approved: true, device: deviceView(d) };
  });
}

export const pairPollSchema = z.object({ pairing_id: z.uuid(), poll_secret: z.string().min(20).max(100) }).strict();

/** The companion collects its key: once. 202 while waiting; 410 when refused or expired. */
export async function pollPairing(ctx: Ctx, input: z.infer<typeof pairPollSchema>) {
  return ctx.db.tx(async (q) => {
    const [p] = await q.query<any>("SELECT * FROM device_pairings WHERE id = $1 FOR UPDATE", [input.pairing_id]);
    if (!p || !safeEqual(sha256(input.poll_secret), p.poll_secret_hash)) throw new HttpError(404, "PAIRING_UNKNOWN", "Unknown pairing request.");
    if (p.status === "pending" && p.expires_at > new Date()) return { status: 202 as const, body: { status: "pending" } };
    if (p.status === "approved" && p.device_key_enc) {
      await q.query("UPDATE device_pairings SET status = 'claimed', device_key_enc = NULL WHERE id = $1", [p.id]);
      return {
        status: 200 as const,
        body: {
          status: "approved", device_id: p.device_id, device_key: open(ctx.config, p.device_key_enc),
          policy_signing_key: ctx.signer ? { key_id: ctx.signer.keyId, public_key_pem: ctx.signer.publicKeyPem } : null,
        },
      };
    }
    const why = p.status === "denied" ? "PAIRING_DENIED" : p.status === "claimed" ? "PAIRING_USED" : "PAIRING_EXPIRED";
    throw new HttpError(410, why, why === "PAIRING_DENIED" ? "The request to add this computer was refused." : why === "PAIRING_USED" ? "This pairing was already completed." : "The pairing request expired. Start again.");
  });
}

// ---------------------------------------------------------------- shared: a new, active companion device with its key

type Q = { query: <T = any>(sql: string, params?: unknown[]) => Promise<T[]> };
async function insertCompanionDevice(q: Q, orgId: string, baseName: string, platform: string, userId: string, version: string) {
  const plat = platform === "windows" || platform === "linux" || platform === "macos" ? platform : "other";
  let d: any;
  for (let i = 1; i <= 50 && !d; i++) {
    const name = (i === 1 ? baseName : `${baseName} (${i})`).slice(0, 120);
    const existing = await q.query("SELECT 1 FROM devices WHERE org_id = $1 AND name = $2", [orgId, name]);
    if (existing.length) continue;
    [d] = await q.query<any>(
      `INSERT INTO devices (org_id, name, platform, kind, status, enrolled_by, enrolled_at, companion_version) VALUES ($1,$2,$3,'companion','active',$4, now(), $5) RETURNING *`,
      [orgId, name, plat, userId, version],
    );
  }
  if (!d) throw conflict("DEVICE_EXISTS", "Too many devices with this name.");
  const k = newDeviceKey();
  await q.query("INSERT INTO device_credentials (org_id, device_id, prefix, secret_hash, kind) VALUES ($1,$2,$3,$4,'device')", [orgId, d.id, k.prefix, k.hash]);
  return { d, key: k.key };
}

// ---------------------------------------------------------------- one-click computer install from the browser

/**
 * The Windows app is built on the server machine (`npm run build:installer`, docs/DEVICES.md) into dist/installer. A download
 * is that same file, renamed Heimdall-Setup-<one-time code>.exe: the code travels in the file NAME, so the file itself (and
 * any code signature on it) is never modified. The app reads its own name on first start and adds the computer.
 */
const installerDir = (ctx: Ctx) => ctx.installerDir ?? join(process.cwd(), "dist", "installer");
function installerManifest(ctx: Ctx): { file: string; version: string; url: string; size: number; built_at: string; download_url?: string; sha256?: string } | null {
  const dir = installerDir(ctx);
  const mf = join(dir, "installer.json");
  if (!existsSync(mf)) return null;
  try {
    const m = JSON.parse(readFileSync(mf, "utf8"));
    if (m.download_url) {
      if (!/^https:\/\/github\.com\/LosharHammond\/Heimdall\/releases\/download\/[a-zA-Z0-9.-]+\/HeimdallSetup\.exe$/.test(m.download_url) || !/^[a-f0-9]{64}$/.test(m.sha256)) return null;
      return { ...m, file: "", size: Number(m.size) };
    }
    const file = join(dir, m.file);
    if (!existsSync(file)) return null;
    return { ...m, file, size: statSync(file).size };
  } catch {
    return null;
  }
}

export async function installerInfo(ctx: Ctx, userId: string, orgId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const m = installerManifest(ctx);
  const [o] = await ctx.db.query<{ device_approval_required: boolean }>("SELECT device_approval_required FROM organizations WHERE id = $1", [orgId]);
  return {
    available: !!m, version: m?.version ?? null, size: m?.size ?? null, built_at: m?.built_at ?? null,
    server_url: m?.url ?? null, approval_required: !!o?.device_approval_required,
  };
}

const TOKEN_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32
const newInstallToken = () => Array.from(randomBytes(24), (b) => TOKEN_ALPHABET[b % 32]).join("");
export const INSTALL_TOKEN_RE = /^[0-9A-HJKMNP-TV-Z]{24}$/;

/** "Protect this computer": a one-time code (15 minutes) for this person and organization, and where to download. */
export async function createInstallToken(ctx: Ctx, userId: string, orgId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  if (!installerManifest(ctx)) throw new HttpError(409, "INSTALLER_NOT_BUILT", "The Windows download is being prepared. Please try again shortly.");
  const token = newInstallToken();
  const [r] = await ctx.db.query<{ expires_at: Date }>(
    "INSERT INTO device_install_tokens (token_hash, org_id, user_id, expires_at) VALUES ($1,$2,$3, now() + interval '15 minutes') RETURNING expires_at",
    [sha256(token), orgId, userId],
  );
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "device.install_link_created", targetType: "organization", targetId: orgId, metadata: {} });
  return { download_url: `/api/device-installs/${token}/download`, filename: installerManifest(ctx)?.download_url ? "Heimdall-Setup.cmd" : `Heimdall-Setup-${token}.exe`, expires_at: r.expires_at };
}

/** Streams the installer under its tagged name. Only for the person who asked for it, while the code is unused. */
export async function downloadInstaller(ctx: Ctx, userId: string, token: string) {
  if (!INSTALL_TOKEN_RE.test(token)) throw notFound("Download");
  const [t] = await ctx.db.query<any>("SELECT * FROM device_install_tokens WHERE token_hash = $1", [sha256(token)]);
  if (!t || t.user_id !== userId || t.used_at || t.expires_at < new Date()) throw notFound("Download (it may have expired: click the button again)");
  const m = installerManifest(ctx);
  if (!m) throw new HttpError(409, "INSTALLER_NOT_BUILT", "The Windows app is not available on this server.");
  if (m.download_url) {
    // The download holds a short-lived, single-use claim code. The GitHub request receives no credentials.
    const ps = `$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $pkg=Join-Path $env:TEMP ('Heimdall-' + [guid]::NewGuid().ToString() + '.exe'); try { Invoke-WebRequest -UseBasicParsing -Uri '${m.download_url}' -OutFile $pkg; if ((Get-FileHash -LiteralPath $pkg -Algorithm SHA256).Hash.ToLower() -ne '${m.sha256}') { throw 'Installer verification failed. Please download again.' }; Start-Process -FilePath $pkg -ArgumentList @('--install-token','${token}') -Wait } catch { Write-Host $_.Exception.Message; Read-Host 'Press Enter to close'; exit 1 } finally { if (Test-Path -LiteralPath $pkg) { Remove-Item -LiteralPath $pkg -Force -ErrorAction SilentlyContinue } }`;
    const script = `@echo off\r\necho Downloading and verifying Kenuxa Heimdall...\r\npowershell.exe -NoProfile -EncodedCommand ${Buffer.from(ps, "utf16le").toString("base64")}\r\n`;
    return { script, filename: "Heimdall-Setup.cmd", size: Buffer.byteLength(script) };
  }
  return { path: m.file, filename: `Heimdall-Setup-${token}.exe`, size: m.size };
}

export const installClaimSchema = z.object({
  install_token: z.string().regex(INSTALL_TOKEN_RE),
  device_name: z.string().trim().min(1).max(100),
  platform: z.enum(PLATFORMS).default("windows"),
  companion_version: z.string().max(32),
}).strict();

/**
 * The app, on first start, trades its code for a device key: the computer is added at once and active. If the organization
 * requires administrator approval, this starts a normal pairing instead (the app shows a code; an admin clicks Add).
 */
export async function claimInstall(ctx: Ctx, input: z.infer<typeof installClaimSchema>, ip: string) {
  const res = await ctx.db.tx(async (q) => {
    const [t] = await q.query<any>("SELECT t.*, o.device_approval_required FROM device_install_tokens t JOIN organizations o ON o.id = t.org_id WHERE t.token_hash = $1 FOR UPDATE OF t", [sha256(input.install_token)]);
    if (!t || t.used_at || t.expires_at < new Date()) return null;
    await q.query("UPDATE device_install_tokens SET used_at = now(), claim_ip = $2 WHERE id = $1", [t.id, ip]);
    if (t.device_approval_required) return { approval: true as const, t };
    const { d, key } = await insertCompanionDevice(q, t.org_id, input.device_name, input.platform, t.user_id, input.companion_version);
    await q.query("UPDATE device_install_tokens SET device_id = $2 WHERE id = $1", [t.id, d.id]);
    await audit(q, { orgId: t.org_id, actorType: "user", actorId: t.user_id, action: "device.installed", targetType: "device", targetId: d.id, metadata: { name: d.name, platform: d.platform, ip } });
    return { approval: false as const, d, key };
  });
  if (!res) throw new HttpError(410, "INSTALL_CODE_INVALID", "This download was already used or is more than 15 minutes old.");
  if (res.approval) {
    const p = await startPairing(ctx, { device_name: input.device_name, platform: input.platform, companion_version: input.companion_version }, ip);
    return { status: 202 as const, body: { status: "approval_required", ...p } };
  }
  return {
    status: 200 as const,
    body: {
      status: "approved", device_id: res.d.id, device_key: res.key,
      policy_signing_key: ctx.signer ? { key_id: ctx.signer.keyId, public_key_pem: ctx.signer.publicKeyPem } : null,
    },
  };
}

export const deviceSettingsSchema = z.object({ device_approval_required: z.boolean() }).strict();
export async function setDeviceSettings(ctx: Ctx, userId: string, orgId: string, input: z.infer<typeof deviceSettingsSchema>) {
  await requireRole(ctx.db, userId, orgId, "admin");
  await ctx.db.query("UPDATE organizations SET device_approval_required = $2 WHERE id = $1", [orgId, input.device_approval_required]);
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "org.device_settings_updated", targetType: "organization", targetId: orgId, metadata: input });
  return input;
}
