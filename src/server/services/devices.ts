import { z } from "zod";
import { redact } from "../../shared/redact.js";
import { HttpError, conflict, forbidden, notFound } from "../errors.js";
import type { Queryable } from "../db.js";
import { newDeviceKey, parseDeviceKey, safeEqual, sha256 } from "../security.js";
import { requireRole, parse } from "./admin.js";
import { audit, type Ctx } from "./core.js";

/** Heartbeats arrive every ~30s. Fresh = a live companion; stale = cannot be assumed to be enforcing or notifying. */
export const DEVICE_FRESH_MS = 3 * 60_000;
export const DEVICE_DEAD_MS = 15 * 60_000;
const ENROLLMENT_TTL_MIN = 60;
/** The same open alert that fires again is only re-announced to a device after this long. This is what prevents notification storms. */
export const RENOTIFY_COOLDOWN_MIN = 30;

/** Alerts worth interrupting a person for. Everything else stays in the dashboard. */
export const INCIDENT_KINDS = ["high_risk_action_denied", "argument_mismatch", "revoked_credential_used", "execution_failed", "offline_decision_mismatch", "device_offline"];

export type DeviceRow = {
  id: string; org_id: string; name: string; platform: string; status: "pending" | "active" | "revoked" | "removed"; kind?: "companion" | "browser"; user_id?: string | null;
  created_at: Date; enrolled_at: Date | null; last_heartbeat_at: Date | null; companion_version: string | null;
  health: any; notification_state: string | null; notification_checked_at: Date | null; consent: any; revoked_at: Date | null;
};

export function deviceConnection(d: DeviceRow, now = Date.now()) {
  if (d.status === "revoked") return { state: "revoked" as const, label: "Revoked", age_ms: null };
  if (d.status === "removed") return { state: "removed" as const, label: "Removed (uninstalled)", age_ms: null };
  if (d.status === "pending") return { state: "pending" as const, label: "Waiting for enrollment", age_ms: null };
  const age = d.last_heartbeat_at ? now - new Date(d.last_heartbeat_at).getTime() : null;
  if (d.kind === "browser") {
    // A browser is reachable by Web Push whether or not Heimdall is open in it; "online" only means the dashboard is open now.
    if (age !== null && age <= DEVICE_FRESH_MS * 2) return { state: "online" as const, label: "Dashboard open now", age_ms: age };
    return { state: "online" as const, label: d.notification_state === "enabled" ? "Push notifications on" : "Added (notifications off)", age_ms: age };
  }
  if (age === null) return { state: "silent" as const, label: "Enrolled, no heartbeat yet", age_ms: null };
  if (age <= DEVICE_FRESH_MS) return { state: "online" as const, label: "Companion online", age_ms: age };
  if (age <= DEVICE_DEAD_MS) return { state: "stale" as const, label: "Heartbeat stale", age_ms: age };
  return { state: "offline" as const, label: "Companion not heard from", age_ms: age };
}

export function deviceView(d: DeviceRow) {
  return {
    id: d.id, name: d.name, platform: d.platform, kind: d.kind ?? "companion", user_id: d.user_id ?? null, status: d.status, created_at: d.created_at, enrolled_at: d.enrolled_at,
    last_heartbeat_at: d.last_heartbeat_at, companion_version: d.companion_version, connection: deviceConnection(d),
    notification_state: d.notification_state, notification_checked_at: d.notification_checked_at,
    consent: d.consent, health: d.health, revoked_at: d.revoked_at,
  };
}

// ---------- admin (session) ----------

export const deviceCreateSchema = z.object({ name: z.string().trim().min(1).max(120), platform: z.enum(["windows", "linux", "macos", "other"]).default("windows") }).strict();

export async function createDevice(ctx: Ctx, userId: string, orgId: string, input: z.infer<typeof deviceCreateSchema>) {
  return ctx.db.tx(async (q) => {
    await requireRole(q, userId, orgId, "admin");
    let d: { id: string };
    try {
      [d] = await q.query<{ id: string }>("INSERT INTO devices (org_id, name, platform, enrolled_by) VALUES ($1,$2,$3,$4) RETURNING id", [orgId, input.name, input.platform, userId]);
    } catch (e) {
      if ((e as { code?: string }).code === "23505") throw conflict("DEVICE_EXISTS", "A device with this name already exists");
      throw e;
    }
    const k = newDeviceKey();
    const [c] = await q.query<{ expires_at: Date }>(
      `INSERT INTO device_credentials (org_id, device_id, prefix, secret_hash, kind, expires_at) VALUES ($1,$2,$3,$4,'enrollment', now() + make_interval(mins => $5::int)) RETURNING expires_at`,
      [orgId, d.id, k.prefix, k.hash, ENROLLMENT_TTL_MIN],
    );
    await audit(q, { orgId, actorType: "user", actorId: userId, action: "device.enrollment_started", targetType: "device", targetId: d.id, metadata: { name: input.name } });
    // The enrollment token is single-use and short-lived; it is shown once and only its hash is stored.
    return { id: d.id, enrollment_token: k.key, expires_at: c.expires_at, signing_key_id: ctx.signer?.keyId ?? null };
  });
}

export async function listDevices(ctx: Ctx, userId: string, orgId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const rows = await ctx.db.query<DeviceRow>("SELECT * FROM devices WHERE org_id = $1 ORDER BY created_at DESC LIMIT 200", [orgId]);
  return rows.map(deviceView);
}

export async function getDevice(ctx: Ctx, userId: string, orgId: string, id: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw notFound("Device");
  const [d] = await ctx.db.query<DeviceRow>("SELECT * FROM devices WHERE id = $1 AND org_id = $2", [id, orgId]);
  if (!d) throw notFound("Device");
  const commands = await ctx.db.query("SELECT id, kind, status, created_at, completed_at, result FROM device_commands WHERE device_id = $1 AND org_id = $2 ORDER BY created_at DESC LIMIT 10", [id, orgId]);
  const [dl] = await ctx.db.query<{ n: number; last: Date | null }>("SELECT count(*)::int AS n, max(delivered_at) AS last FROM notification_deliveries WHERE device_id = $1 AND org_id = $2 AND state = 'shown'", [id, orgId]);
  return { ...deviceView(d), commands, notifications_shown: dl.n, last_notification_at: dl.last };
}

export async function revokeDevice(ctx: Ctx, userId: string, orgId: string, id: string) {
  await ctx.db.tx(async (q) => {
    // People may remove their own browsers; anything else needs an administrator.
    const [own] = await q.query("SELECT 1 FROM devices WHERE id = $1 AND org_id = $2 AND kind = 'browser' AND user_id = $3", [id, orgId, userId]);
    await requireRole(q, userId, orgId, own ? "viewer" : "admin");
    const rows = await q.query("UPDATE devices SET status = 'revoked', revoked_at = now(), revoked_by = $3 WHERE id = $1 AND org_id = $2 AND status IN ('pending','active') RETURNING id", [id, orgId, userId]);
    if (rows.length === 0) {
      const [e] = await q.query("SELECT 1 FROM devices WHERE id = $1 AND org_id = $2", [id, orgId]);
      if (!e) throw notFound("Device");
      return;
    }
    await q.query("UPDATE device_credentials SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL", [id]);
    await q.query("UPDATE device_commands SET status = 'expired' WHERE device_id = $1 AND status IN ('pending','running')", [id]);
    await audit(q, { orgId, actorType: "user", actorId: userId, action: "device.revoked", targetType: "device", targetId: id });
  });
}

export const commandSchema = z.object({ kind: z.enum(["selftest", "test_notification"]) }).strict();

export async function queueCommand(ctx: Ctx, userId: string, orgId: string, deviceId: string, kind: "selftest" | "test_notification") {
  await requireRole(ctx.db, userId, orgId, "admin");
  const [d] = await ctx.db.query<DeviceRow>("SELECT * FROM devices WHERE id = $1 AND org_id = $2", [deviceId, orgId]);
  if (!d) throw notFound("Device");
  if (d.status !== "active") throw conflict("DEVICE_NOT_ACTIVE", "Only an enrolled, active device can run a test");
  if (d.kind === "browser") throw conflict("BROWSER_DEVICE", "Tests run on the companion app. For a browser, use \"Send a test notification\" on that browser.");
  const [pending] = await ctx.db.query("SELECT 1 FROM device_commands WHERE device_id = $1 AND kind = $2 AND status IN ('pending','running') AND created_at > now() - interval '10 minutes'", [deviceId, kind]);
  if (pending) throw conflict("ALREADY_QUEUED", "A test of this kind is already waiting for the device");
  const [c] = await ctx.db.query<{ id: string }>("INSERT INTO device_commands (org_id, device_id, kind, requested_by) VALUES ($1,$2,$3,$4) RETURNING id", [orgId, deviceId, kind, userId]);
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: `device.command_${kind}`, targetType: "device", targetId: deviceId });
  return c;
}

// ---------- device (bearer hdv_ key) ----------

export interface DeviceAuth { deviceId: string; orgId: string; credentialId: string; kind: "enrollment" | "device"; device: DeviceRow }

export async function authenticateDevice(ctx: Ctx, header: string | undefined, allow: Array<"enrollment" | "device">): Promise<DeviceAuth> {
  const key = /^Bearer (.+)$/.exec(header ?? "")?.[1]?.trim();
  const parsed = key ? parseDeviceKey(key) : null;
  if (!key || !parsed) throw new HttpError(401, "DEVICE_CREDENTIAL_INVALID", "Missing or malformed device key");
  const [row] = await ctx.db.query<any>(
    `SELECT c.id, c.org_id, c.device_id, c.kind, c.secret_hash, c.revoked_at, (c.expires_at IS NOT NULL AND c.expires_at < now()) AS expired
       FROM device_credentials c WHERE c.prefix = $1`,
    [parsed.prefix],
  );
  if (!row || !safeEqual(sha256(key), row.secret_hash)) throw new HttpError(401, "DEVICE_CREDENTIAL_INVALID", "Invalid device key");
  if (row.revoked_at) throw new HttpError(401, "DEVICE_REVOKED", "This device key has been revoked. The companion must stop enforcing under this identity.");
  if (row.expired) throw new HttpError(401, "ENROLLMENT_EXPIRED", "This enrollment token has expired. Create a new one in the dashboard.");
  if (!allow.includes(row.kind)) throw forbidden("This key cannot be used for that operation");
  const [d] = await ctx.db.query<DeviceRow>("SELECT * FROM devices WHERE id = $1 AND org_id = $2", [row.device_id, row.org_id]);
  if (!d || d.status === "revoked" || d.status === "removed") throw new HttpError(401, "DEVICE_REVOKED", "This device has been revoked or removed");
  await ctx.db.query("UPDATE device_credentials SET last_used_at = now() WHERE id = $1", [row.id]);
  return { deviceId: row.device_id, orgId: row.org_id, credentialId: row.id, kind: row.kind, device: d };
}

export const enrollSchema = z.object({ companion_version: z.string().max(32), platform: z.enum(["windows", "linux", "macos", "other"]).optional() }).strict();

/** Exchanges the single-use enrollment token for a long-lived device key. */
export async function enroll(ctx: Ctx, auth: DeviceAuth, body: z.infer<typeof enrollSchema>) {
  return ctx.db.tx(async (q) => {
    const used = await q.query("UPDATE device_credentials SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL AND kind = 'enrollment' RETURNING id", [auth.credentialId]);
    if (used.length === 0) throw new HttpError(401, "ENROLLMENT_USED", "This enrollment token was already used");
    const k = newDeviceKey();
    await q.query("INSERT INTO device_credentials (org_id, device_id, prefix, secret_hash, kind) VALUES ($1,$2,$3,$4,'device')", [auth.orgId, auth.deviceId, k.prefix, k.hash]);
    await q.query("UPDATE devices SET status = 'active', enrolled_at = now(), companion_version = $2, platform = COALESCE($3, platform) WHERE id = $1", [auth.deviceId, body.companion_version, body.platform ?? null]);
    await audit(q, { orgId: auth.orgId, actorType: "system", action: "device.enrolled", targetType: "device", targetId: auth.deviceId });
    return {
      device_id: auth.deviceId, device_key: k.key, policy_signing_key: ctx.signer ? { key_id: ctx.signer.keyId, public_key_pem: ctx.signer.publicKeyPem } : null,
    };
  });
}

const notifState = z.enum(["enabled", "disabled_for_user", "disabled_for_application", "disabled_by_group_policy", "disabled_by_manifest", "dnd_suspected", "unknown", "unsupported"]);
export const heartbeatSchema = z
  .object({
    companion_version: z.string().max(32),
    uptime_s: z.number().int().min(0).max(10 ** 9).optional(),
    executor: z.object({ state: z.enum(["running", "missing", "stale"]), detail: z.string().max(200).optional() }).strict(),
    notifications: z.object({ state: notifState, checked_at: z.string().datetime().optional() }).strict(),
    cloud: z.object({ mode: z.enum(["online", "offline_cache"]).default("online"), cache_expires_at: z.string().datetime().optional(), queued_events: z.number().int().min(0).max(100000).optional() }).strict().optional(),
    consent: z.object({ os_security: z.boolean().default(false), process_inventory: z.boolean().default(false) }).strict().default({ os_security: false, process_inventory: false }),
    os_security: z
      .object({ provider: z.string().max(40), realtime_protection: z.boolean().nullable(), antivirus_enabled: z.boolean().nullable(), signature_age_days: z.number().min(0).max(100000).nullable(), checked_at: z.string().datetime() })
      .strict()
      .optional(),
    processes: z.object({ candidates: z.array(z.object({ name: z.string().max(60), count: z.number().int().min(1).max(1000), confidence: z.literal("weak") }).strict()).max(20) }).strict().optional(),
  })
  .strict();

export async function heartbeat(ctx: Ctx, auth: DeviceAuth, body: z.infer<typeof heartbeatSchema>) {
  // Optional telemetry is only accepted when the device user has consented ON THE DEVICE and says so in the same message.
  const health = redact({
    reported_at: new Date().toISOString(), companion_version: body.companion_version, uptime_s: body.uptime_s ?? null, executor: body.executor,
    cloud: body.cloud ?? { mode: "online" },
    os_security: body.consent.os_security ? body.os_security ?? null : null,
    processes: body.consent.process_inventory ? body.processes ?? null : null,
  });
  await ctx.db.query(
    `UPDATE devices SET last_heartbeat_at = now(), companion_version = $2, health = $3::jsonb, notification_state = $4, notification_checked_at = now(), consent = $5::jsonb WHERE id = $1`,
    [auth.deviceId, body.companion_version, JSON.stringify(health), body.notifications.state, JSON.stringify(body.consent)],
  );
  const commands = await ctx.db.query<{ id: string; kind: string }>(
    "UPDATE device_commands SET status = 'running' WHERE device_id = $1 AND status = 'pending' AND created_at > now() - interval '15 minutes' RETURNING id, kind",
    [auth.deviceId],
  );
  await ctx.db.query("UPDATE device_commands SET status = 'expired' WHERE device_id = $1 AND status = 'pending' AND created_at <= now() - interval '15 minutes'", [auth.deviceId]);
  return { server_time: new Date().toISOString(), commands };
}

/** Incident-class alerts this device has not yet been told about. Org scope comes from the device credential. */
export async function pendingNotifications(ctx: Ctx, auth: DeviceAuth) {
  const rows = await ctx.db.query<any>(
    `SELECT al.id, al.kind, al.severity, al.title, al.detail, al.occurrences, al.created_at, ag.name AS agent_name
       FROM alerts al LEFT JOIN agents ag ON ag.id = al.agent_id
      WHERE al.org_id = $1 AND al.status <> 'resolved' AND (al.severity = 'high' OR al.kind = ANY($2::text[]))
        AND al.last_seen_at >= (SELECT enrolled_at FROM devices WHERE id = $3)
        AND NOT EXISTS (SELECT 1 FROM notification_deliveries nd WHERE nd.alert_id = al.id AND nd.device_id = $3
                         AND al.last_seen_at <= nd.delivered_at + make_interval(mins => $4::int))
      ORDER BY al.created_at DESC LIMIT 200`,
    [auth.orgId, INCIDENT_KINDS, auth.deviceId, RENOTIFY_COOLDOWN_MIN],
  );
  const show = rows.slice(0, 3).map((r) => ({ alert_id: r.id, kind: r.kind, severity: r.severity, title: r.title, agent_name: r.agent_name, created_at: r.created_at, occurrences: r.occurrences, is_demo: undefined }));
  return { total: rows.length, show, coalesce_ids: rows.slice(3).map((r) => r.id) };
}

export const ackSchema = z
  .object({
    items: z.array(z.object({ alert_id: z.uuid(), state: z.enum(["shown", "coalesced", "suppressed_disabled", "suppressed_policy", "failed"]), detail: z.string().max(200).optional() }).strict()).min(1).max(200),
  })
  .strict();

export async function acknowledge(ctx: Ctx, auth: DeviceAuth, body: z.infer<typeof ackSchema>) {
  let accepted = 0;
  for (const it of body.items) {
    // The alert must belong to THIS device's organization; foreign ids are silently ignored (and counted as not accepted).
    const rows = await ctx.db.query(
      `INSERT INTO notification_deliveries (org_id, device_id, alert_id, state, detail)
       SELECT $1, $2, al.id, $4, $5 FROM alerts al WHERE al.id = $3 AND al.org_id = $1 ON CONFLICT (alert_id, device_id) DO UPDATE SET state = EXCLUDED.state, detail = EXCLUDED.detail, delivered_at = now()
         WHERE notification_deliveries.delivered_at < now() - make_interval(mins => $6::int) RETURNING id`,
      [auth.orgId, auth.deviceId, it.alert_id, it.state, it.detail ?? null, RENOTIFY_COOLDOWN_MIN],
    );
    accepted += rows.length;
  }
  return { accepted };
}

export const commandResultSchema = z.object({ status: z.enum(["done", "failed"]), result: z.record(z.string().max(60), z.unknown()).default({}) }).strict();

export async function commandResult(ctx: Ctx, auth: DeviceAuth, commandId: string, body: z.infer<typeof commandResultSchema>) {
  const rows = await ctx.db.query(
    "UPDATE device_commands SET status = $4, result = $5::jsonb, completed_at = now() WHERE id = $1 AND device_id = $2 AND org_id = $3 AND status = 'running' RETURNING id",
    [commandId, auth.deviceId, auth.orgId, body.status, JSON.stringify(redact(body.result))],
  );
  if (rows.length === 0) throw notFound("Command");
  return { ok: true };
}

/** Device-initiated removal (uninstall). Revokes every credential of this device; removes nothing else. */
export async function unenroll(ctx: Ctx, auth: DeviceAuth) {
  await ctx.db.tx(async (q) => {
    await q.query("UPDATE devices SET status = 'removed', revoked_at = now() WHERE id = $1 AND org_id = $2", [auth.deviceId, auth.orgId]);
    await q.query("UPDATE device_credentials SET revoked_at = COALESCE(revoked_at, now()) WHERE device_id = $1", [auth.deviceId]);
    await q.query("UPDATE device_commands SET status = 'expired' WHERE device_id = $1 AND status IN ('pending','running')", [auth.deviceId]);
    await audit(q, { orgId: auth.orgId, actorType: "system", actorId: auth.deviceId, action: "device.unenrolled", targetType: "device", targetId: auth.deviceId });
  });
  return { ok: true };
}

/** Raises one alert per silent device (de-duplicated while open). Run by the background worker. */
export async function sweepDevices(q: Queryable) {
  const rows = await q.query<{ id: string; org_id: string; name: string }>(
    `SELECT id, org_id, name FROM devices WHERE status = 'active' AND kind = 'companion' AND last_heartbeat_at IS NOT NULL AND last_heartbeat_at < now() - make_interval(secs => $1::double precision)`,
    [DEVICE_DEAD_MS / 1000],
  );
  for (const d of rows) {
    await q.query(
      `INSERT INTO alerts (org_id, kind, severity, title, detail, dedupe_key) VALUES ($1,'device_offline','medium',$2,$3,$4)
       ON CONFLICT (org_id, dedupe_key) WHERE dedupe_key IS NOT NULL AND status <> 'resolved' DO UPDATE SET occurrences = alerts.occurrences + 1, last_seen_at = now()`,
      [d.org_id, `Device '${d.name}' has stopped reporting`, "The companion has not sent a heartbeat for over 15 minutes. Local enforcement and desktop notifications on this device cannot be assumed.", `device-offline:${d.id}`],
    );
  }
  return rows.length;
}

export { parse };

/** New incident-class alerts for the dashboard's own desktop notifications (works only while the dashboard is loaded). */
export async function dashboardIncidents(ctx: Ctx, userId: string, orgId: string, since?: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const from = since && !Number.isNaN(Date.parse(since)) ? since : new Date(Date.now() - 60_000).toISOString();
  const items = await ctx.db.query(
    `SELECT id, kind, severity, title, occurrences, created_at, is_demo FROM alerts
      WHERE org_id = $1 AND status = 'open' AND (severity = 'high' OR kind = ANY($2::text[])) AND created_at > $3::timestamptz ORDER BY created_at ASC LIMIT 20`,
    [orgId, INCIDENT_KINDS, from],
  );
  return { items, server_time: new Date().toISOString() };
}
