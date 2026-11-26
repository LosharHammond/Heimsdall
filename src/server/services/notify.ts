/**
 * Alert delivery to Slack and email. docs/ALERTS.md.
 *
 * Outbox: every open alert that matches a channel (severity at or above its minimum, optional alert kinds) gets one delivery
 * row; a dispatcher sends due rows and retries failures with backoff (1, 5, 30 min, 2 h, 6 h, then gives up). A delivery is
 * created once per alert, so repeats of the same condition (counted on the alert) do not spam the channel.
 * Messages carry the alert's title, severity and detail (already redacted) plus a dashboard link: never raw tool arguments.
 */
import { z } from "zod";
import { HttpError, badRequest, notFound } from "../errors.js";
import { log } from "../log.js";
import { open, seal } from "../secret-box.js";
import { requireRole } from "./admin.js";
import { audit, type Ctx } from "./core.js";

const SEV_RANK = { low: 0, medium: 1, high: 2 } as const;
const BACKOFF_MIN = [1, 5, 30, 120, 360];
const SLACK_RE = /^https:\/\/hooks\.slack\.com\/(services|workflows|triggers)\/[A-Za-z0-9/_-]{10,300}$/;
const emailRe = /^[^\s@<>,;]+@[^\s@<>,;]+\.[^\s@<>,;]+$/;

export const channelSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("slack"),
    name: z.string().trim().min(1).max(80),
    webhook_url: z.string().trim().regex(SLACK_RE, "Paste a Slack incoming-webhook address (https://hooks.slack.com/services/...)").optional(),
    min_severity: z.enum(["low", "medium", "high"]).default("medium"),
    kinds: z.array(z.string().regex(/^[a-z_]{2,60}$/)).max(30).nullable().optional(),
    enabled: z.boolean().default(true),
  }).strict(),
  z.object({
    kind: z.literal("email"),
    name: z.string().trim().min(1).max(80),
    recipients: z.array(z.string().trim().toLowerCase().regex(emailRe, "Enter valid email addresses")).min(1).max(20).optional(),
    min_severity: z.enum(["low", "medium", "high"]).default("medium"),
    kinds: z.array(z.string().regex(/^[a-z_]{2,60}$/)).max(30).nullable().optional(),
    enabled: z.boolean().default(true),
  }).strict(),
]);
type ChannelInput = z.infer<typeof channelSchema>;

const hintFor = (input: ChannelInput) =>
  input.kind === "slack" ? `hooks.slack.com/…${input.webhook_url!.slice(-6)}` : input.recipients!.map((r) => r.replace(/^(.).*(@.*)$/, "$1…$2")).join(", ");

function view(r: any) {
  return {
    id: r.id, kind: r.kind, name: r.name, target: r.target_hint, min_severity: r.min_severity, kinds: r.kinds, enabled: r.enabled,
    created_at: r.created_at, last_success_at: r.last_success_at, last_error: r.last_error, last_error_at: r.last_error_at,
    sent: r.sent ?? 0, failing: r.failing ?? 0,
  };
}

export async function listChannels(ctx: Ctx, userId: string, orgId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const rows = await ctx.db.query<any>(
    `SELECT c.*, (SELECT count(*)::int FROM channel_deliveries d WHERE d.channel_id = c.id AND d.status = 'sent') AS sent,
            (SELECT count(*)::int FROM channel_deliveries d WHERE d.channel_id = c.id AND d.status IN ('failed','dead')) AS failing
       FROM notification_channels c WHERE c.org_id = $1 ORDER BY c.created_at`,
    [orgId],
  );
  return { items: rows.map(view), email_configured: !!(ctx.sendMail || ctx.config.SMTP_URL) };
}

export async function createChannel(ctx: Ctx, userId: string, orgId: string, input: ChannelInput) {
  await requireRole(ctx.db, userId, orgId, "admin");
  const target = input.kind === "slack" ? input.webhook_url : input.recipients?.join(",");
  if (!target) throw badRequest("TARGET_REQUIRED", input.kind === "slack" ? "Paste the Slack webhook address." : "Add at least one email address.");
  const [n] = await ctx.db.query<{ n: number }>("SELECT count(*)::int AS n FROM notification_channels WHERE org_id = $1", [orgId]);
  if (n.n >= 20) throw new HttpError(409, "TOO_MANY_CHANNELS", "An organization can have up to 20 alert channels.");
  const [r] = await ctx.db.query<any>(
    `INSERT INTO notification_channels (org_id, kind, name, target_enc, target_hint, min_severity, kinds, enabled, created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [orgId, input.kind, input.name, seal(ctx.config, target), hintFor(input), input.min_severity, input.kinds ?? null, input.enabled, userId],
  );
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "channel.created", targetType: "channel", targetId: r.id, metadata: { kind: input.kind, name: input.name, min_severity: input.min_severity } });
  return view(r);
}

export async function updateChannel(ctx: Ctx, userId: string, orgId: string, id: string, input: ChannelInput) {
  await requireRole(ctx.db, userId, orgId, "admin");
  const [cur] = await ctx.db.query<any>("SELECT * FROM notification_channels WHERE id = $1 AND org_id = $2", [id, orgId]);
  if (!cur) throw notFound("Channel");
  if (cur.kind !== input.kind) throw badRequest("KIND_CHANGE", "A channel cannot change between Slack and email. Create a new one.");
  const target = input.kind === "slack" ? input.webhook_url : input.recipients?.join(",");
  const [r] = await ctx.db.query<any>(
    `UPDATE notification_channels SET name = $3, min_severity = $4, kinds = $5, enabled = $6,
       target_enc = COALESCE($7, target_enc), target_hint = COALESCE($8, target_hint), last_error = CASE WHEN $7::text IS NULL THEN last_error END
     WHERE id = $1 AND org_id = $2 RETURNING *`,
    [id, orgId, input.name, input.min_severity, input.kinds ?? null, input.enabled, target ? seal(ctx.config, target) : null, target ? hintFor(input) : null],
  );
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "channel.updated", targetType: "channel", targetId: id, metadata: { enabled: input.enabled, min_severity: input.min_severity, target_changed: !!target } });
  return view(r);
}

export async function deleteChannel(ctx: Ctx, userId: string, orgId: string, id: string) {
  await requireRole(ctx.db, userId, orgId, "admin");
  const r = await ctx.db.query("DELETE FROM notification_channels WHERE id = $1 AND org_id = $2 RETURNING id", [id, orgId]);
  if (!r.length) throw notFound("Channel");
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "channel.deleted", targetType: "channel", targetId: id });
  return { ok: true };
}

/** Sends a sample alert right away and reports what happened. */
export async function testChannel(ctx: Ctx, userId: string, orgId: string, id: string) {
  await requireRole(ctx.db, userId, orgId, "admin");
  const [c] = await ctx.db.query<any>("SELECT c.*, o.name AS org_name FROM notification_channels c JOIN organizations o ON o.id = c.org_id WHERE c.id = $1 AND c.org_id = $2", [id, orgId]);
  if (!c) throw notFound("Channel");
  const sample = { id: "test", org_id: orgId, org_name: c.org_name, kind: "test", severity: "medium", title: "Test alert from Kenuxa Heimdall", detail: "If you can read this, alerts reach this channel.", agent_name: null, occurrences: 1, created_at: new Date().toISOString() };
  try {
    await send(ctx, c, sample);
    await ctx.db.query("UPDATE notification_channels SET last_success_at = now(), last_error = NULL WHERE id = $1", [id]);
    await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "channel.tested", targetType: "channel", targetId: id, metadata: { ok: true } });
    return { ok: true };
  } catch (e) {
    const msg = (e as Error).message.slice(0, 300);
    await ctx.db.query("UPDATE notification_channels SET last_error = $2, last_error_at = now() WHERE id = $1", [id, msg]);
    throw new HttpError(502, "CHANNEL_TEST_FAILED", `The test did not get through: ${msg}`);
  }
}

// ---------------------------------------------------------------- dispatch

/** Queues deliveries for new alerts, then sends what is due. Idempotent; safe to run from the web process and the worker. */
export async function dispatchAlerts(ctx: Ctx, opts: { limit?: number } = {}) {
  await ctx.db.query(
    `INSERT INTO channel_deliveries (org_id, channel_id, alert_id)
     SELECT c.org_id, c.id, a.id FROM alerts a
       JOIN notification_channels c ON c.org_id = a.org_id AND c.enabled
      WHERE a.status = 'open' AND NOT a.is_demo AND a.created_at >= c.created_at AND a.created_at > now() - interval '1 day'
        AND (CASE a.severity WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END) >= (CASE c.min_severity WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END)
        AND (c.kinds IS NULL OR a.kind = ANY(c.kinds))
     ON CONFLICT (channel_id, alert_id) DO NOTHING`,
  );
  // Claim due rows with a 2-minute lease (SKIP LOCKED): the web process and the worker never send the same delivery twice.
  const claimed = await ctx.db.query<{ id: string }>(
    `UPDATE channel_deliveries SET next_attempt_at = now() + interval '2 minutes'
      WHERE id IN (SELECT d.id FROM channel_deliveries d JOIN notification_channels c ON c.id = d.channel_id
                    WHERE d.status IN ('pending', 'failed') AND d.next_attempt_at <= now() AND c.enabled
                    ORDER BY d.next_attempt_at LIMIT ${Math.min(opts.limit ?? 50, 200)} FOR UPDATE OF d SKIP LOCKED)
      RETURNING id`,
  );
  if (!claimed.length) return { sent: 0, failed: 0 };
  const due = await ctx.db.query<any>(
    `SELECT d.id AS delivery_id, d.attempts, c.*, o.name AS org_name,
            a.id AS alert_id, a.kind AS alert_kind, a.severity, a.title, a.detail, a.occurrences, a.created_at AS alert_created_at, a.status AS alert_status, ag.name AS agent_name
       FROM channel_deliveries d
       JOIN notification_channels c ON c.id = d.channel_id
       JOIN alerts a ON a.id = d.alert_id
       JOIN organizations o ON o.id = d.org_id
       LEFT JOIN agents ag ON ag.id = a.agent_id
      WHERE d.id = ANY($1::uuid[])`,
    [claimed.map((r) => r.id)],
  );
  let sent = 0;
  let failed = 0;
  for (const row of due) {
    const alert = { id: row.alert_id, org_id: row.org_id, org_name: row.org_name, kind: row.alert_kind, severity: row.severity, title: row.title, detail: row.detail, agent_name: row.agent_name, occurrences: row.occurrences, created_at: row.alert_created_at };
    try {
      await send(ctx, row, alert);
      await ctx.db.query("UPDATE channel_deliveries SET status = 'sent', sent_at = now(), attempts = attempts + 1, last_error = NULL WHERE id = $1", [row.delivery_id]);
      await ctx.db.query("UPDATE notification_channels SET last_success_at = now(), last_error = NULL WHERE id = $1", [row.id]);
      sent++;
    } catch (e) {
      const attempts = row.attempts + 1;
      const msg = (e as Error).message.slice(0, 300);
      const dead = attempts > BACKOFF_MIN.length;
      await ctx.db.query(
        `UPDATE channel_deliveries SET status = $2, attempts = $3, last_error = $4, next_attempt_at = now() + make_interval(mins => $5::int) WHERE id = $1`,
        [row.delivery_id, dead ? "dead" : "failed", attempts, msg, BACKOFF_MIN[Math.min(attempts - 1, BACKOFF_MIN.length - 1)]],
      );
      await ctx.db.query("UPDATE notification_channels SET last_error = $2, last_error_at = now() WHERE id = $1", [row.id, msg]);
      log("warn", "alert delivery failed", { channel: row.id, kind: row.kind, attempts, error: msg });
      failed++;
    }
  }
  return { sent, failed };
}

interface AlertMsg { id: string; org_id: string; org_name: string; kind: string; severity: string; title: string; detail: string; agent_name: string | null; occurrences: number; created_at: string | Date }

async function send(ctx: Ctx, channel: { kind: string; target_enc: string }, a: AlertMsg) {
  const target = open(ctx.config, channel.target_enc);
  const link = `${ctx.config.APP_URL.replace(/\/$/, "")}/alerts`;
  const sev = a.severity.toUpperCase();
  if (channel.kind === "slack") {
    if (!SLACK_RE.test(target)) throw new Error("The saved Slack address is not a Slack webhook.");
    const emoji = a.severity === "high" ? ":red_circle:" : a.severity === "medium" ? ":large_orange_circle:" : ":white_circle:";
    const body = {
      text: `${sev}: ${a.title}`,
      blocks: [
        { type: "section", text: { type: "mrkdwn", text: `${emoji} *${escSlack(a.title)}*\n${escSlack(a.detail || "")}` } },
        { type: "context", elements: [{ type: "mrkdwn", text: `*${sev}* · ${escSlack(a.org_name)}${a.agent_name ? ` · agent ${escSlack(a.agent_name)}` : ""}${a.occurrences > 1 ? ` · ${a.occurrences} times` : ""}` }] },
        { type: "actions", elements: [{ type: "button", text: { type: "plain_text", text: "Open in Heimdall" }, url: link }] },
      ],
    };
    const r = await (ctx.fetch ?? fetch)(target, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), redirect: "error", signal: AbortSignal.timeout(8000) });
    if (!r.ok) throw new Error(`Slack answered ${r.status}${r.status === 404 || r.status === 403 ? " (the webhook may have been removed)" : ""}`);
    return;
  }
  const to = target.split(",").filter(Boolean);
  const subject = `[Heimdall ${sev}] ${a.title}`.slice(0, 200);
  const text = `${a.title}\n\n${a.detail}\n\nSeverity: ${sev}\nOrganization: ${a.org_name}${a.agent_name ? `\nAgent: ${a.agent_name}` : ""}${a.occurrences > 1 ? `\nSeen ${a.occurrences} times` : ""}\n\nOpen in Heimdall: ${link}\n\nYou receive this because an administrator of ${a.org_name} added this address to an alert channel.`;
  const html = `<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:560px">
<p style="margin:0 0 4px;font-size:12px;font-weight:700;letter-spacing:.06em;color:${a.severity === "high" ? "#b91c1c" : a.severity === "medium" ? "#b45309" : "#4b5563"}">${sev} ALERT</p>
<h2 style="margin:0 0 12px;font-size:20px;color:#111827">${escHtml(a.title)}</h2>
<p style="margin:0 0 16px;color:#374151">${escHtml(a.detail)}</p>
<p style="margin:0 0 16px;color:#6b7280;font-size:13px">${escHtml(a.org_name)}${a.agent_name ? ` · agent ${escHtml(a.agent_name)}` : ""}${a.occurrences > 1 ? ` · seen ${a.occurrences} times` : ""}</p>
<p><a href="${escHtml(link)}" style="background:#0f766e;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;display:inline-block">Open in Heimdall</a></p>
<p style="color:#9ca3af;font-size:12px">You receive this because an administrator of ${escHtml(a.org_name)} added this address to an alert channel.</p></div>`;
  await mailer(ctx)({ to, subject, text, html });
}

let transport: { sendMail: (o: any) => Promise<unknown> } | null = null;
function mailer(ctx: Ctx) {
  if (ctx.sendMail) return ctx.sendMail;
  if (!ctx.config.SMTP_URL) {
    return async () => {
      throw new Error("Email is not set up on this server (SMTP_URL).");
    };
  }
  return async (m: { to: string[]; subject: string; text: string; html: string }) => {
    if (!transport) {
      const nodemailer = (await import("nodemailer")).default;
      transport = nodemailer.createTransport(ctx.config.SMTP_URL);
    }
    await transport.sendMail({ from: ctx.config.EMAIL_FROM, to: m.to, subject: m.subject, text: m.text, html: m.html });
  };
}

const escHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const escSlack = (s: string) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]!);

