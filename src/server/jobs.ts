/**
 * Scheduled jobs in one call, for hosts with no always-on process (Vercel). A scheduler calls /api/cron/tick every 15-30 minutes;
 * alert delivery also runs straight after each request that can raise one (see vercel.ts). Every job is idempotent and leases
 * its work, so overlapping ticks are safe.
 */
import type { Db } from "./db.js";
import { log } from "./log.js";
import { runRetention } from "./retention.js";
import { sweepDevices } from "./services/devices.js";
import { dispatchAlerts } from "./services/notify.js";
import { dispatchPushes } from "./services/device-setup.js";
import type { Ctx } from "./services/core.js";

/** Claims a job for this period: true when it last ran more than `everyMinutes` ago (and records this run). */
export async function due(db: Db, name: string, everyMinutes: number): Promise<boolean> {
  const rows = await db.query(
    `INSERT INTO job_runs (name, last_at) VALUES ($1, now())
     ON CONFLICT (name) DO UPDATE SET last_at = now() WHERE job_runs.last_at < now() - make_interval(mins => $2::int)
     RETURNING name`,
    [name, everyMinutes],
  );
  return rows.length > 0;
}

export async function deliver(ctx: Ctx) {
  const out: Record<string, string> = {};
  for (const [name, fn] of [
    ["alerts", () => dispatchAlerts(ctx)],
    ["push", () => dispatchPushes(ctx)],
  ] as const) {
    try {
      await fn();
      out[name] = "ok";
    } catch (e) {
      out[name] = "failed";
      log("error", `${name} delivery failed`, { error: (e as Error).message });
    }
  }
  return out;
}

export async function tick(ctx: Ctx, opts: { retentionMinutes?: number } = {}) {
  const ran: Record<string, string> = await deliver(ctx);
  try {
    if (await due(ctx.db, "device-sweep", 4)) {
      await sweepDevices(ctx.db);
      ran.devices = "ok";
    }
  } catch (e) {
    ran.devices = "failed";
    log("error", "device sweep failed", { error: (e as Error).message });
  }
  try {
    if (await due(ctx.db, "retention", Math.max(60, opts.retentionMinutes ?? 1440) - 5)) {
      await runRetention(ctx.db);
      ran.retention = "ok";
    }
  } catch (e) {
    ran.retention = "failed";
    log("error", "retention failed", { error: (e as Error).message });
  }
  return ran;
}
