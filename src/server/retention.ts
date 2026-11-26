import type { Db } from "./db.js";
import { audit } from "./services/core.js";
import { log } from "./log.js";

const count = async (db: Db, sql: string, params: unknown[] = []) => (await db.query<{ n: number }>(`WITH d AS (${sql} RETURNING 1) SELECT count(*)::int AS n FROM d`, params))[0].n;

/**
 * Bounded retention. Per organization: action records (and their decisions, approvals and outcomes via cascade),
 * observations and closed alerts older than retention_days; audit entries older than audit_retention_days.
 * Open alerts and pending approvals are never removed by age alone (minimum retention is 7 days, approvals expire in <= 24h).
 */
export async function runRetention(db: Db) {
  const totals = { actions: 0, observations: 0, alerts: 0, audit: 0, sessions: 0, approvals_expired: 0 };
  totals.approvals_expired = await count(db, "UPDATE approvals SET status = 'expired' WHERE status = 'pending' AND expires_at <= now()");
  const orgs = await db.query<{ id: string; retention_days: number; audit_retention_days: number }>("SELECT id, retention_days, audit_retention_days FROM organizations");
  for (const o of orgs) {
    totals.actions += await count(db, "DELETE FROM action_requests WHERE org_id = $1 AND created_at < now() - make_interval(days => $2::int)", [o.id, o.retention_days]);
    totals.observations += await count(db, "DELETE FROM observed_events WHERE org_id = $1 AND created_at < now() - make_interval(days => $2::int)", [o.id, o.retention_days]);
    totals.alerts += await count(db, "DELETE FROM alerts WHERE org_id = $1 AND status <> 'open' AND last_seen_at < now() - make_interval(days => $2::int)", [o.id, o.retention_days]);
    totals.audit += await count(db, "DELETE FROM audit_entries WHERE org_id = $1 AND created_at < now() - make_interval(days => $2::int)", [o.id, o.audit_retention_days]);
  }
  totals.audit += await count(db, "DELETE FROM audit_entries WHERE org_id IS NULL AND created_at < now() - interval '365 days'");
  totals.sessions = await count(db, "DELETE FROM sessions WHERE expires_at < now() - interval '1 day' OR revoked_at < now() - interval '1 day'");
  await audit(db, { orgId: null, actorType: "system", action: "retention.run", metadata: totals });
  log("info", "retention run complete", totals);
  return totals;
}
