import { notFound } from "../errors.js";
import { agentView, escapeLike, pageParams, type AgentRow, type Ctx } from "./core.js";
import { requirePermission, requireRole } from "./admin.js";

type Q = Record<string, string | undefined>;
const oneOf = (v: string | undefined, allowed: readonly string[]) => (v && allowed.includes(v) ? v : undefined);

/** Where the claim stands, in terms an administrator can trust. "blocked" only when the adapter confirmed non-execution. */
export const ACTION_STATE_SQL = `
  CASE
    WHEN o.status = 'refused' AND o.enforcement_confirmed THEN 'blocked_confirmed'
    WHEN o.status = 'succeeded' THEN 'executed'
    WHEN o.status = 'failed' THEN 'execution_failed'
    WHEN o.status = 'claimed' AND o.claimed_at < now() - interval '10 minutes' THEN 'claimed_no_outcome'
    WHEN o.status = 'claimed' THEN 'claimed'
    WHEN d.decision = 'deny' THEN 'denied_unconfirmed'
    WHEN d.decision = 'require_approval' AND ap.status = 'rejected' THEN 'approval_rejected'
    WHEN d.decision = 'require_approval' AND ap.status = 'pending' AND ap.expires_at > now() THEN 'awaiting_approval'
    WHEN d.decision = 'require_approval' AND ap.status = 'approved' AND ap.consumed_at IS NULL AND ap.grant_expires_at > now() THEN 'approved_unused'
    WHEN d.decision = 'require_approval' THEN 'approval_expired'
    ELSE 'authorized_not_executed'
  END`;

const ACTION_FROM = `
  FROM action_requests ar
  JOIN authorization_decisions d ON d.action_request_id = ar.id
  JOIN agents ag ON ag.id = ar.agent_id
  LEFT JOIN approvals ap ON ap.action_request_id = ar.id
  LEFT JOIN execution_outcomes o ON o.action_request_id = ar.id`;

const ACTION_COLS = `
  ar.id, ar.request_id, ar.agent_id, ag.name AS agent_name, ar.tool, ar.operation, ar.resource, ar.destination, ar.data_classification,
  ar.is_demo, ar.source, ar.created_at, d.decision, d.policy_decision, d.enforcement_mode, d.reason_code, d.explanation, d.policy_version, d.matched_rule_id,
  ${ACTION_STATE_SQL} AS state, o.status AS outcome_status, o.enforcement_confirmed, o.error_code, o.claimed_at, o.reported_at`;

export async function listActions(ctx: Ctx, userId: string, orgId: string, query: Q) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const { limit, offset } = pageParams(query);
  const where = ["ar.org_id = $1"];
  const params: unknown[] = [orgId];
  const add = (sql: string, v: unknown) => {
    params.push(v);
    where.push(sql.replaceAll("?", "$" + params.length));
  };
  const agent = query.agent_id && /^[0-9a-f-]{36}$/i.test(query.agent_id) ? query.agent_id : undefined;
  if (agent) add("ar.agent_id = ?", agent);
  const dec = oneOf(query.decision, ["allow", "deny", "require_approval"]);
  if (dec) add("d.decision = ?", dec);
  const op = oneOf(query.operation, ["read", "create", "update", "delete", "external_transfer", "command_execution"]);
  if (op) add("ar.operation = ?", op);
  if (query.demo === "true" || query.demo === "false") add("ar.is_demo = ?", query.demo === "true");
  if (query.q?.trim()) add("(ar.tool ILIKE ? OR ar.resource ILIKE ? OR ar.request_id ILIKE ? OR ag.name ILIKE ?)", `%${escapeLike(query.q.trim().slice(0, 100))}%`);
  const sql = where.join(" AND ");
  const state = oneOf(query.state, ["blocked_confirmed", "executed", "execution_failed", "claimed", "claimed_no_outcome", "denied_unconfirmed", "awaiting_approval", "approved_unused", "approval_rejected", "approval_expired", "authorized_not_executed"]);
  const outer = state ? `WHERE state = '${state}'` : "";
  const base = `SELECT ${ACTION_COLS} ${ACTION_FROM} WHERE ${sql}`;
  const [{ n }] = await ctx.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM (${base}) t ${outer}`, params);
  const items = await ctx.db.query(`SELECT * FROM (${base}) t ${outer} ORDER BY created_at DESC, id LIMIT ${limit} OFFSET ${offset}`, params);
  return { items, total: n, limit, offset };
}

export async function getActionDetail(ctx: Ctx, userId: string, orgId: string, id: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw notFound("Action");
  const [row] = await ctx.db.query<any>(
    `SELECT ${ACTION_COLS}, ar.args_summary, ar.action_digest, ar.adapter_name, ar.adapter_version, ar.requested_at,
            d.expires_at AS decision_expires_at, d.classification_level, d.classification_source, o.detail AS outcome_detail, o.claim_policy_version,
            ap.id AS approval_id, ap.status AS approval_status, ap.expires_at AS approval_expires_at, ap.decided_at, ap.decision_note,
            ap.required_role, ap.consumed_at AS approval_consumed_at, du.name AS decided_by_name
       ${ACTION_FROM} LEFT JOIN users du ON du.id = ap.decided_by
      WHERE ar.id = $1 AND ar.org_id = $2`,
    [id, orgId],
  );
  if (!row) throw notFound("Action");
  return row;
}

export async function listAgents(ctx: Ctx, userId: string, orgId: string, query: Q) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const { limit, offset } = pageParams(query);
  const where = ["a.org_id = $1"];
  const params: unknown[] = [orgId];
  const env = oneOf(query.environment, ["development", "staging", "production"]);
  if (env) {
    params.push(env);
    where.push(`a.environment = $${params.length}`);
  }
  const st = oneOf(query.status, ["active", "revoked"]);
  if (st) {
    params.push(st);
    where.push(`a.status = $${params.length}`);
  }
  if (query.q?.trim()) {
    params.push(`%${escapeLike(query.q.trim().slice(0, 100))}%`);
    where.push(`(a.name ILIKE $${params.length} OR a.description ILIKE $${params.length})`);
  }
  const w = where.join(" AND ");
  const [{ n }] = await ctx.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM agents a WHERE ${w}`, params);
  const rows = await ctx.db.query<AgentRow & { policy_name: string | null }>(
    `SELECT a.*, p.name AS policy_name FROM agents a LEFT JOIN policies p ON p.id = a.policy_id AND p.org_id = a.org_id WHERE ${w} ORDER BY a.created_at DESC LIMIT ${limit} OFFSET ${offset}`,
    params,
  );
  let items = rows.map((r) => ({ ...agentView(r), policy_name: r.policy_name }));
  const cs = oneOf(query.connection, ["revoked", "not_connected", "connected", "monitoring", "reporting_only", "enforcing"]);
  if (cs) items = items.filter((i) => i.connection.state === cs); // derived state; page-local filter
  return { items, total: n, limit, offset };
}

export async function getAgent(ctx: Ctx, userId: string, orgId: string, agentId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  if (!/^[0-9a-f-]{36}$/i.test(agentId)) throw notFound("Agent");
  const [a] = await ctx.db.query<AgentRow & { policy_name: string | null }>(
    `SELECT a.*, p.name AS policy_name FROM agents a LEFT JOIN policies p ON p.id = a.policy_id AND p.org_id = a.org_id WHERE a.id = $1 AND a.org_id = $2`,
    [agentId, orgId],
  );
  if (!a) throw notFound("Agent");
  const [counts] = await ctx.db.query<any>(
    `SELECT count(*) FILTER (WHERE d.decision = 'allow')::int AS allowed, count(*) FILTER (WHERE d.decision = 'deny')::int AS denied,
            count(*) FILTER (WHERE d.decision = 'require_approval')::int AS approvals, count(*)::int AS total
       FROM authorization_decisions d WHERE d.agent_id = $1 AND d.created_at > now() - interval '7 days'`,
    [agentId],
  );
  const credentials = await ctx.db.query(
    `SELECT id, name, prefix, scopes, created_at, last_used_at, revoked_at FROM integration_credentials WHERE agent_id = $1 AND org_id = $2 ORDER BY created_at DESC`,
    [agentId, orgId],
  );
  const [executor] = await ctx.db.query(
    "SELECT reported_at, executor_version, roots, egress_enabled, mode, cache_expires_at, queued_events FROM executor_status WHERE agent_id = $1 AND org_id = $2",
    [agentId, orgId],
  );
  return { ...agentView(a), policy_name: a.policy_name, last_7_days: counts, credentials, executor: executor ?? null };
}

export async function listCredentials(ctx: Ctx, userId: string, orgId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  return ctx.db.query(
    `SELECT c.id, c.name, c.prefix, c.scopes, c.created_at, c.last_used_at, c.revoked_at, c.agent_id, a.name AS agent_name, a.environment
       FROM integration_credentials c JOIN agents a ON a.id = c.agent_id WHERE c.org_id = $1 ORDER BY c.created_at DESC LIMIT 200`,
    [orgId],
  );
}

export async function listPolicies(ctx: Ctx, userId: string, orgId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  return ctx.db.query(
    `SELECT p.id, p.name, p.description, p.current_version, p.updated_at, (SELECT count(*)::int FROM agents a WHERE a.policy_id = p.id AND a.status = 'active') AS agent_count
       FROM policies p WHERE p.org_id = $1 ORDER BY p.name`,
    [orgId],
  );
}

export async function getPolicy(ctx: Ctx, userId: string, orgId: string, policyId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  if (!/^[0-9a-f-]{36}$/i.test(policyId)) throw notFound("Policy");
  const [p] = await ctx.db.query<any>("SELECT id, name, description, current_version, updated_at FROM policies WHERE id = $1 AND org_id = $2", [policyId, orgId]);
  if (!p) throw notFound("Policy");
  const versions = await ctx.db.query(
    `SELECT v.version, v.document, v.created_at, u.name AS created_by_name FROM policy_versions v LEFT JOIN users u ON u.id = v.created_by WHERE v.policy_id = $1 ORDER BY v.version DESC LIMIT 20`,
    [policyId],
  );
  const agents = await ctx.db.query("SELECT id, name, environment, status FROM agents WHERE policy_id = $1 AND org_id = $2 ORDER BY name", [policyId, orgId]);
  return { ...p, versions, agents };
}

export async function listApprovals(ctx: Ctx, userId: string, orgId: string, query: Q) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const { limit, offset } = pageParams(query);
  const status = oneOf(query.status, ["pending", "approved", "rejected", "expired"]);
  // 'expired' also covers pending requests whose time ran out.
  const cond =
    status === "pending" ? "ap.status = 'pending' AND ap.expires_at > now()"
    : status === "expired" ? "(ap.status = 'expired' OR (ap.status = 'pending' AND ap.expires_at <= now()))"
    : status ? `ap.status = '${status}'` : "TRUE";
  const [{ n }] = await ctx.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM approvals ap WHERE ap.org_id = $1 AND ${cond}`, [orgId]);
  const items = await ctx.db.query(
    `SELECT ap.id, ap.status, ap.requested_at, ap.expires_at, ap.grant_expires_at, ap.decided_at, ap.decision_note, ap.required_role, ap.consumed_at,
            (ap.status = 'pending' AND ap.expires_at <= now()) AS timed_out, ap.policy_version,
            ar.id AS action_id, ar.tool, ar.operation, ar.resource, ar.destination, ar.data_classification, ar.args_summary, ar.is_demo,
            ag.id AS agent_id, ag.name AS agent_name, ag.environment, d.explanation, d.reason_code, du.name AS decided_by_name
       FROM approvals ap JOIN action_requests ar ON ar.id = ap.action_request_id JOIN agents ag ON ag.id = ap.agent_id
       JOIN authorization_decisions d ON d.action_request_id = ar.id LEFT JOIN users du ON du.id = ap.decided_by
      WHERE ap.org_id = $1 AND ${cond} ORDER BY ap.requested_at DESC LIMIT ${limit} OFFSET ${offset}`,
    [orgId],
  );
  return { items, total: n, limit, offset };
}

export async function listAlerts(ctx: Ctx, userId: string, orgId: string, query: Q) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const { limit, offset } = pageParams(query);
  const status = oneOf(query.status, ["open", "acknowledged", "resolved"]);
  const sev = oneOf(query.severity, ["low", "medium", "high"]);
  const params: unknown[] = [orgId];
  const where = ["al.org_id = $1"];
  if (status) {
    params.push(status);
    where.push(`al.status = $${params.length}`);
  }
  if (sev) {
    params.push(sev);
    where.push(`al.severity = $${params.length}`);
  }
  const w = where.join(" AND ");
  const [{ n }] = await ctx.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM alerts al WHERE ${w}`, params);
  const items = await ctx.db.query(
    `SELECT al.*, ag.name AS agent_name, u.name AS handled_by_name FROM alerts al LEFT JOIN agents ag ON ag.id = al.agent_id LEFT JOIN users u ON u.id = al.handled_by
      WHERE ${w} ORDER BY (al.status = 'resolved'), al.last_seen_at DESC LIMIT ${limit} OFFSET ${offset}`,
    params,
  );
  return { items, total: n, limit, offset };
}

export async function listAudit(ctx: Ctx, userId: string, orgId: string, query: Q) {
  await requirePermission(ctx.db, userId, orgId, "audit.read");
  const { limit, offset } = pageParams(query, 50);
  const params: unknown[] = [orgId];
  let w = "e.org_id = $1";
  if (query.q?.trim()) {
    params.push(`%${escapeLike(query.q.trim().slice(0, 100))}%`);
    w += ` AND (e.action ILIKE $2 OR e.target_id ILIKE $2)`;
  }
  const [{ n }] = await ctx.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM audit_entries e WHERE ${w}`, params);
  const items = await ctx.db.query(
    `SELECT e.id, e.actor_type, e.actor_id, u.name AS actor_name, e.action, e.target_type, e.target_id, e.metadata, e.created_at
       FROM audit_entries e LEFT JOIN users u ON e.actor_type = 'user' AND u.id::text = e.actor_id WHERE ${w} ORDER BY e.created_at DESC, e.id LIMIT ${limit} OFFSET ${offset}`,
    params,
  );
  return { items, total: n, limit, offset };
}

export async function listObservations(ctx: Ctx, userId: string, orgId: string, query: Q) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const { limit, offset } = pageParams(query);
  const [{ n }] = await ctx.db.query<{ n: number }>("SELECT count(*)::int AS n FROM observed_events WHERE org_id = $1", [orgId]);
  const items = await ctx.db.query(
    `SELECT e.id, e.event_type, e.tool, e.operation, e.resource, e.summary, e.is_demo, e.occurred_at, e.created_at, a.name AS agent_name
       FROM observed_events e JOIN agents a ON a.id = e.agent_id WHERE e.org_id = $1 ORDER BY e.created_at DESC LIMIT ${limit} OFFSET ${offset}`,
    [orgId],
  );
  return { items, total: n, limit, offset };
}

/** Every figure is computed from stored rows. Nothing here is estimated or scored. */
export async function overview(ctx: Ctx, userId: string, orgId: string, hours = 24) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const h = Math.min(24 * 30, Math.max(1, hours));
  const [c] = await ctx.db.query<any>(
    `SELECT count(*) FILTER (WHERE d.decision = 'allow')::int AS allowed,
            count(*) FILTER (WHERE d.decision = 'deny')::int AS denied,
            count(*) FILTER (WHERE d.decision = 'require_approval')::int AS needs_approval,
            count(*) FILTER (WHERE d.policy_decision <> 'allow' AND d.decision = 'allow')::int AS monitor_would_block
       FROM authorization_decisions d WHERE d.org_id = $1 AND d.created_at > now() - make_interval(hours => $2::int)`,
    [orgId, h],
  );
  const [x] = await ctx.db.query<any>(
    `SELECT count(*) FILTER (WHERE status = 'succeeded')::int AS succeeded, count(*) FILTER (WHERE status = 'failed')::int AS failed,
            count(*) FILTER (WHERE status = 'refused' AND enforcement_confirmed)::int AS blocked_confirmed
       FROM execution_outcomes WHERE org_id = $1 AND created_at > now() - make_interval(hours => $2::int)`,
    [orgId, h],
  );
  const [pa] = await ctx.db.query<{ n: number }>("SELECT count(*)::int AS n FROM approvals WHERE org_id = $1 AND status = 'pending' AND expires_at > now()", [orgId]);
  const [al] = await ctx.db.query<{ n: number }>("SELECT count(*)::int AS n FROM alerts WHERE org_id = $1 AND status = 'open'", [orgId]);
  const agents = await ctx.db.query<AgentRow>("SELECT * FROM agents WHERE org_id = $1", [orgId]);
  const views = agents.map(agentView);
  const by_state = { not_connected: 0, connected: 0, monitoring: 0, reporting_only: 0, enforcing: 0, revoked: 0 };
  for (const a of views) by_state[a.connection.state]++;
  const recent_agents = views
    .filter((a) => a.last_seen_at)
    .sort((a, b) => new Date(b.last_seen_at!).getTime() - new Date(a.last_seen_at!).getTime())
    .slice(0, 6)
    .map((a) => ({ id: a.id, name: a.name, environment: a.environment, last_seen_at: a.last_seen_at, connection: a.connection }));
  const recent_failures = await ctx.db.query(
    `SELECT o.id, ar.id AS action_id, ar.tool, ar.operation, ar.resource, o.error_code, o.reported_at, ag.name AS agent_name
       FROM execution_outcomes o JOIN action_requests ar ON ar.id = o.action_request_id JOIN agents ag ON ag.id = o.agent_id
      WHERE o.org_id = $1 AND o.status = 'failed' ORDER BY o.reported_at DESC LIMIT 5`,
    [orgId],
  );
  const recent_alerts = await ctx.db.query(
    `SELECT al.id, al.kind, al.severity, al.title, al.status, al.occurrences, al.last_seen_at, al.is_demo FROM alerts al WHERE al.org_id = $1 AND al.status <> 'resolved' ORDER BY al.last_seen_at DESC LIMIT 5`,
    [orgId],
  );
  const unit = h <= 48 ? "hour" : "day";
  const rows = await ctx.db.query<any>(
    `SELECT date_trunc($3, d.created_at) AS t, count(*) FILTER (WHERE d.decision = 'allow')::int AS allowed, count(*) FILTER (WHERE d.decision = 'deny')::int AS denied,
            count(*) FILTER (WHERE d.decision = 'require_approval')::int AS approval
       FROM authorization_decisions d WHERE d.org_id = $1 AND d.created_at > now() - make_interval(hours => $2::int) GROUP BY 1 ORDER BY 1`,
    [orgId, h, unit],
  );
  const step = unit === "hour" ? 3600_000 : 86400_000;
  const byT = new Map(rows.map((r: any) => [new Date(r.t).getTime(), r]));
  const end = Math.floor(Date.now() / step) * step;
  const n = Math.min(unit === "hour" ? h : Math.ceil(h / 24), 31);
  const timeline = Array.from({ length: n }, (_, i) => {
    const t = end - (n - 1 - i) * step;
    const r: any = byT.get(t);
    return { t: new Date(t).toISOString(), allowed: r?.allowed ?? 0, denied: r?.denied ?? 0, approval: r?.approval ?? 0 };
  });
  const top_denials = await ctx.db.query(
    `SELECT d.reason_code, count(*)::int AS n FROM authorization_decisions d WHERE d.org_id = $1 AND d.policy_decision = 'deny' AND d.created_at > now() - make_interval(hours => $2::int) GROUP BY 1 ORDER BY n DESC LIMIT 5`,
    [orgId, h],
  );
  return { window_hours: h, timeline, unit, top_denials, decisions: c, executions: x, pending_approvals: pa.n, open_alerts: al.n, agents: { total: views.length, by_state }, recent_agents, recent_failures, recent_alerts };
}

/**
 * Everything the Live page shows in one call: what Heimdall is watching (computers, AI tools, rules in force), what it
 * checked in the last hour, and the newest checks (only those after `since`, so the page can poll every few seconds).
 */
export async function live(ctx: Ctx, userId: string, orgId: string, query: Q) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const since = query.since && !Number.isNaN(Date.parse(query.since)) ? new Date(query.since).toISOString() : null;
  const feed = await ctx.db.query<any>(
    `SELECT ${ACTION_COLS}, ar.args_summary ${ACTION_FROM}
      WHERE ar.org_id = $1 ${since ? "AND ar.created_at > $2" : ""}
      ORDER BY ar.created_at DESC LIMIT 40`,
    since ? [orgId, since] : [orgId],
  );
  const [hour] = await ctx.db.query<any>(
    `SELECT count(*)::int AS checked,
            count(*) FILTER (WHERE d.decision = 'allow')::int AS allowed,
            count(*) FILTER (WHERE d.decision = 'deny')::int AS blocked,
            count(*) FILTER (WHERE d.decision = 'require_approval')::int AS waiting
       FROM action_requests ar JOIN authorization_decisions d ON d.action_request_id = ar.id
      WHERE ar.org_id = $1 AND ar.created_at > now() - interval '1 hour' AND NOT ar.is_demo`,
    [orgId],
  );
  const [today] = await ctx.db.query<any>(
    `SELECT count(*)::int AS checked, count(*) FILTER (WHERE d.decision = 'deny')::int AS blocked
       FROM action_requests ar JOIN authorization_decisions d ON d.action_request_id = ar.id
      WHERE ar.org_id = $1 AND ar.created_at > now() - interval '24 hours' AND NOT ar.is_demo`,
    [orgId],
  );
  const devices = await ctx.db.query<any>(
    `SELECT id, name, platform, last_heartbeat_at, status FROM devices WHERE org_id = $1 AND status = 'active' ORDER BY last_heartbeat_at DESC NULLS LAST LIMIT 50`,
    [orgId],
  );
  const tools = await ctx.db.query<any>(
    `SELECT t.key, t.kind, t.product, t.detail, t.protectable, t.protection, t.running, t.last_seen_at, t.device_id, a.id AS agent_id
       FROM discovered_tools t JOIN devices d ON d.id = t.device_id LEFT JOIN agents a ON a.id = t.agent_id
      WHERE t.org_id = $1 AND d.status = 'active' ORDER BY t.protectable DESC, t.product LIMIT 300`,
    [orgId],
  );
  const policies = await ctx.db.query<any>(
    `SELECT p.id, p.name, p.current_version, v.document,
            (SELECT count(*)::int FROM agents a WHERE a.policy_id = p.id AND a.status = 'active') AS agents
       FROM policies p JOIN policy_versions v ON v.policy_id = p.id AND v.version = p.current_version
      WHERE p.org_id = $1 AND EXISTS (SELECT 1 FROM agents a WHERE a.policy_id = p.id AND a.status = 'active')
      ORDER BY agents DESC LIMIT 10`,
    [orgId],
  );
  return {
    now: new Date().toISOString(),
    last_hour: hour, last_day: today,
    devices, tools,
    policies: policies.map((p) => ({
      id: p.id, name: p.name, version: p.current_version, agents: p.agents,
      rules: (p.document?.rules ?? []).map((r: any) => ({ id: r.id, effect: r.effect, description: r.description ?? null, operations: r.match?.operations ?? null })),
    })),
    feed,
  };
}
