/**
 * Browser guard (docs/BROWSER-GUARD.md). The person clicks "Connect this browser" in the dashboard; the Heimdall extension
 * receives a key for its own agent, held to the Browser guard policy. The extension then asks /v1/authorize before text with
 * secrets or personal data reaches an AI chat site, and checks in every few minutes so the dashboard can say it is on.
 */
import { z } from "zod";
import { BROWSER_POLICY, BROWSER_POLICY_NAME } from "../../shared/browser-policy.js";
import { newIntegrationKey } from "../security.js";
import { audit, type Ctx } from "./core.js";
import { docHash, requireRole } from "./admin.js";
import type { Queryable } from "../db.js";

export const connectSchema = z.object({ browser: z.string().trim().min(1).max(60) }).strict();

async function ensurePolicy(q: Queryable, orgId: string): Promise<string> {
  const [p] = await q.query<{ id: string }>("SELECT id FROM policies WHERE org_id = $1 AND name = $2", [orgId, BROWSER_POLICY_NAME]);
  if (p) return p.id;
  const [n] = await q.query<{ id: string }>("INSERT INTO policies (org_id, name, description) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING id",
    [orgId, BROWSER_POLICY_NAME, "Created automatically for the Heimdall browser extension. Edit it like any policy."]);
  if (!n) return ensurePolicy(q, orgId);
  await q.query("INSERT INTO policy_versions (policy_id, org_id, version, document, document_hash) VALUES ($1,$2,1,$3::jsonb,$4)",
    [n.id, orgId, JSON.stringify(BROWSER_POLICY), docHash(BROWSER_POLICY)]);
  await audit(q, { orgId, actorType: "system", actorId: null, action: "policy.created", targetType: "policy", targetId: n.id, metadata: { name: BROWSER_POLICY_NAME, automatic: true } });
  return n.id;
}

export async function connect(ctx: Ctx, userId: string, orgId: string, input: z.infer<typeof connectSchema>) {
  return ctx.db.tx(async (q) => {
    await requireRole(q, userId, orgId, "viewer");
    const [u] = await q.query<{ name: string }>("SELECT name FROM users WHERE id = $1", [userId]);
    const policyId = await ensurePolicy(q, orgId);
    const base = `Browser guard: ${input.browser} (${(u?.name || "member").split(" ")[0]})`;
    let agent: { id: string; name: string } | undefined;
    for (let i = 1; i <= 50 && !agent; i++) {
      [agent] = await q.query<{ id: string; name: string }>(
        `INSERT INTO agents (org_id, name, description, environment, integration_type, policy_id, enforcement_mode, created_by)
         VALUES ($1,$2,$3,'production','browser_extension',$4,'enforce',$5) ON CONFLICT DO NOTHING RETURNING id, name`,
        [orgId, (i === 1 ? base : `${base} ${i}`).slice(0, 120), "Checks what is pasted, typed or uploaded into AI chat websites in this browser.", policyId, userId]);
    }
    if (!agent) throw new Error("could not name the browser agent");
    const k = newIntegrationKey();
    await q.query("INSERT INTO integration_credentials (org_id, agent_id, name, prefix, secret_hash, scopes, created_by) VALUES ($1,$2,'Browser extension',$3,$4,ARRAY['actions','events']::text[],$5)",
      [orgId, agent.id, k.prefix, k.hash, userId]);
    await audit(q, { orgId, actorType: "user", actorId: userId, action: "browser_guard.connected", targetType: "agent", targetId: agent.id, metadata: { browser: input.browser } });
    return { agent_id: agent.id, agent_name: agent.name, api_key: k.key, api_url: ctx.config.APP_URL.replace(/\/$/, "") };
  });
}

/** Every connected browser, whether it checked in recently, and what it stopped in the last 24 hours. */
export async function status(ctx: Ctx, userId: string, orgId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const rows = await ctx.db.query<any>(
    `SELECT a.id, a.name, a.status, a.last_seen_at,
       (SELECT count(*)::int FROM action_requests r JOIN authorization_decisions d ON d.action_request_id = r.id
          WHERE r.agent_id = a.id AND r.created_at > now() - interval '24 hours') AS checked_24h,
       (SELECT count(*)::int FROM action_requests r JOIN authorization_decisions d ON d.action_request_id = r.id
          WHERE r.agent_id = a.id AND d.decision <> 'allow' AND r.created_at > now() - interval '24 hours') AS stopped_24h
     FROM agents a WHERE a.org_id = $1 AND a.integration_type = 'browser_extension' AND a.status = 'active' ORDER BY a.last_seen_at DESC NULLS LAST`, [orgId]);
  const active = rows.filter((r) => r.last_seen_at && Date.now() - new Date(r.last_seen_at).getTime() < 20 * 60_000);
  return { browsers: rows, active: active.length, webstore_url: process.env.BROWSER_GUARD_WEBSTORE_URL || null };
}
