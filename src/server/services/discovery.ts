/**
 * Automatic discovery (docs/DISCOVERY.md). Each added computer reports the AI tools, agents and automations it finds. For
 * tools Heimdall can sit in front of (MCP clients, Claude Code), an agent is created with the organization's automatic policy
 * and a key handed to that computer, so protection starts without anyone registering anything. Tools it can see but not
 * control raise one "unprotected" alert each, so nothing is silently missed.
 */
import { z } from "zod";
import { POLICY_EXAMPLES, type PolicyDocument } from "../../shared/policy.js";
import { PREVIOUS_AUTO_POLICIES, STANDARD_POLICY } from "../../shared/standard-policy.js";
import { newIntegrationKey } from "../security.js";
import { audit, raiseAlert, type Ctx } from "./core.js";
import { docHash, requireRole } from "./admin.js";
import type { DeviceAuth } from "./devices.js";
import type { Queryable } from "../db.js";

export const AUTO_POLICY_NAME = "Recommended for AI tools (automatic)";
/** Standard protection (src/shared/standard-policy.ts): the same lines the companion holds when it is offline. */
export const AUTO_POLICY: PolicyDocument = STANDARD_POLICY;
void POLICY_EXAMPLES;

const KINDS = ["mcp_client", "coding_agent", "ai_app", "local_model", "agent_script", "automation"] as const;
export const discoverySchema = z.object({
  items: z.array(z.object({
    key: z.string().regex(/^[a-z0-9][a-z0-9:_.-]{0,79}$/),
    kind: z.enum(KINDS),
    product: z.string().trim().min(1).max(80),
    detail: z.string().max(200).default(""),
    protectable: z.boolean(),
    protection: z.enum(["protected", "restart_needed", "unprotected", "not_possible", "off"]),
    running: z.boolean().default(false),
    /** The computer has no key for this tool (new, or its stored key was lost). */
    needs_key: z.boolean().default(false),
  }).strict()).max(200),
}).strict();

async function ensureAutoPolicy(q: Queryable, orgId: string): Promise<string> {
  const [p] = await q.query<{ id: string; current_version: number }>("SELECT id, current_version FROM policies WHERE org_id = $1 AND name = $2", [orgId, AUTO_POLICY_NAME]);
  if (p) {
    await upgradeLegacyAutoPolicy(q, orgId, p.id, p.current_version);
    return p.id;
  }
  const [n] = await q.query<{ id: string }>("INSERT INTO policies (org_id, name, description) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING id", [orgId, AUTO_POLICY_NAME, "Created automatically for AI tools found on your computers. Edit it like any policy."]);
  if (!n) return ensureAutoPolicy(q, orgId);
  await q.query("INSERT INTO policy_versions (policy_id, org_id, version, document, document_hash) VALUES ($1,$2,1,$3::jsonb,$4)", [n.id, orgId, JSON.stringify(AUTO_POLICY), docHash(AUTO_POLICY)]);
  await audit(q, { orgId, actorType: "system", actorId: null, action: "policy.created", targetType: "policy", targetId: n.id, metadata: { name: AUTO_POLICY_NAME, automatic: true } });
  return n.id;
}

/**
 * The first automatic policy let nearly everything through. If an organization never edited it, move it to Standard protection
 * as a new version (the old one stays in the history). Edited policies are left exactly as their owners wrote them.
 */
export async function upgradeLegacyAutoPolicy(q: Queryable, orgId: string, policyId: string, currentVersion: number) {
  const [cur] = await q.query<{ document_hash: string }>("SELECT document_hash FROM policy_versions WHERE policy_id = $1 AND version = $2", [policyId, currentVersion]);
  if (!cur || !PREVIOUS_AUTO_POLICIES.some((p) => docHash(p) === cur.document_hash)) return false;
  const next = currentVersion + 1;
  await q.query("INSERT INTO policy_versions (policy_id, org_id, version, document, document_hash) VALUES ($1,$2,$3,$4::jsonb,$5) ON CONFLICT DO NOTHING", [policyId, orgId, next, JSON.stringify(AUTO_POLICY), docHash(AUTO_POLICY)]);
  await q.query("UPDATE policies SET current_version = $3, description = $4, updated_at = now() WHERE id = $1 AND org_id = $2 AND current_version = $5", [policyId, orgId, next, "Standard protection for AI tools found on your computers. Edit it like any policy.", currentVersion]);
  await audit(q, { orgId, actorType: "system", actorId: null, action: "policy.updated", targetType: "policy", targetId: policyId, metadata: { version: next, previous_version: currentVersion, reason: "upgraded to Standard protection" } });
  return true;
}

/** At start-up: every organization still on the first automatic policy moves to Standard protection. */
export async function upgradeAllLegacyAutoPolicies(q: Queryable) {
  const rows = await q.query<{ id: string; org_id: string; current_version: number }>("SELECT id, org_id, current_version FROM policies WHERE name = $1", [AUTO_POLICY_NAME]);
  let n = 0;
  for (const r of rows) if (await upgradeLegacyAutoPolicy(q, r.org_id, r.id, r.current_version)) n++;
  return n;
}

async function createAgent(q: Queryable, orgId: string, name: string, policyId: string, description: string) {
  for (let i = 1; i <= 50; i++) {
    const n = (i === 1 ? name : `${name} (${i})`).slice(0, 120);
    const [a] = await q.query<{ id: string; name: string }>(
      `INSERT INTO agents (org_id, name, description, environment, integration_type, policy_id, enforcement_mode)
       VALUES ($1,$2,$3,'production','auto_discovered',$4,'enforce') ON CONFLICT DO NOTHING RETURNING id, name`,
      [orgId, n, description.slice(0, 1000), policyId],
    );
    if (a) return a;
  }
  throw new Error("could not name the agent");
}

async function issueKey(q: Queryable, orgId: string, agentId: string) {
  await q.query("UPDATE integration_credentials SET revoked_at = now() WHERE agent_id = $1 AND revoked_at IS NULL AND name = 'Added automatically'", [agentId]);
  const k = newIntegrationKey();
  await q.query(
    "INSERT INTO integration_credentials (org_id, agent_id, name, prefix, secret_hash, scopes) VALUES ($1,$2,'Added automatically',$3,$4,ARRAY['actions','events']::text[])",
    [orgId, agentId, k.prefix, k.hash],
  );
  return k.key;
}

/** A computer reports what it found. Returns keys for tools it should start protecting, and whether to protect at all. */
export async function reportDiscovery(ctx: Ctx, auth: DeviceAuth, body: z.infer<typeof discoverySchema>) {
  return ctx.db.tx(async (q) => {
    const [o] = await q.query<{ auto_protect: boolean }>("SELECT auto_protect FROM organizations WHERE id = $1", [auth.orgId]);
    const keys: Array<{ key: string; agent_id: string; api_key: string }> = [];
    let policyId: string | null = null;
    const seen: string[] = [];
    for (const it of body.items) {
      seen.push(it.key);
      const [prev] = await q.query<any>("SELECT * FROM discovered_tools WHERE device_id = $1 AND key = $2 FOR UPDATE", [auth.deviceId, it.key]);
      let agentId: string | null = prev?.agent_id ?? null;
      if (agentId) {
        const [a] = await q.query<{ status: string }>("SELECT status FROM agents WHERE id = $1", [agentId]);
        if (!a || a.status !== "active") agentId = a ? agentId : null; // a revoked agent stays revoked: an admin turned it off
      }
      if (o.auto_protect && it.protectable && (!agentId || it.needs_key)) {
        const [still] = agentId ? await q.query<{ status: string }>("SELECT status FROM agents WHERE id = $1", [agentId]) : [];
        if (!agentId) {
          policyId ??= await ensureAutoPolicy(q, auth.orgId);
          const a = await createAgent(q, auth.orgId, `${it.product} on ${auth.device.name}`, policyId, `Found automatically on ${auth.device.name}${it.detail ? ` (${it.detail})` : ""}.`);
          agentId = a.id;
          await audit(q, { orgId: auth.orgId, actorType: "system", actorId: null, action: "agent.discovered", targetType: "agent", targetId: a.id, metadata: { product: it.product, kind: it.kind, device: auth.device.name, device_id: auth.deviceId } });
          keys.push({ key: it.key, agent_id: agentId, api_key: await issueKey(q, auth.orgId, agentId) });
        } else if (still?.status === "active") {
          keys.push({ key: it.key, agent_id: agentId, api_key: await issueKey(q, auth.orgId, agentId) });
        }
      }
      await q.query(
        `INSERT INTO discovered_tools (org_id, device_id, key, kind, product, detail, protectable, protection, running, agent_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (device_id, key) DO UPDATE SET kind = EXCLUDED.kind, product = EXCLUDED.product, detail = EXCLUDED.detail, protectable = EXCLUDED.protectable,
           protection = EXCLUDED.protection, running = EXCLUDED.running, agent_id = COALESCE(EXCLUDED.agent_id, discovered_tools.agent_id), last_seen_at = now()`,
        [auth.orgId, auth.deviceId, it.key, it.kind, it.product, it.detail, it.protectable, it.protection, it.running, agentId],
      );
      // Something with AI on this computer that Heimdall cannot stand in front of: say so, once.
      if (!prev && !it.protectable && it.protection !== "protected" && (it.kind === "agent_script" || it.kind === "automation")) {
        await raiseAlert(q, {
          orgId: auth.orgId, kind: "unprotected_agent", severity: "medium",
          title: `Unprotected AI agent on ${auth.device.name}: ${it.product}`,
          detail: `${it.detail || it.product} was found running. Heimdall lists it but cannot block its actions. Add the Heimdall SDK to it (two lines) to protect it.`,
          dedupeKey: `unprotected:${auth.deviceId}:${it.key}`,
        });
      }
    }
    await q.query("UPDATE discovered_tools SET running = false WHERE device_id = $1 AND NOT (key = ANY($2::text[]))", [auth.deviceId, seen]);
    return { auto_protect: o.auto_protect, keys };
  });
}

export async function listDiscovered(ctx: Ctx, userId: string, orgId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const items = await ctx.db.query<any>(
    `SELECT t.id, t.key, t.kind, t.product, t.detail, t.protectable, t.protection, t.running, t.first_seen_at, t.last_seen_at,
            d.id AS device_id, d.name AS device_name, a.id AS agent_id, a.name AS agent_name, a.status AS agent_status
       FROM discovered_tools t JOIN devices d ON d.id = t.device_id LEFT JOIN agents a ON a.id = t.agent_id
      WHERE t.org_id = $1 AND d.status = 'active' ORDER BY t.protectable DESC, t.product, d.name LIMIT 500`,
    [orgId],
  );
  const [o] = await ctx.db.query<{ auto_protect: boolean }>("SELECT auto_protect FROM organizations WHERE id = $1", [orgId]);
  return { auto_protect: o.auto_protect, items };
}

export const autoProtectSchema = z.object({ auto_protect: z.boolean() }).strict();
export async function setAutoProtect(ctx: Ctx, userId: string, orgId: string, input: z.infer<typeof autoProtectSchema>) {
  await requireRole(ctx.db, userId, orgId, "admin");
  await ctx.db.query("UPDATE organizations SET auto_protect = $2 WHERE id = $1", [orgId, input.auto_protect]);
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "org.auto_protect_updated", targetType: "organization", targetId: orgId, metadata: input });
  return input;
}
