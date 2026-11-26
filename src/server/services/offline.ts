import { z } from "zod";
import { canonicalJson } from "../../shared/action.js";
import { evaluate, normalizeResource, OPERATIONS, policyDocumentSchema, type PolicyDocument } from "../../shared/policy.js";
import { redact, redactedJsonString } from "../../shared/redact.js";
import { HttpError, notFound } from "../errors.js";
import { audit, raiseAlert, type Ctx } from "./core.js";
import type { CredentialAuth } from "./authz.js";

export const BUNDLE_FORMAT = 1;

export interface PolicyBundle {
  v: number;
  key_id: string;
  org_id: string;
  agent_id: string;
  policy_id: string | null;
  /** Monotonic per policy. Executors refuse a bundle whose version is lower than one they have already accepted. */
  policy_version: number | null;
  document: PolicyDocument | null;
  enforcement_mode: "monitor" | "enforce";
  issued_at: string;
  expires_at: string;
}

/**
 * Signed policy bundle for offline enforcement. The signature covers the canonical JSON of the whole bundle,
 * including agent/org binding, version and expiry, so a bundle cannot be replayed for another agent or extended.
 */
export async function issueBundle(ctx: Ctx, auth: CredentialAuth) {
  if (!ctx.signer) throw new HttpError(503, "SIGNING_UNAVAILABLE", "This server has no policy signing key configured, so offline bundles are unavailable");
  const [row] = await ctx.db.query<any>(
    `SELECT a.policy_id, a.enforcement_mode, p.current_version AS version, v.document
       FROM agents a LEFT JOIN policies p ON p.id = a.policy_id AND p.org_id = a.org_id
       LEFT JOIN policy_versions v ON v.policy_id = p.id AND v.version = p.current_version
      WHERE a.id = $1 AND a.org_id = $2`,
    [auth.agentId, auth.orgId],
  );
  if (!row) throw notFound("Agent");
  const issued = new Date();
  const bundle: PolicyBundle = {
    v: BUNDLE_FORMAT,
    key_id: ctx.signer.keyId,
    org_id: auth.orgId,
    agent_id: auth.agentId,
    policy_id: row.policy_id,
    policy_version: row.policy_id ? row.version : null,
    document: row.document ? policyDocumentSchema.parse(row.document) : null,
    enforcement_mode: row.enforcement_mode,
    issued_at: issued.toISOString(),
    expires_at: new Date(issued.getTime() + ctx.config.POLICY_BUNDLE_TTL_MINUTES * 60_000).toISOString(),
  };
  return { bundle, signature: ctx.signer.sign(canonicalJson(bundle)) };
}

/**
 * The agent's current policy pointer: cheap to serve, polled by fast-path executors every couple of seconds so a policy change
 * is picked up quickly. A revoked key or agent is refused by the credential check before this runs.
 */
export async function policyState(ctx: Ctx, auth: CredentialAuth) {
  const [row] = await ctx.db.query<any>(
    `SELECT a.policy_id, a.enforcement_mode, p.current_version AS version
       FROM agents a LEFT JOIN policies p ON p.id = a.policy_id AND p.org_id = a.org_id
      WHERE a.id = $1 AND a.org_id = $2`,
    [auth.agentId, auth.orgId],
  );
  if (!row) throw notFound("Agent");
  return { policy_id: row.policy_id as string | null, policy_version: row.policy_id ? (row.version as number) : null, enforcement_mode: row.enforcement_mode as "monitor" | "enforce" };
}

export const executorReportSchema = z
  .object({
    executor_version: z.string().max(32).optional(),
    roots: z.array(z.object({ label: z.string().max(80), prefix: z.string().max(200).default("") }).strict()).max(20),
    egress_enabled: z.boolean(),
    mode: z.enum(["online", "offline_cache", "degraded"]).default("online"),
    cache_expires_at: z.string().datetime().optional(),
    queued_events: z.number().int().min(0).max(100000).default(0),
  })
  .strict();

/** What an executor says about itself. It is EVIDENCE shown in the Protection Center, never proof. */
export async function reportExecutor(ctx: Ctx, auth: CredentialAuth, body: z.infer<typeof executorReportSchema>) {
  await ctx.db.query(
    `INSERT INTO executor_status (agent_id, org_id, reported_at, executor_version, roots, egress_enabled, mode, cache_expires_at, queued_events)
     VALUES ($1,$2, now(), $3, $4::jsonb, $5, $6, $7, $8)
     ON CONFLICT (agent_id) DO UPDATE SET reported_at = now(), executor_version = EXCLUDED.executor_version, roots = EXCLUDED.roots, egress_enabled = EXCLUDED.egress_enabled,
       mode = EXCLUDED.mode, cache_expires_at = EXCLUDED.cache_expires_at, queued_events = EXCLUDED.queued_events`,
    [auth.agentId, auth.orgId, body.executor_version ?? null, JSON.stringify(body.roots), body.egress_enabled, body.mode, body.cache_expires_at ?? null, body.queued_events],
  );
  return { ok: true };
}

export const offlineSyncSchema = z
  .object({
    records: z
      .array(
        z
          .object({
            request_id: z.string().regex(/^[A-Za-z0-9_.:-]{8,128}$/),
            action: z
              .object({ tool: z.string().regex(/^[a-z0-9][a-z0-9_.-]{0,63}$/), operation: z.enum(OPERATIONS), resource: z.string().min(1).max(512), destination: z.string().max(2048).optional(), args: z.record(z.string().max(100), z.unknown()).optional() })
              .strict(),
            action_digest: z.string().regex(/^[0-9a-f]{64}$/),
            decision: z.enum(["allow", "deny", "require_approval"]),
            reason_code: z.string().max(64),
            policy_version: z.number().int().nullable(),
            decided_at: z.string().datetime(),
            outcome: z.object({ status: z.enum(["succeeded", "failed", "refused"]), error_code: z.string().max(64).optional() }).strict(),
            /** offline_cache: decided while the service was unreachable. local_fast: decided in-process by the fast path. */
            source: z.enum(["offline_cache", "local_fast"]).optional(),
          })
          .strict(),
      )
      .min(1)
      .max(500),
  })
  .strict();

/**
 * Receives decisions an executor took from its cached, signed policy while the service was unreachable.
 * Each record is idempotent by request_id, marked source=offline_cache, and RE-EVALUATED here against the policy version it
 * claims to have used. A mismatch (an executor allowing something that version does not allow) raises a high-severity alert.
 */
export async function syncOffline(ctx: Ctx, auth: CredentialAuth, body: z.infer<typeof offlineSyncSchema>) {
  const results: Array<{ request_id: string; status: "recorded" | "duplicate" | "mismatch" | "rejected" }> = [];
  // A batch usually uses one or two policy versions: parse each once, not once per record.
  const docs = new Map<number | null, { doc: PolicyDocument; policyId: string } | null>();
  for (const r of body.records) {
    const source = r.source ?? "offline_cache";
    const out = await ctx.db.tx(async (q) => {
      const [existing] = await q.query("SELECT 1 FROM action_requests WHERE agent_id = $1 AND request_id = $2", [auth.agentId, r.request_id]);
      if (existing) return "duplicate" as const;
      const n = normalizeResource(r.action.resource);
      if (!n.ok) return "rejected" as const;
      // Re-evaluate against the claimed policy version of THIS agent's policy.
      if (!docs.has(r.policy_version)) {
        const [row] = await q.query<any>(
          `SELECT v.document, a.policy_id FROM agents a JOIN policy_versions v ON v.policy_id = a.policy_id AND v.org_id = a.org_id AND v.version = $3 WHERE a.id = $1 AND a.org_id = $2`,
          [auth.agentId, auth.orgId, r.policy_version],
        );
        docs.set(r.policy_version, row ? { doc: policyDocumentSchema.parse(row.document), policyId: row.policy_id } : null);
      }
      const pv = docs.get(r.policy_version) ?? null;
      let recomputed: string | null = null;
      if (pv) {
        recomputed = evaluate(pv.doc, { tool: r.action.tool, operation: r.action.operation, resource: r.action.resource, destination: r.action.destination }, { allowedInWindow: 0, hasValidApproval: false }).decision;
      }
      // Budgets are counted where the decision was made; a local budget denial is stricter than the server's view, not a mismatch.
      const budgetDeny = r.decision === "deny" && r.reason_code === "BUDGET_EXCEEDED" && recomputed === "allow";
      const mismatch = recomputed === null || (recomputed !== r.decision && !budgetDeny);
      const decidedAt = new Date(Math.min(Date.now(), new Date(r.decided_at).getTime()));
      const [ar] = await q.query<{ id: string }>(
        `INSERT INTO action_requests (org_id, agent_id, credential_id, request_id, tool, operation, resource, destination, args_summary, action_digest, is_demo, source, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,false,$12,$11) RETURNING id`,
        [auth.orgId, auth.agentId, auth.credentialId, r.request_id, r.action.tool, r.action.operation, n.value, r.action.destination ? String(redact(r.action.destination)).slice(0, 512) : null, redactedJsonString(r.action.args ?? {}), r.action_digest, decidedAt, source],
      );
      await q.query(
        `INSERT INTO authorization_decisions (action_request_id, org_id, agent_id, decision, policy_decision, enforcement_mode, reason_code, explanation, policy_id, policy_version, expires_at, created_at)
         VALUES ($1,$2,$3,$4,$4,'enforce',$5,$6,$7,$8,$9,$9)`,
        [ar.id, auth.orgId, auth.agentId, r.decision, r.reason_code, `${source === "local_fast" ? `Decided in-process by the fast path from the signed policy (v${r.policy_version ?? "none"}).` : `Decided locally from the cached signed policy (v${r.policy_version ?? "none"}) while the service was unreachable.`}${mismatch ? " Server re-evaluation disagrees or the version is unknown." : ""}`, pv?.policyId ?? null, r.policy_version, decidedAt],
      );
      await q.query(
        `INSERT INTO execution_outcomes (action_request_id, org_id, agent_id, status, enforcement_confirmed, error_code, claimed_at, reported_at, created_at)
         VALUES ($1,$2,$3,$4,true,$5, CASE WHEN $4 = 'refused' THEN NULL ELSE $6::timestamptz END, now(), $6::timestamptz)`,
        [ar.id, auth.orgId, auth.agentId, r.outcome.status, r.outcome.error_code ?? null, decidedAt],
      );
      if (mismatch) {
        await raiseAlert(q, {
          orgId: auth.orgId, agentId: auth.agentId, actionRequestId: ar.id, kind: "offline_decision_mismatch", severity: "high",
          title: `${source === "local_fast" ? "Fast-path" : "Offline"} decision for ${r.action.tool}.${r.action.operation} does not match policy v${r.policy_version ?? "?"}`,
          detail: `The executor decided '${r.decision}' offline; the server computes '${recomputed ?? "unknown version"}'. Investigate this executor.`,
          dedupeKey: `offline-mismatch:${auth.agentId}`,
        });
        await audit(q, { orgId: auth.orgId, actorType: "credential", actorId: auth.credentialId, action: "offline.decision_mismatch", targetType: "action_request", targetId: ar.id });
      }
      return mismatch ? ("mismatch" as const) : ("recorded" as const);
    });
    results.push({ request_id: r.request_id, status: out });
  }
  await ctx.db.query("UPDATE agents SET last_enforced_at = now() WHERE id = $1", [auth.agentId]);
  return { results };
}
