import { z } from "zod";
import { actionDigest, type ActionRequestInput } from "../../shared/action.js";
import { evaluate, normalizeDestination, policyDocumentSchema, type Decision, type PolicyDocument, type ReasonCode } from "../../shared/policy.js";
import { redact, redactedJsonString } from "../../shared/redact.js";
import { HttpError, conflict, notFound } from "../errors.js";
import type { Queryable } from "../db.js";
import { parseIntegrationKey, safeEqual, sha256 } from "../security.js";
import { audit, raiseAlert, type AgentRow, type Ctx } from "./core.js";

/** How long an immediate "allow" decision may be claimed for execution. */
export const AUTHORIZATION_TTL_SEC = 300;
/** How long after a human approves the action may be claimed (one time). */
export const APPROVAL_GRANT_SEC = 300;
const HIGH_RISK_OPS = new Set(["command_execution", "external_transfer", "delete"]);

export interface CredentialAuth {
  credentialId: string;
  orgId: string;
  agentId: string;
  scopes: string[];
  agent: Pick<AgentRow, "status" | "enforcement_mode" | "integration_type" | "policy_id" | "name">;
}

const denyBody = (reason: ReasonCode) => ({ decision: "deny", reason_code: reason });

export async function authenticateKey(ctx: Ctx, authHeader: string | undefined, scope: "actions" | "events"): Promise<CredentialAuth> {
  const key = /^Bearer (.+)$/.exec(authHeader ?? "")?.[1]?.trim();
  const parsed = key ? parseIntegrationKey(key) : null;
  if (!key || !parsed) throw new HttpError(401, "CREDENTIAL_INVALID", "Missing or malformed integration key", denyBody("CREDENTIAL_INVALID"));
  const [row] = await ctx.db.query<any>(
    `SELECT c.id, c.org_id, c.agent_id, c.scopes, c.secret_hash, c.revoked_at, c.name AS credential_name,
            a.status AS agent_status, a.enforcement_mode, a.integration_type, a.policy_id, a.name AS agent_name
       FROM integration_credentials c JOIN agents a ON a.id = c.agent_id AND a.org_id = c.org_id
      WHERE c.prefix = $1`,
    [parsed.prefix],
  );
  if (!row || !safeEqual(sha256(key), row.secret_hash)) {
    throw new HttpError(401, "CREDENTIAL_INVALID", "Invalid integration key", denyBody("CREDENTIAL_INVALID"));
  }
  if (row.revoked_at) {
    await audit(ctx.db, { orgId: row.org_id, actorType: "credential", actorId: row.id, action: "credential.revoked_use_attempt", targetType: "agent", targetId: row.agent_id });
    await raiseAlert(ctx.db, {
      orgId: row.org_id,
      agentId: row.agent_id,
      kind: "revoked_credential_used",
      severity: "high",
      title: `Revoked credential used by ${row.agent_name}`,
      detail: `Credential '${row.credential_name}' was presented after revocation and was refused.`,
      dedupeKey: `revoked-cred:${row.id}`,
    });
    throw new HttpError(401, "CREDENTIAL_REVOKED", "This integration key has been revoked", denyBody("CREDENTIAL_REVOKED"));
  }
  if (row.agent_status === "revoked") {
    await audit(ctx.db, { orgId: row.org_id, actorType: "credential", actorId: row.id, action: "agent.revoked_use_attempt", targetType: "agent", targetId: row.agent_id });
    throw new HttpError(403, "AGENT_REVOKED", "This agent has been revoked", denyBody("AGENT_REVOKED"));
  }
  if (!(row.scopes as string[]).includes(scope)) {
    throw new HttpError(403, "INSUFFICIENT_SCOPE", `This key does not have the '${scope}' scope`);
  }
  await ctx.db.query("UPDATE integration_credentials SET last_used_at = now() WHERE id = $1", [row.id]);
  await ctx.db.query("UPDATE agents SET last_seen_at = now() WHERE id = $1", [row.agent_id]);
  return {
    credentialId: row.id,
    orgId: row.org_id,
    agentId: row.agent_id,
    scopes: row.scopes,
    agent: { status: row.agent_status, enforcement_mode: row.enforcement_mode, integration_type: row.integration_type, policy_id: row.policy_id, name: row.agent_name },
  };
}

// ---------- shared loading ----------

async function loadPolicy(q: Queryable, policyId: string, orgId: string): Promise<{ version: number; doc: PolicyDocument } | null> {
  const [row] = await q.query<any>(
    `SELECT p.current_version AS version, v.document
       FROM policies p JOIN policy_versions v ON v.policy_id = p.id AND v.version = p.current_version
      WHERE p.id = $1 AND p.org_id = $2`,
    [policyId, orgId],
  );
  if (!row) return null;
  const doc = policyDocumentSchema.parse(row.document); // a stored policy that no longer validates must fail closed (throws)
  return { version: row.version, doc };
}

async function allowedInWindow(q: Queryable, agentId: string, windowSec: number, excludeActionId: string): Promise<number> {
  const [r] = await q.query<{ n: number }>(
    `SELECT (
        (SELECT count(*) FROM authorization_decisions d
          WHERE d.agent_id = $1 AND d.policy_decision = 'allow' AND d.action_request_id <> $3
            AND d.created_at > now() - make_interval(secs => $2::double precision))
      + (SELECT count(*) FROM approvals a
          WHERE a.agent_id = $1 AND a.consumed_at IS NOT NULL AND a.action_request_id <> $3
            AND a.consumed_at > now() - make_interval(secs => $2::double precision))
     )::int AS n`,
    [agentId, windowSec, excludeActionId],
  );
  return r?.n ?? 0;
}

const ACTION_SQL = `
  SELECT ar.id AS action_id, ar.org_id, ar.agent_id, ar.request_id, ar.tool, ar.operation, ar.resource, ar.destination,
         ar.data_classification, ar.action_digest, ar.is_demo, ar.created_at,
         d.decision, d.policy_decision, d.enforcement_mode AS decision_mode, d.reason_code, d.explanation,
         d.policy_id AS decision_policy_id, d.policy_version AS decision_policy_version, d.matched_rule_id,
         d.expires_at AS decision_expires_at, (d.expires_at < now()) AS decision_expired, d.classification_level, d.classification_source,
         ap.id AS approval_id, ap.status AS approval_status, ap.expires_at AS approval_expires_at,
         (ap.expires_at < now()) AS approval_request_expired, ap.grant_expires_at, (ap.grant_expires_at < now()) AS grant_expired,
         ap.consumed_at AS approval_consumed_at, ap.required_role, ap.policy_id AS approval_policy_id,
         ap.policy_version AS approval_policy_version, ap.action_digest AS approval_digest,
         o.status AS outcome_status, o.enforcement_confirmed
    FROM action_requests ar
    JOIN authorization_decisions d ON d.action_request_id = ar.id
    LEFT JOIN approvals ap ON ap.action_request_id = ar.id
    LEFT JOIN execution_outcomes o ON o.action_request_id = ar.id
   WHERE ar.agent_id = $1 AND ar.request_id = $2`;

export function effectiveApprovalStatus(r: any): "pending" | "approved" | "rejected" | "expired" | "used" | null {
  if (!r.approval_id) return null;
  if (r.approval_status === "rejected") return "rejected";
  if (r.approval_status === "expired") return "expired";
  if (r.approval_status === "pending") return r.approval_request_expired ? "expired" : "pending";
  if (r.approval_consumed_at) return "used";
  return r.grant_expired ? "expired" : "approved";
}

function view(r: any, extra: Record<string, unknown> = {}) {
  const dest = r.destination ? normalizeDestination(r.destination) : null;
  return {
    request_id: r.request_id,
    action_id: r.action_id,
    decision: r.decision,
    policy_decision: r.policy_decision,
    reason_code: r.reason_code,
    explanation: r.explanation,
    policy_version: r.decision_policy_version,
    matched_rule_id: r.matched_rule_id,
    classification: r.classification_level ? { level: r.classification_level, source: r.classification_source } : null,
    enforcement_mode: r.decision_mode,
    action_digest: r.action_digest,
    decision_expires_at: r.decision_expires_at,
    destination_host: dest && dest.ok ? dest.host : null,
    approval: r.approval_id
      ? { id: r.approval_id, status: effectiveApprovalStatus(r), expires_at: r.approval_expires_at, grant_expires_at: r.grant_expires_at, required_role: r.required_role }
      : null,
    execution: r.outcome_status ? { status: r.outcome_status, enforcement_confirmed: r.enforcement_confirmed } : null,
    ...extra,
  };
}

// ---------- authorize ----------

export async function authorize(ctx: Ctx, auth: CredentialAuth, input: ActionRequestInput) {
  const digest = actionDigest(input);
  return ctx.db.tx(async (q) => {
    // Serialise per agent: idempotent request handling and budget counting are race-free.
    const [agent] = await q.query<AgentRow>("SELECT * FROM agents WHERE id = $1 AND org_id = $2 FOR UPDATE", [auth.agentId, auth.orgId]);
    if (!agent) throw notFound("Agent");

    const [existing] = await q.query<any>("SELECT id, action_digest FROM action_requests WHERE agent_id = $1 AND request_id = $2", [auth.agentId, input.request_id]);
    if (existing) {
      if (existing.action_digest !== digest) {
        await audit(q, { orgId: auth.orgId, actorType: "credential", actorId: auth.credentialId, action: "action.request_id_conflict", targetType: "action_request", targetId: existing.id });
        throw conflict("REQUEST_ID_CONFLICT", "This request_id was already used for a different action. Use a new request_id.");
      }
      const [row] = await q.query<any>(ACTION_SQL, [auth.agentId, input.request_id]);
      return view(row, { idempotent_replay: true });
    }

    const [ar] = await q.query<{ id: string }>(
      `INSERT INTO action_requests (org_id, agent_id, credential_id, request_id, tool, operation, resource, destination, data_classification,
                                    args_summary, action_digest, is_demo, adapter_name, adapter_version, requested_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15) RETURNING id`,
      [
        auth.orgId, auth.agentId, auth.credentialId, input.request_id, input.tool, input.operation,
        String(redact(input.resource)).slice(0, 512), input.destination ? String(redact(input.destination)).slice(0, 512) : null,
        input.data_classification ?? null, redactedJsonString(input.args ?? {}), digest, input.demo ?? false,
        input.adapter?.name ?? null, input.adapter?.version ?? null, input.requested_at ?? null,
      ],
    );

    // Decide.
    let policyDecision: Decision;
    let policyId: string | null = agent.policy_id;
    let policyVersion: number | null = null;
    if (agent.status === "revoked") {
      policyDecision = { decision: "deny", reason_code: "AGENT_REVOKED", explanation: "This agent has been revoked.", matched_rule_id: null };
    } else {
      const policy = agent.policy_id ? await loadPolicy(q, agent.policy_id, auth.orgId) : null;
      if (!policy) {
        policyDecision = { decision: "deny", reason_code: "NO_POLICY_ASSIGNED", explanation: "No policy is assigned to this agent; the default is to deny.", matched_rule_id: null };
        policyId = null;
      } else {
        policyVersion = policy.version;
        const used = policy.doc.budget ? await allowedInWindow(q, agent.id, policy.doc.budget.window_seconds, ar.id) : 0;
        policyDecision = evaluate(policy.doc, input, { allowedInWindow: used, hasValidApproval: false });
      }
    }

    let effective: Decision = policyDecision;
    const monitor = agent.enforcement_mode === "monitor" && agent.status === "active";
    if (monitor && policyDecision.decision !== "allow") {
      effective = {
        decision: "allow",
        reason_code: "MONITOR_ONLY",
        explanation: `Monitor mode: the policy would have returned '${policyDecision.decision}' (${policyDecision.reason_code}) but is not enforcing. ${policyDecision.explanation}`,
        matched_rule_id: policyDecision.matched_rule_id,
      };
    }

    await q.query(
      `INSERT INTO authorization_decisions (action_request_id, org_id, agent_id, decision, policy_decision, enforcement_mode, reason_code, explanation,
                                            policy_id, policy_version, matched_rule_id, expires_at, classification_level, classification_source)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, now() + make_interval(secs => $12::double precision), $13, $14)`,
      [ar.id, auth.orgId, agent.id, effective.decision, policyDecision.decision, agent.enforcement_mode, effective.reason_code, effective.explanation.slice(0, 600),
       policyId, policyVersion, effective.matched_rule_id, AUTHORIZATION_TTL_SEC, policyDecision.classification?.level ?? null, policyDecision.classification?.source ?? null],
    );

    if (effective.decision === "require_approval" && policyId && policyVersion !== null && effective.approval) {
      await q.query(
        `INSERT INTO approvals (org_id, action_request_id, agent_id, action_digest, policy_id, policy_version, required_role, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7, now() + make_interval(secs => $8::double precision))`,
        [auth.orgId, ar.id, agent.id, digest, policyId, policyVersion, effective.approval.required_role, effective.approval.ttl_seconds],
      );
      await audit(q, { orgId: auth.orgId, actorType: "credential", actorId: auth.credentialId, action: "approval.requested", targetType: "action_request", targetId: ar.id, metadata: { operation: input.operation, resource: input.resource } });
    }

    await q.query("UPDATE agents SET last_authorized_at = now() WHERE id = $1", [agent.id]);
    await decisionAlerts(q, auth, agent, input, policyDecision, effective, ar.id);

    const [row] = await q.query<any>(ACTION_SQL, [auth.agentId, input.request_id]);
    return view(row, { idempotent_replay: false });
  });
}

async function decisionAlerts(q: Queryable, auth: CredentialAuth, agent: AgentRow, input: ActionRequestInput, policy: Decision, effective: Decision, actionId: string) {
  const common = { orgId: auth.orgId, agentId: agent.id, actionRequestId: actionId, isDemo: input.demo ?? false };
  if (policy.decision === "deny" && policy.reason_code !== "AGENT_REVOKED") {
    const would = effective.reason_code === "MONITOR_ONLY";
    if (HIGH_RISK_OPS.has(input.operation) || policy.reason_code === "BUDGET_EXCEEDED") {
      const budget = policy.reason_code === "BUDGET_EXCEEDED";
      await raiseAlert(q, {
        ...common,
        kind: budget ? "budget_exceeded" : "high_risk_action_denied",
        severity: budget ? "medium" : input.operation === "delete" ? "medium" : "high",
        title: would
          ? `${agent.name}: ${input.operation} would be denied (monitor mode, not enforced)`
          : budget ? `${agent.name} exceeded its action budget` : `${agent.name}: ${input.operation} on '${redact(input.resource)}' denied`,
        detail: `${policy.reason_code}: ${policy.explanation}`,
        dedupeKey: `deny:${agent.id}:${input.operation}:${policy.reason_code}:${would ? "m" : "e"}`,
      });
    }
    const [r] = await q.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM authorization_decisions WHERE agent_id = $1 AND policy_decision = 'deny' AND created_at > now() - interval '5 minutes'`,
      [agent.id],
    );
    if ((r?.n ?? 0) >= 10) {
      await raiseAlert(q, { ...common, kind: "repeated_denials", severity: "medium", title: `${agent.name} was denied ${r.n} times in 5 minutes`, detail: "Repeated denials can indicate a misconfigured or misbehaving agent.", dedupeKey: `repeat-deny:${agent.id}` });
    }
    await audit(q, { orgId: auth.orgId, actorType: "credential", actorId: auth.credentialId, action: would ? "action.would_deny_monitor" : "action.denied", targetType: "action_request", targetId: actionId, metadata: { reason: policy.reason_code, operation: input.operation } });
  }
}

export async function getAction(ctx: Ctx, auth: CredentialAuth, requestId: string) {
  const [row] = await ctx.db.query<any>(ACTION_SQL, [auth.agentId, requestId]);
  if (!row) throw notFound("Action");
  return view(row);
}

// ---------- claim (the one-time execution permit) ----------

type ClaimResult =
  | { ok: true; claim: { claimed_at: string; policy_version: number | null } }
  | { ok: false; status: 403 | 409; code: string; message: string };

type Refusal = Extract<ClaimResult, { ok: false }>;
const refuse = (status: 403 | 409, code: string, message: string): Refusal => ({ ok: false, status, code, message });

export async function claim(ctx: Ctx, auth: CredentialAuth, requestId: string, presentedDigest: string): Promise<ClaimResult> {
  const result = await ctx.db.tx(async (q): Promise<ClaimResult> => {
    const [agent] = await q.query<AgentRow>("SELECT * FROM agents WHERE id = $1 AND org_id = $2 FOR UPDATE", [auth.agentId, auth.orgId]);
    if (!agent) throw notFound("Agent");
    const [r] = await q.query<any>(ACTION_SQL, [auth.agentId, requestId]);
    if (!r) throw notFound("Action");
    const base = { orgId: auth.orgId, actorType: "credential" as const, actorId: auth.credentialId, targetType: "action_request", targetId: r.action_id };
    const refused = async (res: Refusal, alert?: { kind: string; severity: "low" | "medium" | "high"; title: string }) => {
      await audit(q, { ...base, action: "action.claim_refused", metadata: { code: res.code } });
      if (alert) await raiseAlert(q, { orgId: auth.orgId, agentId: agent.id, actionRequestId: r.action_id, kind: alert.kind, severity: alert.severity, title: alert.title, detail: res.message, dedupeKey: `${alert.kind}:${agent.id}`, isDemo: r.is_demo });
      return res;
    };

    if (agent.status === "revoked") return refused(refuse(403, "AGENT_REVOKED", "The agent has been revoked."));
    const [existingOutcome] = await q.query("SELECT 1 FROM execution_outcomes WHERE action_request_id = $1", [r.action_id]);
    if (existingOutcome) return refused(refuse(409, "ALREADY_CLAIMED", "This action was already claimed. Each authorization can be executed at most once."));
    if (presentedDigest !== r.action_digest) {
      return refused(refuse(409, "DIGEST_MISMATCH", "The action to execute differs from the action that was authorized."), {
        kind: "argument_mismatch", severity: "high", title: `${agent.name} tried to execute different arguments than authorized`,
      });
    }
    if (r.decision === "deny") return refused(refuse(403, "NOT_AUTHORIZED", `Authorization was denied (${r.reason_code}).`));

    const policy = agent.policy_id ? await loadPolicy(q, agent.policy_id, auth.orgId) : null;
    const reeval = async (hasValidApproval: boolean): Promise<Decision> => {
      if (!policy) return { decision: "deny", reason_code: "NO_POLICY_ASSIGNED", explanation: "No policy is assigned to this agent.", matched_rule_id: null };
      const used = policy.doc.budget ? await allowedInWindow(q, agent.id, policy.doc.budget.window_seconds, r.action_id) : 0;
      return evaluate(policy.doc, { tool: r.tool, operation: r.operation, resource: r.resource, destination: r.destination, data_classification: r.data_classification }, { allowedInWindow: used, hasValidApproval });
    };

    if (r.decision === "require_approval") {
      const st = effectiveApprovalStatus(r);
      if (st === "pending") return refused(refuse(409, "APPROVAL_PENDING", "This action is still waiting for a human decision."));
      if (st === "rejected") return refused(refuse(403, "APPROVAL_REJECTED", "A human rejected this action."));
      if (st === "expired") return refused(refuse(403, "APPROVAL_EXPIRED", "The approval has expired. Submit a new request."));
      if (st === "used") return refused(refuse(409, "APPROVAL_ALREADY_USED", "This one-time approval has already been used."));
      if (r.approval_digest !== r.action_digest || r.approval_policy_id !== agent.policy_id || !policy || r.approval_policy_version !== policy.version) {
        return refused(refuse(403, "APPROVAL_POLICY_CHANGED", "The policy or agent assignment changed after this action was approved. Request approval again."));
      }
      const d = await reeval(true);
      if (d.decision !== "allow") return refused(refuse(403, d.reason_code, `Re-evaluation before execution: ${d.explanation}`));
      const consumed = await q.query(
        `UPDATE approvals SET consumed_at = now()
          WHERE id = $1 AND org_id = $2 AND status = 'approved' AND consumed_at IS NULL AND grant_expires_at > now() RETURNING id`,
        [r.approval_id, auth.orgId],
      );
      if (consumed.length === 0) return refused(refuse(409, "APPROVAL_ALREADY_USED", "The approval could not be consumed (already used or expired)."));
    } else {
      // Immediate allow: bounded validity, then re-check against the policy as it stands now.
      if (r.decision_expired) return refused(refuse(403, "AUTHORIZATION_EXPIRED", "The authorization expired. Request a new one."));
      const stillMonitor = agent.enforcement_mode === "monitor";
      if (!stillMonitor) {
        const d = await reeval(false);
        if (d.decision === "deny") return refused(refuse(403, d.reason_code, `Policy changed since authorization: ${d.explanation}`));
        if (d.decision === "require_approval") return refused(refuse(403, "APPROVAL_REQUIRED", "Policy now requires approval for this action."));
      }
    }

    await q.query(
      `INSERT INTO execution_outcomes (action_request_id, org_id, agent_id, status, claim_policy_version, claimed_at, enforcement_confirmed)
       VALUES ($1,$2,$3,'claimed',$4, now(), false)`,
      [r.action_id, auth.orgId, agent.id, policy?.version ?? null],
    );
    await q.query("UPDATE agents SET last_enforced_at = now() WHERE id = $1", [agent.id]);
    if (r.decision === "require_approval") await audit(q, { ...base, action: "approval.consumed", metadata: { approval_id: r.approval_id } });
    return { ok: true, claim: { claimed_at: new Date().toISOString(), policy_version: policy?.version ?? null } };
  });
  return result;
}

// ---------- outcome ----------

export const outcomeSchema = z
  .object({
    status: z.enum(["succeeded", "failed", "refused"]),
    error_code: z.string().max(64).optional(),
    detail: z.record(z.string().max(100), z.unknown()).optional(),
  })
  .strict();

export async function reportOutcome(ctx: Ctx, auth: CredentialAuth, requestId: string, body: z.infer<typeof outcomeSchema>) {
  return ctx.db.tx(async (q) => {
    const [agent] = await q.query<AgentRow>("SELECT * FROM agents WHERE id = $1 AND org_id = $2 FOR UPDATE", [auth.agentId, auth.orgId]);
    if (!agent) throw notFound("Agent");
    const [r] = await q.query<any>(ACTION_SQL, [auth.agentId, requestId]);
    if (!r) throw notFound("Action");
    const [existing] = await q.query<any>("SELECT * FROM execution_outcomes WHERE action_request_id = $1 FOR UPDATE", [r.action_id]);
    const detail = redactedJsonString(body.detail ?? {}, 1024);
    const done = (replay: boolean) => ({ request_id: requestId, status: body.status, enforcement_confirmed: true, idempotent_replay: replay });

    if (body.status === "refused") {
      if (existing) {
        if (existing.status === "refused") return done(true);
        throw conflict("OUTCOME_CONFLICT", `The action already has outcome '${existing.status}'.`);
      }
      await q.query(
        `INSERT INTO execution_outcomes (action_request_id, org_id, agent_id, status, enforcement_confirmed, error_code, detail, reported_at)
         VALUES ($1,$2,$3,'refused',true,$4,$5::jsonb, now())`,
        [r.action_id, auth.orgId, agent.id, body.error_code ?? null, detail],
      );
    } else {
      if (!existing) throw conflict("NO_CLAIM", "Report an execution outcome only after a successful claim.");
      if (existing.status === body.status) return done(true);
      if (existing.status !== "claimed") throw conflict("OUTCOME_CONFLICT", `The action already has outcome '${existing.status}'.`);
      await q.query(
        `UPDATE execution_outcomes SET status = $2, enforcement_confirmed = true, error_code = $3, detail = $4::jsonb, reported_at = now()
          WHERE action_request_id = $1`,
        [r.action_id, body.status, body.error_code ?? null, detail],
      );
      if (body.status === "failed") {
        await raiseAlert(q, {
          orgId: auth.orgId, agentId: agent.id, actionRequestId: r.action_id, kind: "execution_failed", severity: "medium",
          title: `${agent.name}: ${r.tool}.${r.operation} failed during execution`, detail: `Error code: ${body.error_code ?? "unspecified"}`,
          dedupeKey: `exec-failed:${agent.id}:${r.tool}:${r.operation}`, isDemo: r.is_demo,
        });
      }
    }
    await q.query("UPDATE agents SET last_enforced_at = now() WHERE id = $1", [agent.id]);
    return done(false);
  });
}

// ---------- observation-only events ----------

export const eventSchema = z
  .object({
    event_id: z.string().regex(/^[A-Za-z0-9_.:-]{8,128}$/).optional(),
    event_type: z.string().regex(/^[a-z0-9_.-]{1,64}$/),
    tool: z.string().max(64).optional(),
    operation: z.string().max(64).optional(),
    resource: z.string().max(512).optional(),
    summary: z.record(z.string().max(100), z.unknown()).optional(),
    occurred_at: z.string().datetime().optional(),
    demo: z.boolean().optional(),
  })
  .strict();

export async function recordEvent(ctx: Ctx, auth: CredentialAuth, body: z.infer<typeof eventSchema>) {
  const rows = await ctx.db.query<{ id: string }>(
    `INSERT INTO observed_events (org_id, agent_id, credential_id, event_id, event_type, tool, operation, resource, summary, is_demo, occurred_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)
     ON CONFLICT (agent_id, event_id) WHERE event_id IS NOT NULL DO NOTHING RETURNING id`,
    [auth.orgId, auth.agentId, auth.credentialId, body.event_id ?? null, body.event_type, body.tool ?? null, body.operation ?? null,
     body.resource ? String(redact(body.resource)) : null, redactedJsonString(body.summary ?? {}), body.demo ?? false, body.occurred_at ?? null],
  );
  return { recorded: rows.length === 1, idempotent_replay: rows.length === 0, note: "Observation only: this event reports what happened; it does not mean anything was blocked." };
}
