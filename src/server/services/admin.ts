import { createHash } from "node:crypto";
import { z } from "zod";
import { canonicalJson } from "../../shared/action.js";
import { evaluate, normalizeResource, policyDocumentSchema, OPERATIONS, CLASSIFICATIONS, type PolicyDocument } from "../../shared/policy.js";
import { HttpError, badRequest, conflict, forbidden, notFound, unauthorized } from "../errors.js";
import type { Queryable } from "../db.js";
import { hashPassword, newIntegrationKey, newSessionToken, sha256, verifyPassword } from "../security.js";
import { audit, can, roleAtLeast, ROLES, type AgentRow, type Ctx, type Permission, type Role } from "./core.js";
import { currentSession } from "../session-context.js";
import { APPROVAL_GRANT_SEC } from "./authz.js";

const isUnique = (e: unknown) => (e as { code?: string })?.code === "23505";

export function parse<T extends z.ZodTypeAny>(schema: T, data: unknown): z.infer<T> {
  const r = schema.safeParse(data);
  if (!r.success) {
    throw badRequest("VALIDATION_ERROR", "Some fields are invalid", r.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })));
  }
  return r.data;
}

export const validTimezone = (tz: string) => {
  try {
    new Intl.DateTimeFormat("en", { timeZone: tz });
    return true;
  } catch {
    return false;
  }
};

// ---------- users & sessions ----------

export const registerSchema = z
  .object({
    email: z.email().max(254).transform((s) => s.toLowerCase()),
    name: z.string().trim().min(1).max(120),
    password: z.string().min(12, "Use at least 12 characters").max(200),
  })
  .strict()
  .refine((v) => v.password.toLowerCase() !== v.email, { message: "Password must not be your email", path: ["password"] });

export async function registerUser(ctx: Ctx, input: z.infer<typeof registerSchema>) {
  const hash = await hashPassword(input.password);
  try {
    const [u] = await ctx.db.query<{ id: string }>("INSERT INTO users (email, name, password_hash) VALUES ($1,$2,$3) RETURNING id", [input.email, input.name, hash]);
    await audit(ctx.db, { orgId: null, actorType: "user", actorId: u.id, action: "user.registered" });
    return { id: u.id, email: input.email, name: input.name };
  } catch (e) {
    if (isUnique(e)) throw conflict("EMAIL_TAKEN", "An account with this email already exists");
    throw e;
  }
}

export async function logout(ctx: Ctx, token: string) {
  await ctx.db.query("UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL", [sha256(token)]);
}

// ---------- organizations & membership ----------

/** Org scope comes from the authenticated user's membership, never from a client-supplied claim. */
export async function requireRole(q: Queryable, userId: string, orgId: string, min: Role): Promise<Role> {
  if (!/^[0-9a-f-]{36}$/i.test(orgId)) throw notFound("Organization");
  const [m] = await q.query<{ role: Role; require_mfa: boolean; sso_enforced: boolean }>(
    "SELECT m.role, o.require_mfa, o.sso_enforced FROM memberships m JOIN organizations o ON o.id = m.org_id WHERE m.org_id = $1 AND m.user_id = $2",
    [orgId, userId],
  );
  if (!m) throw notFound("Organization"); // do not reveal whether the org exists
  enforceOrgSecurity(orgId, m);
  if (!roleAtLeast(m.role, min)) throw forbidden(`This needs the ${min} role or higher`);
  return m.role;
}

/** For permissions that do not follow seniority (approvals, alerts, audit log). */
export async function requirePermission(q: Queryable, userId: string, orgId: string, perm: Permission): Promise<Role> {
  const role = await requireRole(q, userId, orgId, "viewer");
  if (!can(role, perm)) throw forbidden(`Your role (${role}) does not include ${perm.replace(".", ": ")}`);
  return role;
}

/**
 * The organization's sign-in rules, checked on every request into the organization (this is the one chokepoint).
 *  - require_mfa: the session must have passed a second factor.
 *  - sso_enforced: the session must come from this organization's identity provider. Owners are exempt (break-glass), so a
 *    broken identity provider cannot lock the organization out; they still need MFA when it is required.
 * Requests that did not come through the session middleware (internal jobs) carry no session and are not subject to them.
 */
function enforceOrgSecurity(orgId: string, m: { role: Role; require_mfa: boolean; sso_enforced: boolean }) {
  const s = currentSession();
  if (!s) return;
  if (m.sso_enforced && m.role !== "owner" && !(s.authMethod === "oidc" && s.ssoOrgId === orgId)) {
    throw new HttpError(403, "SSO_REQUIRED", "This organization requires signing in with its single sign-on.", { sso_org_id: orgId });
  }
  if (m.require_mfa && !s.mfaVerified) {
    throw new HttpError(403, "MFA_REQUIRED", "This organization requires two-step verification. Verify with your authenticator app to continue.");
  }
}

export const orgCreateSchema = z.object({ name: z.string().trim().min(2).max(120) }).strict();

export async function createOrg(ctx: Ctx, userId: string, input: z.infer<typeof orgCreateSchema>) {
  return ctx.db.tx(async (q) => {
    const [o] = await q.query<any>("INSERT INTO organizations (name, created_by) VALUES ($1,$2) RETURNING id, name, timezone", [input.name, userId]);
    await q.query("INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,'owner')", [o.id, userId]);
    await audit(q, { orgId: o.id, actorType: "user", actorId: userId, action: "org.created", targetType: "organization", targetId: o.id });
    return { ...o, role: "owner" as Role };
  });
}

export async function myOrgs(ctx: Ctx, userId: string) {
  return ctx.db.query(
    `SELECT o.id, o.name, o.timezone, m.role FROM memberships m JOIN organizations o ON o.id = m.org_id WHERE m.user_id = $1 ORDER BY o.created_at`,
    [userId],
  );
}

export const orgUpdateSchema = z
  .object({
    name: z.string().trim().min(2).max(120).optional(),
    timezone: z.string().max(64).refine(validTimezone, "Unknown timezone").optional(),
    retention_days: z.number().int().min(7).max(730).optional(),
    audit_retention_days: z.number().int().min(30).max(3650).optional(),
  })
  .strict();

export async function getOrg(ctx: Ctx, userId: string, orgId: string) {
  const role = await requireRole(ctx.db, userId, orgId, "viewer");
  const [o] = await ctx.db.query<any>("SELECT id, name, timezone, retention_days, audit_retention_days, created_at FROM organizations WHERE id = $1", [orgId]);
  return { ...o, role };
}

export async function updateOrg(ctx: Ctx, userId: string, orgId: string, input: z.infer<typeof orgUpdateSchema>) {
  await requireRole(ctx.db, userId, orgId, "owner");
  await ctx.db.query(
    `UPDATE organizations SET name = COALESCE($2, name), timezone = COALESCE($3, timezone),
            retention_days = COALESCE($4, retention_days), audit_retention_days = COALESCE($5, audit_retention_days) WHERE id = $1`,
    [orgId, input.name ?? null, input.timezone ?? null, input.retention_days ?? null, input.audit_retention_days ?? null],
  );
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "org.updated", targetType: "organization", targetId: orgId, metadata: input });
  return getOrg(ctx, userId, orgId);
}

export async function listMembers(ctx: Ctx, userId: string, orgId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  return ctx.db.query(
    `SELECT u.id AS user_id, u.name, u.email, m.role, m.created_at FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = $1 ORDER BY m.created_at`,
    [orgId],
  );
}

export const memberAddSchema = z.object({ email: z.email().transform((s) => s.toLowerCase()), role: z.enum(ROLES) }).strict();
export const memberRoleSchema = z.object({ role: z.enum(ROLES) }).strict();

async function ownerCount(q: Queryable, orgId: string) {
  const [r] = await q.query<{ n: number }>("SELECT count(*)::int AS n FROM memberships WHERE org_id = $1 AND role = 'owner'", [orgId]);
  return r.n;
}

export async function addMember(ctx: Ctx, userId: string, orgId: string, input: z.infer<typeof memberAddSchema>) {
  await requireRole(ctx.db, userId, orgId, "owner");
  const [u] = await ctx.db.query<{ id: string }>("SELECT id FROM users WHERE email = $1", [input.email]);
  if (!u) throw badRequest("USER_NOT_FOUND", "That person must create an account first (email invitations are not implemented yet).");
  try {
    await ctx.db.query("INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,$3)", [orgId, u.id, input.role]);
  } catch (e) {
    if (isUnique(e)) throw conflict("ALREADY_MEMBER", "That person is already a member");
    throw e;
  }
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "member.added", targetType: "user", targetId: u.id, metadata: { role: input.role } });
}

export async function changeMemberRole(ctx: Ctx, userId: string, orgId: string, targetUserId: string, role: Role) {
  return ctx.db.tx(async (q) => {
    await requireRole(q, userId, orgId, "owner");
    const [m] = await q.query<{ role: Role }>("SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2 FOR UPDATE", [orgId, targetUserId]);
    if (!m) throw notFound("Member");
    if (m.role === "owner" && role !== "owner" && (await ownerCount(q, orgId)) <= 1) throw conflict("LAST_OWNER", "An organization must keep at least one owner");
    await q.query("UPDATE memberships SET role = $3 WHERE org_id = $1 AND user_id = $2", [orgId, targetUserId, role]);
    await audit(q, { orgId, actorType: "user", actorId: userId, action: "member.role_changed", targetType: "user", targetId: targetUserId, metadata: { from: m.role, to: role } });
  });
}

export async function removeMember(ctx: Ctx, userId: string, orgId: string, targetUserId: string) {
  return ctx.db.tx(async (q) => {
    await requireRole(q, userId, orgId, "owner");
    const [m] = await q.query<{ role: Role }>("SELECT role FROM memberships WHERE org_id = $1 AND user_id = $2 FOR UPDATE", [orgId, targetUserId]);
    if (!m) throw notFound("Member");
    if (m.role === "owner" && (await ownerCount(q, orgId)) <= 1) throw conflict("LAST_OWNER", "An organization must keep at least one owner");
    await q.query("DELETE FROM memberships WHERE org_id = $1 AND user_id = $2", [orgId, targetUserId]);
    await audit(q, { orgId, actorType: "user", actorId: userId, action: "member.removed", targetType: "user", targetId: targetUserId });
  });
}

// ---------- agents ----------

export const agentCreateSchema = z
  .object({
    name: z.string().trim().min(1).max(120),
    description: z.string().trim().max(1000).default(""),
    environment: z.enum(["development", "staging", "production"]),
    integration_type: z.enum(["typescript_sdk", "event_reporting"]),
    policy_id: z.uuid().nullable().optional(),
    enforcement_mode: z.enum(["monitor", "enforce"]).default("enforce"),
  })
  .strict();

async function assertPolicyInOrg(q: Queryable, policyId: string | null | undefined, orgId: string) {
  if (!policyId) return;
  const [p] = await q.query("SELECT 1 FROM policies WHERE id = $1 AND org_id = $2", [policyId, orgId]);
  if (!p) throw badRequest("POLICY_NOT_FOUND", "That policy does not exist in this organization");
}

export async function createAgent(ctx: Ctx, userId: string, orgId: string, input: z.infer<typeof agentCreateSchema>) {
  await requireRole(ctx.db, userId, orgId, "admin");
  await assertPolicyInOrg(ctx.db, input.policy_id, orgId);
  try {
    const [a] = await ctx.db.query<{ id: string }>(
      `INSERT INTO agents (org_id, name, description, environment, integration_type, policy_id, enforcement_mode, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [orgId, input.name, input.description, input.environment, input.integration_type, input.policy_id ?? null, input.enforcement_mode, userId],
    );
    await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "agent.registered", targetType: "agent", targetId: a.id, metadata: { name: input.name, environment: input.environment } });
    return a;
  } catch (e) {
    if (isUnique(e)) throw conflict("AGENT_EXISTS", "An agent with this name already exists in that environment");
    throw e;
  }
}

export const agentUpdateSchema = z
  .object({
    name: z.string().trim().min(1).max(120).optional(),
    description: z.string().trim().max(1000).optional(),
    policy_id: z.uuid().nullable().optional(),
    enforcement_mode: z.enum(["monitor", "enforce"]).optional(),
  })
  .strict();

export async function updateAgent(ctx: Ctx, userId: string, orgId: string, agentId: string, input: z.infer<typeof agentUpdateSchema>) {
  await requireRole(ctx.db, userId, orgId, "admin");
  await assertPolicyInOrg(ctx.db, input.policy_id, orgId);
  const [a] = await ctx.db.query<AgentRow>("SELECT * FROM agents WHERE id = $1 AND org_id = $2", [agentId, orgId]);
  if (!a) throw notFound("Agent");
  if (a.status === "revoked") throw conflict("AGENT_REVOKED", "A revoked agent cannot be changed");
  const policyChange = "policy_id" in input;
  try {
    await ctx.db.query(
      `UPDATE agents SET name = COALESCE($3, name), description = COALESCE($4, description),
              policy_id = CASE WHEN $5::boolean THEN $6::uuid ELSE policy_id END, enforcement_mode = COALESCE($7, enforcement_mode)
        WHERE id = $1 AND org_id = $2`,
      [agentId, orgId, input.name ?? null, input.description ?? null, policyChange, input.policy_id ?? null, input.enforcement_mode ?? null],
    );
  } catch (e) {
    if (isUnique(e)) throw conflict("AGENT_EXISTS", "An agent with this name already exists in that environment");
    throw e;
  }
  await audit(ctx.db, {
    orgId, actorType: "user", actorId: userId, action: "agent.updated", targetType: "agent", targetId: agentId,
    metadata: { changes: input, previous: { policy_id: a.policy_id, enforcement_mode: a.enforcement_mode } },
  });
}

export async function revokeAgent(ctx: Ctx, userId: string, orgId: string, agentId: string) {
  await ctx.db.tx(async (q) => {
    await requireRole(q, userId, orgId, "admin");
    const rows = await q.query("UPDATE agents SET status = 'revoked', revoked_at = now(), revoked_by = $3 WHERE id = $1 AND org_id = $2 AND status = 'active' RETURNING id", [agentId, orgId, userId]);
    if (rows.length === 0) {
      const [exists] = await q.query("SELECT 1 FROM agents WHERE id = $1 AND org_id = $2", [agentId, orgId]);
      if (!exists) throw notFound("Agent");
      return; // already revoked: idempotent
    }
    await q.query("UPDATE integration_credentials SET revoked_at = now(), revoked_by = $3 WHERE agent_id = $1 AND org_id = $2 AND revoked_at IS NULL", [agentId, orgId, userId]);
    await q.query("UPDATE approvals SET status = 'expired' WHERE agent_id = $1 AND org_id = $2 AND status IN ('pending','approved') AND consumed_at IS NULL", [agentId, orgId]);
    await audit(q, { orgId, actorType: "user", actorId: userId, action: "agent.revoked", targetType: "agent", targetId: agentId });
  });
}

// ---------- credentials ----------

export const credentialCreateSchema = z
  .object({
    agent_id: z.uuid(),
    name: z.string().trim().min(1).max(120),
    scopes: z.array(z.enum(["actions", "events"])).min(1).max(2).optional(),
  })
  .strict();

async function issueCredential(q: Queryable, userId: string, orgId: string, agentId: string, name: string, scopes?: string[]) {
  const [agent] = await q.query<AgentRow>("SELECT * FROM agents WHERE id = $1 AND org_id = $2 FOR UPDATE", [agentId, orgId]);
  if (!agent) throw notFound("Agent");
  if (agent.status === "revoked") throw conflict("AGENT_REVOKED", "Cannot issue credentials for a revoked agent");
  const allowed = agent.integration_type !== "event_reporting" ? ["actions", "events"] : ["events"];
  const final = scopes ?? allowed;
  if (final.some((s) => !allowed.includes(s))) throw badRequest("SCOPE_NOT_ALLOWED", "Agents that only report events cannot hold the 'actions' scope");
  const [n] = await q.query<{ n: number }>("SELECT count(*)::int AS n FROM integration_credentials WHERE agent_id = $1 AND revoked_at IS NULL", [agentId]);
  if (n.n >= 5) throw conflict("TOO_MANY_CREDENTIALS", "An agent can have at most 5 active credentials. Revoke one first.");
  const k = newIntegrationKey();
  const [c] = await q.query<any>(
    `INSERT INTO integration_credentials (org_id, agent_id, name, prefix, secret_hash, scopes, created_by)
     VALUES ($1,$2,$3,$4,$5,$6::text[],$7) RETURNING id, prefix, scopes, created_at`,
    [orgId, agentId, name, k.prefix, k.hash, final, userId],
  );
  await audit(q, { orgId, actorType: "user", actorId: userId, action: "credential.created", targetType: "credential", targetId: c.id, metadata: { agent_id: agentId, scopes: final } });
  // The full key is returned exactly once and never stored or logged.
  return { id: c.id, agent_id: agentId, name, prefix: c.prefix, scopes: c.scopes, created_at: c.created_at, secret: k.key };
}

export async function createCredential(ctx: Ctx, userId: string, orgId: string, input: z.infer<typeof credentialCreateSchema>) {
  return ctx.db.tx(async (q) => {
    await requireRole(q, userId, orgId, "admin");
    return issueCredential(q, userId, orgId, input.agent_id, input.name, input.scopes);
  });
}

export async function revokeCredential(ctx: Ctx, userId: string, orgId: string, credentialId: string) {
  await requireRole(ctx.db, userId, orgId, "admin");
  const rows = await ctx.db.query("UPDATE integration_credentials SET revoked_at = COALESCE(revoked_at, now()), revoked_by = COALESCE(revoked_by, $3) WHERE id = $1 AND org_id = $2 RETURNING id", [credentialId, orgId, userId]);
  if (rows.length === 0) throw notFound("Credential");
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "credential.revoked", targetType: "credential", targetId: credentialId });
}

export async function replaceCredential(ctx: Ctx, userId: string, orgId: string, credentialId: string) {
  return ctx.db.tx(async (q) => {
    await requireRole(q, userId, orgId, "admin");
    const [old] = await q.query<any>("SELECT * FROM integration_credentials WHERE id = $1 AND org_id = $2 FOR UPDATE", [credentialId, orgId]);
    if (!old) throw notFound("Credential");
    if (old.revoked_at) throw conflict("ALREADY_REVOKED", "This credential is already revoked; create a new one instead");
    await q.query("UPDATE integration_credentials SET revoked_at = now(), revoked_by = $2 WHERE id = $1", [credentialId, userId]);
    const fresh = await issueCredential(q, userId, orgId, old.agent_id, old.name, old.scopes);
    await q.query("UPDATE integration_credentials SET replaced_by = $2 WHERE id = $1", [credentialId, fresh.id]);
    await audit(q, { orgId, actorType: "user", actorId: userId, action: "credential.replaced", targetType: "credential", targetId: credentialId, metadata: { new_credential_id: fresh.id } });
    return fresh;
  });
}

// ---------- policies ----------

export const policyCreateSchema = z.object({ name: z.string().trim().min(1).max(120), description: z.string().trim().max(500).default(""), document: z.unknown() }).strict();
export const policyUpdateSchema = z.object({ name: z.string().trim().min(1).max(120).optional(), description: z.string().trim().max(500).optional(), document: z.unknown().optional() }).strict();

const parsePolicyDoc = (doc: unknown): PolicyDocument => {
  const r = policyDocumentSchema.safeParse(doc);
  if (!r.success) throw badRequest("INVALID_POLICY", "The policy document is not valid", r.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })));
  return r.data;
};
export const docHash = (d: PolicyDocument) => createHash("sha256").update(canonicalJson(d)).digest("hex");

export async function createPolicy(ctx: Ctx, userId: string, orgId: string, input: z.infer<typeof policyCreateSchema>) {
  await requireRole(ctx.db, userId, orgId, "admin");
  const doc = parsePolicyDoc(input.document);
  try {
    return await ctx.db.tx(async (q) => {
      const [p] = await q.query<{ id: string }>("INSERT INTO policies (org_id, name, description, created_by) VALUES ($1,$2,$3,$4) RETURNING id", [orgId, input.name, input.description, userId]);
      await q.query("INSERT INTO policy_versions (policy_id, org_id, version, document, document_hash, created_by) VALUES ($1,$2,1,$3::jsonb,$4,$5)", [p.id, orgId, JSON.stringify(doc), docHash(doc), userId]);
      await audit(q, { orgId, actorType: "user", actorId: userId, action: "policy.created", targetType: "policy", targetId: p.id, metadata: { name: input.name, version: 1 } });
      return p;
    });
  } catch (e) {
    if (isUnique(e)) throw conflict("POLICY_EXISTS", "A policy with this name already exists");
    throw e;
  }
}

export async function updatePolicy(ctx: Ctx, userId: string, orgId: string, policyId: string, input: z.infer<typeof policyUpdateSchema>) {
  const doc = input.document !== undefined ? parsePolicyDoc(input.document) : null;
  try {
    return await ctx.db.tx(async (q) => {
      await requireRole(q, userId, orgId, "admin");
      const [p] = await q.query<any>("SELECT * FROM policies WHERE id = $1 AND org_id = $2 FOR UPDATE", [policyId, orgId]);
      if (!p) throw notFound("Policy");
      let version = p.current_version as number;
      if (doc) {
        const [cur] = await q.query<{ document_hash: string }>("SELECT document_hash FROM policy_versions WHERE policy_id = $1 AND version = $2", [policyId, version]);
        if (cur?.document_hash !== docHash(doc)) {
          version += 1;
          await q.query("INSERT INTO policy_versions (policy_id, org_id, version, document, document_hash, created_by) VALUES ($1,$2,$3,$4::jsonb,$5,$6)", [policyId, orgId, version, JSON.stringify(doc), docHash(doc), userId]);
        }
      }
      await q.query("UPDATE policies SET name = COALESCE($3,name), description = COALESCE($4,description), current_version = $5, updated_at = now() WHERE id = $1 AND org_id = $2", [policyId, orgId, input.name ?? null, input.description ?? null, version]);
      await audit(q, { orgId, actorType: "user", actorId: userId, action: "policy.updated", targetType: "policy", targetId: policyId, metadata: { version, previous_version: p.current_version } });
      return { id: policyId, version, changed_version: version !== p.current_version };
    });
  } catch (e) {
    if (isUnique(e)) throw conflict("POLICY_EXISTS", "A policy with this name already exists");
    throw e;
  }
}

export const simulateSchema = z
  .object({
    document: z.unknown(),
    action: z
      .object({
        tool: z.string().regex(/^[a-z0-9][a-z0-9_.-]{0,63}$/),
        operation: z.enum(OPERATIONS),
        resource: z.string().min(1).max(512),
        destination: z.string().max(2048).optional(),
        data_classification: z.enum(CLASSIFICATIONS).optional(),
      })
      .strict(),
    has_valid_approval: z.boolean().optional(),
  })
  .strict();

/** Dry run: pure evaluation, nothing is stored and no budget is consumed. */
export function simulatePolicy(input: z.infer<typeof simulateSchema>) {
  const doc = parsePolicyDoc(input.document);
  return evaluate(doc, input.action, { allowedInWindow: 0, hasValidApproval: input.has_valid_approval ?? false });
}

// ---------- approvals ----------

export const approvalDecisionSchema = z.object({ note: z.string().trim().max(500).optional() }).strict();

/**
 * Only an authenticated human member with sufficient role can decide. Integration credentials have no route here,
 * so a requesting agent can never approve its own request.
 */
export async function decideApproval(ctx: Ctx, userId: string, orgId: string, approvalId: string, verdict: "approve" | "reject", note?: string) {
  const out = await ctx.db.tx(async (q) => {
    const role = await requirePermission(q, userId, orgId, "approvals.decide");
    const [ap] = await q.query<any>(
      `SELECT ap.*, (ap.expires_at < now()) AS request_expired, ar.operation, ar.resource, ar.tool, ag.status AS agent_status, ag.policy_id AS agent_policy_id,
              p.current_version AS current_policy_version
         FROM approvals ap
         JOIN action_requests ar ON ar.id = ap.action_request_id
         JOIN agents ag ON ag.id = ap.agent_id
         LEFT JOIN policies p ON p.id = ag.policy_id
        WHERE ap.id = $1 AND ap.org_id = $2 FOR UPDATE OF ap`,
      [approvalId, orgId],
    );
    if (!ap) throw notFound("Approval");
    if (ap.required_role === "owner" && role !== "owner") throw forbidden("This action requires an owner to approve it");
    if (ap.status !== "pending") return { error: conflict("ALREADY_DECIDED", `This approval is already ${ap.status}`) };
    if (ap.request_expired) {
      await q.query("UPDATE approvals SET status = 'expired' WHERE id = $1", [approvalId]);
      return { error: conflict("APPROVAL_EXPIRED", "This approval request has expired") };
    }
    if (verdict === "approve" && (ap.agent_status !== "active" || ap.agent_policy_id !== ap.policy_id || ap.current_policy_version !== ap.policy_version)) {
      await q.query("UPDATE approvals SET status = 'expired' WHERE id = $1", [approvalId]);
      return { error: conflict("APPROVAL_STALE", "The agent or its policy changed since this was requested. The agent must request approval again.") };
    }
    if (verdict === "approve") {
      await q.query("UPDATE approvals SET status = 'approved', decided_by = $2, decided_at = now(), decision_note = $3, grant_expires_at = now() + make_interval(secs => $4::double precision) WHERE id = $1", [approvalId, userId, note ?? null, APPROVAL_GRANT_SEC]);
    } else {
      await q.query("UPDATE approvals SET status = 'rejected', decided_by = $2, decided_at = now(), decision_note = $3 WHERE id = $1", [approvalId, userId, note ?? null]);
    }
    await audit(q, {
      orgId, actorType: "user", actorId: userId, action: verdict === "approve" ? "approval.approved" : "approval.rejected", targetType: "approval", targetId: approvalId,
      metadata: { tool: ap.tool, operation: ap.operation, resource: ap.resource, action_request_id: ap.action_request_id },
    });
    return { ok: true as const };
  });
  if ("error" in out) throw out.error;
}

// ---------- alerts ----------

export async function setAlertStatus(ctx: Ctx, userId: string, orgId: string, alertId: string, status: "acknowledged" | "resolved") {
  await requirePermission(ctx.db, userId, orgId, "alerts.manage");
  const rows = await ctx.db.query("UPDATE alerts SET status = $3, handled_by = $4, handled_at = now() WHERE id = $1 AND org_id = $2 RETURNING id", [alertId, orgId, status, userId]);
  if (rows.length === 0) throw notFound("Alert");
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: `alert.${status}`, targetType: "alert", targetId: alertId });
}

export { HttpError, normalizeResource };
