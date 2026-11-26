import type { Config } from "../config.js";
import type { Db, Queryable } from "../db.js";
import { redact } from "../../shared/redact.js";

export interface Ctx {
  db: Db;
  config: Config;
  /** Signs policy bundles. Absent => offline bundles are unavailable (503). */
  signer?: import("../signing.js").Signer;
  /** Outbound HTTP for identity providers (discovery, JWKS, token exchange). Tests inject a fake. Default: global fetch. */
  fetch?: typeof fetch;
  /** DNS TXT lookup for domain verification. Tests inject a fake. Default: node:dns. */
  resolveTxt?: (name: string) => Promise<string[][]>;
  /** Sends one email. Tests inject a fake. Default: SMTP_URL through nodemailer (absent => email channels report "not configured"). */
  sendMail?: (m: { to: string[]; subject: string; text: string; html: string }) => Promise<void>;
  /** Sends one Web Push message. Tests inject a fake. Default: the web-push library with the server's own VAPID keys. */
  /** Where the built Windows app lives (default dist/installer). Tests point this at a fixture. */
  installerDir?: string;
  webPush?: (sub: { endpoint: string; keys: { p256dh: string; auth: string } }, payload: string) => Promise<{ statusCode: number }>;
}

export const ROLES = ["owner", "admin", "approver", "auditor", "viewer"] as const;
export type Role = (typeof ROLES)[number];
/**
 * Seniority for "this role or higher" checks. approver and auditor sit beside viewer: they read what a viewer reads and get
 * one extra permission each (see PERMISSIONS), never the admin's power to change agents, keys or policies.
 */
const RANK: Record<Role, number> = { viewer: 1, auditor: 1, approver: 1, admin: 2, owner: 3 };
export const roleAtLeast = (role: Role, min: Role) => RANK[role] >= RANK[min];

/** Permissions that do not follow seniority. Everything else uses roleAtLeast. */
export const PERMISSIONS = {
  "approvals.decide": ["owner", "admin", "approver"],
  "alerts.manage": ["owner", "admin", "approver"],
  "audit.read": ["owner", "admin", "auditor"],
  "security.manage": ["owner"],
} as const satisfies Record<string, readonly Role[]>;
export type Permission = keyof typeof PERMISSIONS;
export const can = (role: Role, perm: Permission) => (PERMISSIONS[perm] as readonly Role[]).includes(role);

export interface AuditInput {
  orgId: string | null;
  actorType: "user" | "credential" | "system";
  actorId?: string | null;
  action: string;
  targetType?: string;
  targetId?: string;
  metadata?: Record<string, unknown>;
}

/** Application-append-only audit trail. Metadata is redacted before persistence. */
export async function audit(q: Queryable, e: AuditInput): Promise<void> {
  await q.query(
    `INSERT INTO audit_entries (org_id, actor_type, actor_id, action, target_type, target_id, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
    [e.orgId, e.actorType, e.actorId ?? null, e.action, e.targetType ?? null, e.targetId ?? null, JSON.stringify(redact(e.metadata ?? {}))],
  );
}

export interface AlertInput {
  orgId: string;
  agentId?: string | null;
  actionRequestId?: string | null;
  kind: string;
  severity: "low" | "medium" | "high";
  title: string;
  detail?: string;
  dedupeKey?: string;
  isDemo?: boolean;
}

/** Repeated occurrences of the same open condition collapse into one alert with a counter. */
export async function raiseAlert(q: Queryable, a: AlertInput): Promise<void> {
  await q.query(
    `INSERT INTO alerts (org_id, agent_id, action_request_id, kind, severity, title, detail, dedupe_key, is_demo)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     ON CONFLICT (org_id, dedupe_key) WHERE dedupe_key IS NOT NULL AND status <> 'resolved'
     DO UPDATE SET occurrences = alerts.occurrences + 1, last_seen_at = now(), detail = EXCLUDED.detail,
                   action_request_id = COALESCE(EXCLUDED.action_request_id, alerts.action_request_id)`,
    [a.orgId, a.agentId ?? null, a.actionRequestId ?? null, a.kind, a.severity, a.title, (a.detail ?? "").slice(0, 500), a.dedupeKey ?? null, a.isDemo ?? false],
  );
}

export function escapeLike(s: string): string {
  return s.replace(/[\\%_]/g, (c) => `\\${c}`);
}

export function pageParams(query: Record<string, string | undefined>, defaultLimit = 25, maxLimit = 100) {
  const limit = Math.min(maxLimit, Math.max(1, Number.parseInt(query.limit ?? "", 10) || defaultLimit));
  const page = Math.min(1000, Math.max(1, Number.parseInt(query.page ?? "", 10) || 1));
  return { limit, offset: (page - 1) * limit, page };
}

export type AgentRow = {
  id: string;
  org_id: string;
  name: string;
  description: string;
  environment: string;
  integration_type: string;
  status: "active" | "revoked";
  policy_id: string | null;
  enforcement_mode: "monitor" | "enforce";
  created_at: Date;
  last_seen_at: Date | null;
  last_authorized_at: Date | null;
  last_enforced_at: Date | null;
  revoked_at: Date | null;
};

export const RECENT_MS = 15 * 60 * 1000;

/**
 * Registration is not connectivity. An agent is only "connected" after it has authenticated successfully,
 * and only "enforcing" after the adapter has confirmed a claim/outcome while the agent is in enforce mode.
 */
export function connectionState(a: AgentRow, now = Date.now()) {
  const seen = a.last_seen_at ? new Date(a.last_seen_at).getTime() : null;
  const recently = seen !== null && now - seen <= RECENT_MS;
  if (a.status === "revoked") return { state: "revoked" as const, label: "Revoked", connected_recently: false };
  if (!seen) return { state: "not_connected" as const, label: "Registered, not connected", connected_recently: false };
  if (a.integration_type === "event_reporting") return { state: "reporting_only" as const, label: "Reporting events only", connected_recently: recently };
  if (a.enforcement_mode === "monitor") return { state: "monitoring" as const, label: "Connected · monitor mode (advisory)", connected_recently: recently };
  if (a.last_enforced_at) return { state: "enforcing" as const, label: "Enforcing through adapter", connected_recently: recently };
  return { state: "connected" as const, label: "Connected · no enforcement confirmed yet", connected_recently: recently };
}

export function agentView(a: AgentRow) {
  return {
    id: a.id,
    name: a.name,
    description: a.description,
    environment: a.environment,
    integration_type: a.integration_type,
    status: a.status,
    policy_id: a.policy_id,
    enforcement_mode: a.enforcement_mode,
    created_at: a.created_at,
    last_seen_at: a.last_seen_at,
    last_authorized_at: a.last_authorized_at,
    last_enforced_at: a.last_enforced_at,
    revoked_at: a.revoked_at,
    connection: connectionState(a),
  };
}
