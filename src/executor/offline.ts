/**
 * Offline operation for the trusted executor: signed policy cache, local one-time permits, bounded outbox.
 *
 * Strategy (documented in docs/OFFLINE.md):
 *  - While the service is reachable every decision is made online. The executor refreshes a SIGNED policy bundle in the background.
 *  - When the service is UNREACHABLE (network error, timeout, 5xx) the executor decides from the cached bundle, using the very same
 *    deterministic engine. Explicit denies, default deny and allow rules behave exactly as online.
 *  - Anything that needs a human (require_approval) is REFUSED offline: an approval can never silently become an allow.
 *  - A 401/403 from the service (revoked key/agent, wrong scope) is a decision, not an outage: no fallback.
 *  - The bundle expires. After expiry the executor refuses everything routed through it and reports degraded protection.
 *    Only calls through the executor are affected; unrelated activity on the machine is never blocked.
 *  - A bundle with a lower policy version than one already accepted is refused (rollback), as is a bad signature or a bundle
 *    issued for another agent/organization.
 *  - Offline decisions are queued in a bounded, redacted outbox and synchronized (idempotently) on reconnect, where the server
 *    re-evaluates them against the policy version used.
 *
 * Limits: someone who can write to the cache directory can delete the rollback marker or the outbox. The directory must be
 * ACL-protected to the signed-in user; this is not a defence against a local administrator.
 */
import { createHash } from "node:crypto";
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson } from "../shared/action.js";
import { evaluate, policyDocumentSchema, type Decision, type PolicyDocument } from "../shared/policy.js";
import { redact } from "../shared/redact.js";
import type { GuardianClient, ProtectedAction } from "../sdk/index.js";

export interface CachedBundle {
  bundle: {
    v: number; key_id: string; org_id: string; agent_id: string; policy_id: string | null; policy_version: number | null;
    document: PolicyDocument | null; enforcement_mode: "monitor" | "enforce"; issued_at: string; expires_at: string;
  };
  signature: string;
}

export type LoadResult =
  | { ok: true; bundle: CachedBundle["bundle"] }
  | { ok: false; code: "NO_CACHE" | "BAD_SIGNATURE" | "EXPIRED" | "WRONG_BINDING" | "ROLLBACK" | "BAD_FORMAT" | "NO_PINNED_KEY" };

export interface OfflineOptions {
  dir: string;
  /** Pinned Ed25519 public key (PEM). If absent it is read from `<dir>/pinned-key.pem`, or pinned on first contact with `pin()`. */
  publicKeyPem?: string;
  /** Pin the cache to this agent. If absent the first accepted bundle pins it. */
  agentId?: string;
  now?: () => number;
  maxOutbox?: number;
  verify: (publicKeyPem: string, data: string, signatureB64: string) => boolean;
}

export interface OfflineRecord {
  request_id: string;
  action: { tool: string; operation: string; resource: string; destination?: string; args?: Record<string, unknown> };
  action_digest: string;
  decision: "allow" | "deny" | "require_approval";
  reason_code: string;
  policy_version: number | null;
  decided_at: string;
  outcome: { status: "succeeded" | "failed" | "refused"; error_code?: string };
}

export class OfflineAuthority {
  private dir: string;
  private now: () => number;
  private maxOutbox: number;

  constructor(private opts: OfflineOptions) {
    this.dir = opts.dir;
    this.now = opts.now ?? Date.now;
    this.maxOutbox = opts.maxOutbox ?? 500;
    mkdirSync(join(this.dir, "permits"), { recursive: true });
  }

  private p = (f: string) => join(this.dir, f);
  private readJson<T>(f: string): T | null {
    try {
      return JSON.parse(readFileSync(this.p(f), "utf8")) as T;
    } catch {
      return null;
    }
  }
  private writeJson(f: string, v: unknown) {
    const tmp = this.p(`${f}.tmp`);
    writeFileSync(tmp, JSON.stringify(v), { mode: 0o600 });
    renameSync(tmp, this.p(f)); // atomic replace: a crash never leaves a half-written cache
  }

  pinnedKey(): string | null {
    if (this.opts.publicKeyPem) return this.opts.publicKeyPem;
    try {
      return readFileSync(this.p("pinned-key.pem"), "utf8");
    } catch {
      return null;
    }
  }

  /** Trust-on-first-use pinning of the service's signing key. Verify the key id shown in the dashboard when you enroll. */
  async pin(client: GuardianClient): Promise<string> {
    const existing = this.pinnedKey();
    if (existing) return existing;
    const k = await client.getSigningKey();
    writeFileSync(this.p("pinned-key.pem"), k.public_key_pem, { mode: 0o600 });
    return k.public_key_pem;
  }

  /** Validates a signed bundle against the pinned key, the agent pin, expiry and the rollback marker. */
  validate(cached: CachedBundle, opts: { checkRollback?: boolean } = {}): LoadResult {
    const key = this.pinnedKey();
    if (!key) return { ok: false, code: "NO_PINNED_KEY" };
    if (!cached?.bundle || typeof cached.signature !== "string" || cached.bundle.v !== 1) return { ok: false, code: "BAD_FORMAT" };
    if (!this.opts.verify(key, canonicalJson(cached.bundle), cached.signature)) return { ok: false, code: "BAD_SIGNATURE" };
    const pin = this.opts.agentId ?? this.readJson<{ agent_id: string; org_id: string }>("meta.json")?.agent_id;
    if (pin && cached.bundle.agent_id !== pin) return { ok: false, code: "WRONG_BINDING" };
    if (this.now() >= new Date(cached.bundle.expires_at).getTime()) return { ok: false, code: "EXPIRED" };
    if (opts.checkRollback !== false) {
      const hi = this.readJson<{ policy_id: string | null; policy_version: number | null; issued_at: string }>("highest.json");
      if (hi && hi.policy_id === cached.bundle.policy_id && (hi.policy_version ?? 0) > (cached.bundle.policy_version ?? 0)) return { ok: false, code: "ROLLBACK" };
      if (hi && hi.policy_id === cached.bundle.policy_id && hi.policy_version === cached.bundle.policy_version && new Date(hi.issued_at).getTime() > new Date(cached.bundle.issued_at).getTime()) return { ok: false, code: "ROLLBACK" };
    }
    return { ok: true, bundle: cached.bundle };
  }

  /** Fetches, verifies and persists a fresh bundle. Returns the validation outcome; a refused bundle never replaces the cache. */
  async refresh(client: GuardianClient): Promise<LoadResult> {
    await this.pin(client);
    const fresh = (await client.getPolicyBundle()) as CachedBundle;
    const v = this.validate(fresh);
    if (!v.ok) return v;
    if (v.bundle.document) policyDocumentSchema.parse(v.bundle.document);
    this.writeJson("bundle.json", fresh);
    this.writeJson("highest.json", { policy_id: v.bundle.policy_id, policy_version: v.bundle.policy_version, issued_at: v.bundle.issued_at });
    this.writeJson("meta.json", { agent_id: v.bundle.agent_id, org_id: v.bundle.org_id });
    return v;
  }

  load(): LoadResult {
    const cached = this.readJson<CachedBundle>("bundle.json");
    if (!cached) return { ok: false, code: "NO_CACHE" };
    return this.validate(cached);
  }

  /** Local, atomic, one-time permit per request id (exclusive create). A second claim of the same id is refused. */
  permit(requestId: string): boolean {
    try {
      closeSync(openSync(this.p(join("permits", createHash("sha256").update(requestId).digest("hex"))), "wx"));
      return true;
    } catch {
      return false;
    }
  }

  used(requestId: string): boolean {
    return existsSync(this.p(join("permits", createHash("sha256").update(requestId).digest("hex"))));
  }

  /** Same deterministic engine as online. Approval-required actions are never allowed offline. */
  decide(action: Readonly<ProtectedAction>, bundle: CachedBundle["bundle"]): Decision {
    if (!bundle.document) return { decision: "deny", reason_code: "NO_POLICY_ASSIGNED", explanation: "The cached bundle has no policy assigned; the default is to deny.", matched_rule_id: null };
    const used = bundle.document.budget ? this.allowedSince(this.now() - bundle.document.budget.window_seconds * 1000) : 0;
    const d = evaluate(bundle.document, action, { allowedInWindow: used, hasValidApproval: false });
    if (d.decision === "require_approval") {
      return { ...d, decision: "deny", reason_code: "APPROVAL_REQUIRED", explanation: "This action needs a human approval, which cannot be obtained while the service is unreachable. It is refused, not allowed." };
    }
    return d;
  }

  private outbox(): OfflineRecord[] {
    try {
      return readFileSync(this.p("outbox.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as OfflineRecord);
    } catch {
      return [];
    }
  }
  private allowedSince(ms: number): number {
    return this.outbox().filter((r) => r.decision === "allow" && new Date(r.decided_at).getTime() >= ms).length;
  }

  record(r: OfflineRecord) {
    const cur = this.outbox();
    if (cur.length >= this.maxOutbox) return false; // bounded: oldest records are kept, newest dropped and counted as dropped
    const safe = { ...r, action: { ...r.action, resource: String(redact(r.action.resource)), destination: r.action.destination ? String(redact(r.action.destination)) : undefined, args: redact(r.action.args ?? {}) as Record<string, unknown> } };
    appendFileSync(this.p("outbox.jsonl"), JSON.stringify(safe) + "\n", { mode: 0o600 });
    return true;
  }

  hasRoom(): boolean {
    return this.outbox().length < this.maxOutbox;
  }

  queued(): number {
    return this.outbox().length;
  }

  /** Sends queued records. Server-side idempotency makes retries and duplicate flushes harmless. */
  async flush(client: GuardianClient): Promise<{ sent: number; mismatches: number }> {
    const recs = this.outbox();
    if (recs.length === 0) return { sent: 0, mismatches: 0 };
    let sent = 0, mismatches = 0;
    for (let i = 0; i < recs.length; i += 100) {
      const res = await client.syncOffline(recs.slice(i, i + 100));
      sent += res.results.filter((r) => r.status === "recorded" || r.status === "duplicate" || r.status === "mismatch").length;
      mismatches += res.results.filter((r) => r.status === "mismatch").length;
    }
    writeFileSync(this.p("outbox.jsonl"), "");
    return { sent, mismatches };
  }

  status() {
    const l = this.load();
    const cached = this.readJson<CachedBundle>("bundle.json");
    return {
      cache: l.ok ? ("fresh" as const) : l.code === "EXPIRED" ? ("expired" as const) : l.code === "NO_CACHE" ? ("none" as const) : ("invalid" as const),
      cache_expires_at: cached?.bundle?.expires_at ?? null,
      queued: this.queued(),
      has_pin: existsSync(this.p("pinned-key.pem")) || !!this.opts.publicKeyPem,
    };
  }
}
