/**
 * Fast path: in-process policy decisions with background audit. Agents are not slowed down.
 *
 * Why: the online path makes up to three sequential network round trips per action (authorize, claim, outcome), each with
 * database writes, before and after the tool runs. On a busy agent that is milliseconds to tens of milliseconds per call.
 *
 * What this does instead (documented in docs/FAST-PATH.md):
 *  - Holds the agent's SIGNED policy bundle in memory, verified once when it arrives (Ed25519, pinned key, agent binding,
 *    expiry, no rollback). Every decision is then the same deterministic engine the server uses, run in-process: no network,
 *    no disk, no await. Typical cost is a few microseconds.
 *  - Allow and deny are decided locally. require_approval is NOT decided locally: those actions go to the service and wait
 *    for a person, exactly as before. They are the only actions that ever pause.
 *  - Every local decision and its outcome go into an in-memory queue that a background timer sends in batches. The server
 *    stores them (source = local_fast), RE-EVALUATES each one against the policy version used, and raises a high-severity
 *    alert on any disagreement, so a tampered executor is caught.
 *  - The bundle is refreshed in the background (default every 30 s). A policy change, a revoked key or a revoked agent takes
 *    effect within that interval. A 401/403 from the service drops the bundle at once and the executor falls back to the
 *    online path, which refuses a revoked credential.
 *  - Nothing here ever blocks the caller on the network. If no valid bundle is loaded (first start, expired, revoked), the
 *    executor uses the normal online path, which stays correct, only slower.
 *
 * Limits, stated plainly:
 *  - Revocation and policy changes are eventually consistent, bounded by `refreshMs` (and the bundle expiry as a hard stop).
 *  - Action budgets are counted per process, not across every process that shares the agent's key.
 *  - One-time permits are per process (request ids are random UUIDs; the server flags any duplicate on sync).
 *  - Audit records still queued when the process is killed (at most `flushMs` worth, by default 250 ms) are lost. Call
 *    `stop()` on shutdown to flush. If the queue is full the action is refused, never run unrecorded.
 *  - Same enforcement boundary as the SDK: only tools executed through the executor are protected.
 */
import { canonicalJson } from "../shared/action.js";
import { evaluate, policyDocumentSchema, type Decision } from "../shared/policy.js";
import { redact } from "../shared/redact.js";
import type { GuardianClient, GuardianError, ProtectedAction } from "../sdk/index.js";
import type { CachedBundle, OfflineRecord } from "./offline.js";

export type Bundle = CachedBundle["bundle"];

export interface FastPathOptions {
  client: GuardianClient;
  /** Verifies an Ed25519 signature over the canonical bundle JSON (use `verifySignature` from the server's signing module). */
  verify: (publicKeyPem: string, data: string, signatureB64: string) => boolean;
  /** Pinned service signing key (PEM). If absent it is fetched once and pinned on first `start()` (trust on first use). */
  publicKeyPem?: string;
  /** Pin decisions to this agent id. If absent, the first accepted bundle pins it. */
  agentId?: string;
  /** How often to fetch a fresh signed bundle (renews its expiry). Default 30 000 ms. */
  refreshMs?: number;
  /**
   * How often to ask the service for the agent's current policy version (a tiny request). A changed version triggers an immediate
   * refresh; a revoked key or agent drops the bundle. Bounds how long a policy change or revocation takes to apply. Default 2 000 ms.
   */
  checkMs?: number;
  /** How often to send queued audit records. Default 250 ms. */
  flushMs?: number;
  /** Records per sync request. Default 500 (the server's maximum). */
  maxBatch?: number;
  /** Queue bound. When full, new actions are refused rather than run unrecorded. Default 50 000. */
  maxQueue?: number;
  /** Request ids remembered for one-time execution. Default 200 000. */
  maxPermits?: number;
  now?: () => number;
  /** Called on background errors (refresh or flush). Never throws into the agent. */
  onError?: (where: "refresh" | "flush", e: unknown) => void;
}

export type FastDecision =
  | { kind: "decided"; decision: Decision; policyDecision: "allow" | "deny"; bundle: Bundle }
  | { kind: "needs_approval"; decision: Decision }
  | { kind: "not_ready"; reason: FastPathState };

export type FastPathState = "starting" | "ready" | "expired" | "revoked" | "no_policy_bundle" | "stopped";

export interface FastPathStats {
  state: FastPathState;
  policy_version: number | null;
  bundle_expires_at: string | null;
  decisions: number;
  queued: number;
  sent: number;
  mismatches: number;
  refused_queue_full: number;
  last_refresh_at: string | null;
  last_flush_at: string | null;
}

interface QueuedRecord extends OfflineRecord {
  source: "local_fast";
}

const AUTH_CODES = new Set(["CREDENTIAL_REVOKED", "CREDENTIAL_INVALID", "AGENT_REVOKED", "UNAUTHORIZED", "FORBIDDEN"]);

export class FastPathAuthority {
  private bundle: Bundle | null = null;
  private key: string | null;
  private agentPin: string | null;
  private highest: { policy_id: string | null; policy_version: number | null; issued_at: number } | null = null;
  private state: FastPathState = "starting";
  private queue: QueuedRecord[] = [];
  private permits = new Set<string>();
  private allowTimes: number[] = []; // allowed decisions inside the budget window (oldest first)
  private allowHead = 0;
  private timers: NodeJS.Timeout[] = [];
  private flushing: Promise<void> | null = null;
  private now: () => number;
  private s = { decisions: 0, sent: 0, mismatches: 0, refused_queue_full: 0, last_refresh_at: null as string | null, last_flush_at: null as string | null };
  private readonly refreshMs: number;
  private readonly checkMs: number;
  private readonly flushMs: number;
  private readonly maxBatch: number;
  private readonly maxQueue: number;
  private readonly maxPermits: number;

  constructor(private opts: FastPathOptions) {
    this.key = opts.publicKeyPem ?? null;
    this.agentPin = opts.agentId ?? null;
    this.now = opts.now ?? Date.now;
    this.refreshMs = opts.refreshMs ?? 30_000;
    this.checkMs = opts.checkMs ?? 2_000;
    this.flushMs = opts.flushMs ?? 250;
    this.maxBatch = Math.min(opts.maxBatch ?? 500, 500);
    this.maxQueue = opts.maxQueue ?? 50_000;
    this.maxPermits = opts.maxPermits ?? 200_000;
  }

  /**
   * Loads the first bundle and starts the background refresh and flush timers (unref'd: they never keep a process alive).
   * Resolves with the state; it never throws. Until a bundle is loaded the executor simply uses the online path.
   */
  async start(): Promise<FastPathState> {
    await this.refresh();
    this.timers.push(setInterval(() => void this.refresh(), this.refreshMs).unref());
    this.timers.push(setInterval(() => void this.flush(), this.flushMs).unref());
    this.timers.push(setInterval(() => void this.checkState(), this.checkMs).unref());
    return this.state;
  }

  /** Stops the timers and sends everything still queued. Call it on shutdown. */
  async stop(): Promise<void> {
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    await this.flush();
    if (this.queue.length) await this.flush();
    this.state = "stopped";
  }

  // ---------- bundle ----------

  /** Verifies a signed bundle: pinned key, signature, format, agent binding, expiry and no rollback. Pure: changes nothing. */
  check(cached: CachedBundle): { ok: true; bundle: Bundle } | { ok: false; code: string } {
    if (!this.key) return { ok: false, code: "NO_PINNED_KEY" };
    if (!cached?.bundle || typeof cached.signature !== "string" || cached.bundle.v !== 1) return { ok: false, code: "BAD_FORMAT" };
    if (!this.opts.verify(this.key, canonicalJson(cached.bundle), cached.signature)) return { ok: false, code: "BAD_SIGNATURE" };
    if (this.agentPin && cached.bundle.agent_id !== this.agentPin) return { ok: false, code: "WRONG_BINDING" };
    if (this.now() >= new Date(cached.bundle.expires_at).getTime()) return { ok: false, code: "EXPIRED" };
    const h = this.highest;
    if (h && h.policy_id === cached.bundle.policy_id) {
      const v = cached.bundle.policy_version ?? 0;
      if ((h.policy_version ?? 0) > v) return { ok: false, code: "ROLLBACK" };
      if (h.policy_version === cached.bundle.policy_version && h.issued_at > new Date(cached.bundle.issued_at).getTime()) return { ok: false, code: "ROLLBACK" };
    }
    if (cached.bundle.document) {
      const parsed = policyDocumentSchema.safeParse(cached.bundle.document);
      if (!parsed.success) return { ok: false, code: "BAD_FORMAT" };
    }
    return { ok: true, bundle: cached.bundle };
  }

  /** Accepts a verified bundle. Exposed for tests and for pushing a bundle obtained another way. */
  accept(cached: CachedBundle): { ok: boolean; code?: string } {
    const v = this.check(cached);
    if (!v.ok) return v;
    this.bundle = v.bundle;
    this.agentPin ??= v.bundle.agent_id;
    this.highest = { policy_id: v.bundle.policy_id, policy_version: v.bundle.policy_version, issued_at: new Date(v.bundle.issued_at).getTime() };
    this.state = v.bundle.document ? "ready" : "no_policy_bundle";
    this.s.last_refresh_at = new Date(this.now()).toISOString();
    return { ok: true };
  }

  /** Fetches and accepts a fresh bundle. Background-safe: never throws, never blocks a decision. */
  async refresh(): Promise<FastPathState> {
    if (this.state === "stopped") return this.state;
    try {
      if (!this.key) this.key = (await this.opts.client.getSigningKey()).public_key_pem;
      const fresh = (await this.opts.client.getPolicyBundle()) as CachedBundle;
      const r = this.accept(fresh);
      if (!r.ok) this.opts.onError?.("refresh", new Error(`Policy bundle refused: ${r.code}`));
    } catch (e) {
      if (isAuthRefusal(e)) this.revoke();
      this.opts.onError?.("refresh", e);
    }
    return this.currentState();
  }

  /** Polls the agent's policy pointer. Refreshes at once when it moved; drops the bundle on a revoked key or agent. Never throws. */
  async checkState(): Promise<FastPathState> {
    if (this.state === "stopped") return this.state;
    try {
      const cur = await this.opts.client.getPolicyState();
      const b = this.bundle;
      if (!b || cur.policy_id !== b.policy_id || cur.policy_version !== b.policy_version || cur.enforcement_mode !== b.enforcement_mode) await this.refresh();
    } catch (e) {
      if (isAuthRefusal(e)) this.revoke();
    }
    return this.currentState();
  }

  /** Drops the bundle immediately (revoked key or agent). Decisions fall back to the online path, which refuses them. */
  revoke() {
    this.bundle = null;
    this.state = "revoked";
  }

  private currentState(): FastPathState {
    if (this.state === "ready" && this.bundle && this.now() >= new Date(this.bundle.expires_at).getTime()) this.state = "expired";
    return this.state;
  }

  // ---------- the hot path: synchronous, no I/O ----------

  /** Decides an action from the in-memory bundle. Synchronous; does no I/O. */
  decide(action: Readonly<ProtectedAction>): FastDecision {
    const st = this.currentState();
    const b = this.bundle;
    if (st !== "ready" || !b || !b.document) return { kind: "not_ready", reason: st === "ready" ? "no_policy_bundle" : st };
    const doc = b.document;
    let used = 0;
    if (doc.budget) used = this.allowedInWindow(doc.budget.window_seconds * 1000);
    const d = evaluate(doc, action, { allowedInWindow: used, hasValidApproval: false });
    this.s.decisions++;
    if (d.decision === "require_approval") return { kind: "needs_approval", decision: d };
    if (b.enforcement_mode === "monitor" && d.decision !== "allow") {
      return { kind: "decided", policyDecision: d.decision, bundle: b, decision: { decision: "allow", reason_code: "MONITOR_ONLY", explanation: `Monitor mode (advisory): ${d.explanation}`, matched_rule_id: d.matched_rule_id, classification: d.classification } };
    }
    return { kind: "decided", policyDecision: d.decision, bundle: b, decision: d };
  }

  /** Counts an allowed action toward the policy budget (per process). */
  noteAllowed() {
    this.allowTimes.push(this.now());
  }

  private allowedInWindow(windowMs: number): number {
    const from = this.now() - windowMs;
    while (this.allowHead < this.allowTimes.length && this.allowTimes[this.allowHead] < from) this.allowHead++;
    if (this.allowHead > 4096 && this.allowHead * 2 > this.allowTimes.length) {
      this.allowTimes = this.allowTimes.slice(this.allowHead);
      this.allowHead = 0;
    }
    return this.allowTimes.length - this.allowHead;
  }

  /** One-time permit for a request id, in memory. A repeated id in this process is refused. */
  permit(requestId: string): boolean {
    if (this.permits.has(requestId)) return false;
    if (this.permits.size >= this.maxPermits) this.permits.delete(this.permits.values().next().value as string);
    this.permits.add(requestId);
    return true;
  }

  used(requestId: string): boolean {
    return this.permits.has(requestId);
  }

  hasRoom(): boolean {
    return this.queue.length < this.maxQueue;
  }

  /** Queues an audit record (O(1)). Redaction happens at send time, off the hot path. Returns false when the queue is full. */
  record(r: OfflineRecord): boolean {
    if (this.queue.length >= this.maxQueue) {
      this.s.refused_queue_full++;
      return false;
    }
    this.queue.push({ ...r, source: "local_fast" });
    return true;
  }

  noteQueueFullRefusal() {
    this.s.refused_queue_full++;
  }

  // ---------- background audit ----------

  /** Sends queued records in batches. Concurrent calls share one run. Never throws. */
  flush(): Promise<void> {
    if (this.flushing) return this.flushing;
    this.flushing = this.flushNow().finally(() => {
      this.flushing = null;
    });
    return this.flushing;
  }

  private async flushNow() {
    while (this.queue.length) {
      const batch = this.takeBatch();
      try {
        const res = await this.opts.client.syncOffline(batch.map(toWire));
        this.s.sent += batch.length;
        this.s.mismatches += res.results.filter((x) => x.status === "mismatch").length;
        this.s.last_flush_at = new Date(this.now()).toISOString();
      } catch (e) {
        if (isAuthRefusal(e)) this.revoke();
        // Put the batch back at the front (bounded) and try again on the next tick.
        const room = Math.max(0, this.maxQueue - this.queue.length);
        this.queue.unshift(...batch.slice(0, room));
        this.opts.onError?.("flush", e);
        return;
      }
    }
  }

  /** Up to `maxBatch` records and about 3 MiB of JSON: the service accepts 4 MiB per sync request. */
  private takeBatch(): QueuedRecord[] {
    let bytes = 0;
    let n = 0;
    while (n < this.queue.length && n < this.maxBatch) {
      const size = JSON.stringify(this.queue[n]).length + 1;
      if (n > 0 && bytes + size > 3 * 1024 * 1024) break;
      bytes += size;
      n++;
    }
    return this.queue.splice(0, n);
  }

  stats(): FastPathStats {
    return {
      state: this.currentState(),
      policy_version: this.bundle?.policy_version ?? null,
      bundle_expires_at: this.bundle?.expires_at ?? null,
      decisions: this.s.decisions,
      queued: this.queue.length,
      sent: this.s.sent,
      mismatches: this.s.mismatches,
      refused_queue_full: this.s.refused_queue_full,
      last_refresh_at: this.s.last_refresh_at,
      last_flush_at: this.s.last_flush_at,
    };
  }
}

function toWire(r: QueuedRecord) {
  return {
    ...r,
    action: {
      tool: r.action.tool,
      operation: r.action.operation,
      resource: String(redact(r.action.resource)),
      destination: r.action.destination ? String(redact(r.action.destination)) : undefined,
      args: r.action.args ? (redact(r.action.args) as Record<string, unknown>) : undefined,
    },
  };
}

function isAuthRefusal(e: unknown): boolean {
  const err = e as GuardianError;
  return !!err && (err.status === 401 || err.status === 403 || AUTH_CODES.has(err.code));
}
