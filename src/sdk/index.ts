/**
 * Kenuxa Heimdall TypeScript SDK / controlled tool executor.
 *
 * ENFORCEMENT BOUNDARY: this adapter only protects tools that are executed THROUGH it. Resource access
 * (files, databases, APIs) must live inside the registered handlers, and the agent must not hold a direct
 * route to those resources. A compromised application that can bypass this adapter is not protected.
 */
import { randomUUID } from "node:crypto";
import { actionDigest, type ActionRequestInput } from "../shared/action.js";
import { normalizeDestination } from "../shared/policy.js";
import type { OfflineAuthority } from "../executor/offline.js";
import type { FastPathAuthority } from "../executor/fast-path.js";

export { actionDigest, normalizeDestination };

export interface ProtectedAction {
  tool: string;
  operation: ActionRequestInput["operation"];
  resource: string;
  destination?: string;
  data_classification?: ActionRequestInput["data_classification"];
  args?: Record<string, unknown>;
}

export interface GuardianOptions {
  baseUrl: string;
  apiKey: string;
  /** Per-request timeout. Timeouts are treated as "not authorized". Default 5000ms. */
  timeoutMs?: number;
  /** Retries for idempotent calls only (authorize, status, outcome, events). Never used for claim. Default 2. */
  maxRetries?: number;
  fetch?: typeof fetch;
  /** Mark everything sent as a demonstration so the dashboard labels it as such. */
  demo?: boolean;
  adapter?: { name: string; version: string };
}

export class GuardianError extends Error {
  constructor(
    public code: string,
    message: string,
    public status?: number,
    public body?: unknown,
  ) {
    super(message);
  }
}

export interface AuthorizeResponse {
  request_id: string;
  action_id: string;
  decision: "allow" | "deny" | "require_approval";
  policy_decision: "allow" | "deny" | "require_approval";
  reason_code: string;
  explanation: string;
  policy_version: number | null;
  enforcement_mode: "monitor" | "enforce";
  action_digest: string;
  destination_host: string | null;
  approval: { id: string; status: "pending" | "approved" | "rejected" | "expired" | "used"; expires_at: string } | null;
  execution: { status: string; enforcement_confirmed: boolean } | null;
  idempotent_replay?: boolean;
}

function validateAuthorize(b: unknown): AuthorizeResponse {
  const o = b as Record<string, unknown> | null;
  const ok =
    o && typeof o === "object" &&
    ["allow", "deny", "require_approval"].includes(o.decision as string) &&
    typeof o.action_digest === "string" && /^[0-9a-f]{64}$/.test(o.action_digest) &&
    typeof o.request_id === "string" && typeof o.reason_code === "string";
  if (!ok) throw new GuardianError("MALFORMED_RESPONSE", "The authorization service returned an unexpected response");
  return o as unknown as AuthorizeResponse;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export class GuardianClient {
  private timeoutMs: number;
  private maxRetries: number;
  private f: typeof fetch;
  constructor(private opts: GuardianOptions) {
    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.maxRetries = opts.maxRetries ?? 2;
    this.f = opts.fetch ?? fetch;
  }

  private async call(method: "GET" | "POST", path: string, body?: unknown, retry = false): Promise<{ status: number; body: any }> {
    const attempts = retry ? this.maxRetries + 1 : 1;
    let lastErr: unknown;
    for (let i = 0; i < attempts; i++) {
      try {
        const res = await this.f(`${this.opts.baseUrl.replace(/\/$/, "")}${path}`, {
          method,
          headers: { authorization: `Bearer ${this.opts.apiKey}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: AbortSignal.timeout(this.timeoutMs),
          redirect: "error",
        });
        let parsed: any;
        try {
          parsed = await res.json();
        } catch {
          throw new GuardianError("MALFORMED_RESPONSE", "The authorization service returned a non-JSON response", res.status);
        }
        if (res.status >= 500 && i < attempts - 1) {
          lastErr = new GuardianError("SERVER_ERROR", `Server error ${res.status}`, res.status);
        } else return { status: res.status, body: parsed };
      } catch (e) {
        lastErr = e instanceof GuardianError ? e : new GuardianError("UNAVAILABLE", `Could not reach the authorization service: ${(e as Error).message}`);
        if (i >= attempts - 1) break;
      }
      await sleep(200 * 2 ** i);
    }
    throw lastErr instanceof GuardianError ? lastErr : new GuardianError("UNAVAILABLE", "Authorization service unavailable");
  }

  async whoami() {
    const r = await this.call("GET", "/v1/whoami", undefined, true);
    if (r.status !== 200) throw new GuardianError(r.body?.error?.code ?? "AUTH_FAILED", r.body?.error?.message ?? "Authentication failed", r.status, r.body);
    return r.body as { agent_id: string; agent_name: string; scopes: string[]; enforcement_mode: string; policy_assigned: boolean };
  }

  /** Safe to retry: the server treats a repeated request_id with the same action as a replay. */
  async authorize(requestId: string, action: ProtectedAction): Promise<AuthorizeResponse> {
    const payload: ActionRequestInput = { request_id: requestId, ...action, adapter: this.opts.adapter ?? { name: "heimdall-sdk-ts", version: "0.1.0" }, demo: this.opts.demo || undefined };
    const r = await this.call("POST", "/v1/authorize", payload, true);
    if (r.status !== 200) throw new GuardianError(r.body?.error?.code ?? "AUTHORIZATION_FAILED", r.body?.error?.message ?? "Authorization failed", r.status, r.body);
    return validateAuthorize(r.body);
  }

  async getAction(requestId: string): Promise<AuthorizeResponse> {
    const r = await this.call("GET", `/v1/actions/${encodeURIComponent(requestId)}`, undefined, true);
    if (r.status !== 200) throw new GuardianError(r.body?.error?.code ?? "LOOKUP_FAILED", r.body?.error?.message ?? "Lookup failed", r.status, r.body);
    return validateAuthorize(r.body);
  }

  /** NOT retried: a claim is the one-time execution permit. An uncertain claim fails closed. */
  async claim(requestId: string, digest: string): Promise<{ permitted: boolean; code?: string; message?: string }> {
    const r = await this.call("POST", `/v1/actions/${encodeURIComponent(requestId)}/claim`, { action_digest: digest }, false);
    if (r.status === 200 && r.body?.permitted === true) return { permitted: true };
    return { permitted: false, code: r.body?.error?.code ?? "CLAIM_REFUSED", message: r.body?.error?.message ?? "Execution was not permitted" };
  }

  /** Safe to retry: outcome reports are idempotent. */
  async reportOutcome(requestId: string, outcome: { status: "succeeded" | "failed" | "refused"; error_code?: string; detail?: Record<string, unknown> }) {
    const r = await this.call("POST", `/v1/actions/${encodeURIComponent(requestId)}/outcome`, outcome, true);
    if (r.status !== 200) throw new GuardianError(r.body?.error?.code ?? "OUTCOME_FAILED", r.body?.error?.message ?? "Could not record outcome", r.status, r.body);
    return r.body;
  }

  /** Signed, expiring policy bundle for offline enforcement. */
  async getPolicyBundle(): Promise<{ bundle: any; signature: string }> {
    const r = await this.call("GET", "/v1/policy-bundle", undefined, true);
    if (r.status !== 200) throw new GuardianError(r.body?.error?.code ?? "BUNDLE_FAILED", r.body?.error?.message ?? "Could not fetch policy bundle", r.status, r.body);
    return r.body;
  }

  /** The agent's current policy id, version and mode. Cheap; fast-path executors poll it to notice changes quickly. */
  async getPolicyState(): Promise<{ policy_id: string | null; policy_version: number | null; enforcement_mode: "monitor" | "enforce" }> {
    const r = await this.call("GET", "/v1/policy-state", undefined, false);
    if (r.status !== 200) throw new GuardianError(r.body?.error?.code ?? "STATE_FAILED", r.body?.error?.message ?? "Could not read policy state", r.status, r.body);
    return r.body;
  }

  async getSigningKey(): Promise<{ key_id: string; public_key_pem: string }> {
    const r = await this.call("GET", "/v1/signing-key", undefined, true);
    if (r.status !== 200) throw new GuardianError(r.body?.error?.code ?? "KEY_FAILED", "Could not fetch signing key", r.status, r.body);
    return r.body;
  }

  /** Idempotent: records of decisions taken from the cached policy while the service was unreachable. */
  async syncOffline(records: unknown[]): Promise<{ results: Array<{ request_id: string; status: string }> }> {
    const r = await this.call("POST", "/v1/offline-sync", { records }, true);
    if (r.status !== 200) throw new GuardianError(r.body?.error?.code ?? "SYNC_FAILED", r.body?.error?.message ?? "Could not sync", r.status, r.body);
    return r.body;
  }

  /** What this executor attests about itself (shown as evidence in the Protection Center). */
  async reportExecutor(body: { executor_version?: string; roots: Array<{ label: string; prefix?: string }>; egress_enabled: boolean; mode?: "online" | "offline_cache" | "degraded"; cache_expires_at?: string; queued_events?: number }) {
    const r = await this.call("POST", "/v1/executor/report", body, true);
    if (r.status !== 200) throw new GuardianError(r.body?.error?.code ?? "REPORT_FAILED", r.body?.error?.message ?? "Could not report", r.status, r.body);
    return r.body;
  }

  /** Observation only. Reporting an event never blocks or authorizes anything. */
  async sendEvent(event: { event_type: string; tool?: string; operation?: string; resource?: string; summary?: Record<string, unknown>; event_id?: string }) {
    const r = await this.call("POST", "/v1/events", { ...event, demo: this.opts.demo || undefined }, true);
    if (r.status !== 201) throw new GuardianError(r.body?.error?.code ?? "EVENT_FAILED", r.body?.error?.message ?? "Could not record event", r.status, r.body);
    return r.body;
  }
}

export interface HandlerContext {
  requestId: string;
  /** Server-normalized destination host. External-transfer handlers MUST connect only to this host. */
  destinationHost: string | null;
  /** Whatever `prepare` returned (for example the identity of the file that was authorized). */
  binding?: unknown;
}
export type ToolHandler = (action: Readonly<ProtectedAction>, ctx: HandlerContext) => Promise<unknown>;

/** Thrown by a trusted executor when it refuses to run an action that policy allowed (path escape, changed file, private address...). */
export class ExecutorRefusal extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = "ExecutorRefusal";
  }
}

/**
 * A tool with trusted pre- and post-authorization steps.
 *  - prepare: runs BEFORE authorization. May canonicalize the action (for example real-case path) and capture a binding.
 *    The canonical action is what gets authorized, digested, approved and executed.
 *  - verify:  runs after an allow and BEFORE the one-time claim is consumed; refusing here costs nothing.
 *  - execute: runs after the claim; must re-validate everything again (resource changes between authorization and use).
 */
export interface ToolDefinition {
  prepare?(action: Readonly<ProtectedAction>): Promise<{ action: ProtectedAction; binding?: unknown }> | { action: ProtectedAction; binding?: unknown };
  verify?(action: Readonly<ProtectedAction>, ctx: HandlerContext): Promise<void> | void;
  execute: ToolHandler;
}

export type RunResult =
  | { status: "executed"; requestId: string; result: unknown; outcomeReported: boolean; offline?: true; local?: true }
  | { status: "denied"; requestId: string; reasonCode: string; explanation: string; executed: false; refusalReported: boolean; offline?: true; local?: true }
  | { status: "pending_approval"; requestId: string; approvalId: string; expiresAt: string; executed: false }
  | { status: "execution_failed"; requestId: string; error: string; outcomeReported: boolean }
  | { status: "not_authorized"; requestId: string; reasonCode: string; message: string; executed: false };

function deepFreeze<T>(o: T): T {
  if (o && typeof o === "object") {
    Object.freeze(o);
    for (const v of Object.values(o as object)) deepFreeze(v);
  }
  return o;
}

export class ProtectedExecutor {
  constructor(
    private client: GuardianClient,
    private handlers: Record<string, ToolHandler | ToolDefinition>,
    private opts: {
      executionTimeoutMs?: number;
      offline?: OfflineAuthority;
      /** In-process decisions from the signed policy with background audit (docs/FAST-PATH.md). Only approvals go online. */
      fastPath?: FastPathAuthority;
    } = {},
  ) {}

  private lastSync = 0;
  /** After any successful online call: refresh the signed policy cache and flush queued offline records (throttled, best effort). */
  private afterOnline() {
    const off = this.opts.offline;
    if (!off || Date.now() - this.lastSync < 60_000) return;
    this.lastSync = Date.now();
    void off.refresh(this.client).catch(() => undefined);
    void off.flush(this.client).catch(() => undefined);
  }

  private isOutage(e: unknown): boolean {
    const err = e as GuardianError;
    return err instanceof GuardianError && (err.code === "UNAVAILABLE" || err.code === "SERVER_ERROR" || (typeof err.status === "number" && err.status >= 500));
  }

  /**
   * Service unreachable: decide from the signed, unexpired, non-rolled-back cached policy. Approval-required => refused.
   * Everything is recorded in a bounded local outbox and synchronized on reconnect.
   */
  private async runOffline(requestId: string, snapshot: Readonly<ProtectedAction>, digest: string, def: ToolDefinition, binding: unknown): Promise<RunResult> {
    const off = this.opts.offline!;
    const loaded = off.load();
    if (!loaded.ok) {
      return { status: "not_authorized", requestId, reasonCode: `OFFLINE_${loaded.code}`, message: "The service is unreachable and there is no valid signed policy cache, so the action was not run.", executed: false };
    }
    if (!off.hasRoom()) {
      // Never run an action that cannot be recorded: the operator would not be able to see it after reconnect.
      return { status: "not_authorized", requestId, reasonCode: "OFFLINE_OUTBOX_FULL", message: "The offline record queue is full. Reconnect to the service to continue.", executed: false };
    }
    const decidedAt = new Date().toISOString();
    const base = { request_id: requestId, action: { tool: snapshot.tool, operation: snapshot.operation, resource: snapshot.resource, destination: snapshot.destination, args: snapshot.args }, action_digest: digest, policy_version: loaded.bundle.policy_version, decided_at: decidedAt };
    const monitor = loaded.bundle.enforcement_mode === "monitor";
    let d = off.decide(snapshot, loaded.bundle);
    // What the POLICY decided (the server re-evaluates this field): offline refusal of an approval rule is still "require_approval".
    const policyDecision: "allow" | "deny" | "require_approval" = d.reason_code === "APPROVAL_REQUIRED" ? "require_approval" : d.decision;
    if (monitor && d.decision !== "allow") d = { decision: "allow", reason_code: "MONITOR_ONLY", explanation: "Monitor mode (advisory).", matched_rule_id: d.matched_rule_id };
    if (off.used(requestId)) {
      return { status: "denied", requestId, reasonCode: "OFFLINE_ALREADY_USED", explanation: "This request id was already used offline; each permit executes at most once.", executed: false, refusalReported: false, offline: true };
    }
    if (d.decision !== "allow") {
      off.record({ ...base, decision: policyDecision, reason_code: d.reason_code, outcome: { status: "refused", error_code: d.reason_code } });
      return { status: "denied", requestId, reasonCode: d.reason_code, explanation: `Offline (cached policy v${loaded.bundle.policy_version ?? "none"}): ${d.explanation}`, executed: false, refusalReported: false, offline: true };
    }
    // destinationHost comes from the same shared normalizer the server would have used.
    const dn = snapshot.destination ? normalizeDestination(snapshot.destination) : null;
    const destinationHost = dn && dn.ok ? dn.host : null;
    if (def.verify) {
      try {
        await def.verify(snapshot, { requestId, destinationHost, binding });
      } catch (e) {
        const code = e instanceof ExecutorRefusal ? `EXECUTOR_${e.code}` : "EXECUTOR_VERIFY_FAILED";
        off.record({ ...base, decision: policyDecision, reason_code: d.reason_code, outcome: { status: "refused", error_code: code } });
        return { status: "denied", requestId, reasonCode: code, explanation: (e as Error).message, executed: false, refusalReported: false, offline: true };
      }
    }
    if (!off.permit(requestId)) {
      return { status: "denied", requestId, reasonCode: "OFFLINE_ALREADY_USED", explanation: "This request id was already used offline; each permit executes at most once.", executed: false, refusalReported: false, offline: true };
    }
    try {
      const result = await this.withTimeout(def.execute(snapshot, { requestId, destinationHost, binding }));
      off.record({ ...base, decision: policyDecision, reason_code: d.reason_code, outcome: { status: "succeeded" } });
      return { status: "executed", requestId, result, outcomeReported: false, offline: true };
    } catch (e) {
      const code = e instanceof ExecutorRefusal ? `EXECUTOR_REFUSED_${e.code}` : "HANDLER_ERROR";
      off.record({ ...base, decision: policyDecision, reason_code: d.reason_code, outcome: { status: "failed", error_code: code } });
      return { status: "execution_failed", requestId, error: (e as Error).message, outcomeReported: false };
    }
  }

  /**
   * Fast path, no network and no disk on the caller's path: a local allow or deny from the in-memory signed bundle, a local
   * one-time permit, then the handler. The decision and its outcome are queued and sent to the service in the background,
   * where they are re-evaluated. If the audit queue is full the action is refused, never run unrecorded.
   */
  private async runFast(
    requestId: string,
    snapshot: Readonly<ProtectedAction>,
    digest: string,
    def: ToolDefinition,
    binding: unknown,
    fast: Extract<ReturnType<FastPathAuthority["decide"]>, { kind: "decided" }>,
  ): Promise<RunResult> {
    const fp = this.opts.fastPath!;
    const d = fast.decision;
    const base = {
      request_id: requestId,
      action: { tool: snapshot.tool, operation: snapshot.operation, resource: snapshot.resource, destination: snapshot.destination, args: snapshot.args as Record<string, unknown> | undefined },
      action_digest: digest,
      policy_version: fast.bundle.policy_version,
      decided_at: new Date().toISOString(),
      decision: fast.policyDecision,
      reason_code: d.reason_code,
    } as const;
    if (!fp.hasRoom()) {
      fp.noteQueueFullRefusal();
      return { status: "not_authorized", requestId, reasonCode: "AUDIT_QUEUE_FULL", message: "The audit queue is full (the service has been unreachable for a while). The action was not run so that nothing runs unrecorded.", executed: false };
    }
    if (fp.used(requestId)) {
      return { status: "denied", requestId, reasonCode: "ALREADY_USED", explanation: "This request id was already used; each permit executes at most once.", executed: false, refusalReported: false, local: true };
    }
    if (d.decision !== "allow") {
      fp.record({ ...base, outcome: { status: "refused", error_code: d.reason_code } });
      return { status: "denied", requestId, reasonCode: d.reason_code, explanation: d.explanation, executed: false, refusalReported: false, local: true };
    }
    const dn = snapshot.destination ? normalizeDestination(snapshot.destination) : null;
    const destinationHost = dn && dn.ok ? dn.host : null;
    if (def.verify) {
      try {
        await def.verify(snapshot, { requestId, destinationHost, binding });
      } catch (e) {
        const code = e instanceof ExecutorRefusal ? `EXECUTOR_${e.code}` : "EXECUTOR_VERIFY_FAILED";
        fp.record({ ...base, outcome: { status: "refused", error_code: code } });
        return { status: "denied", requestId, reasonCode: code, explanation: (e as Error).message, executed: false, refusalReported: false, local: true };
      }
    }
    if (!fp.permit(requestId)) {
      return { status: "denied", requestId, reasonCode: "ALREADY_USED", explanation: "This request id was already used; each permit executes at most once.", executed: false, refusalReported: false, local: true };
    }
    if (fast.policyDecision === "allow") fp.noteAllowed();
    try {
      const result = await this.withTimeout(def.execute(snapshot, { requestId, destinationHost, binding }));
      fp.record({ ...base, outcome: { status: "succeeded" } });
      return { status: "executed", requestId, result, outcomeReported: false, local: true };
    } catch (e) {
      const code = e instanceof ExecutorRefusal ? `EXECUTOR_REFUSED_${e.code}` : (e as Error).name === "TimeoutError" ? "EXECUTION_TIMEOUT" : "HANDLER_ERROR";
      fp.record({ ...base, outcome: { status: "failed", error_code: code } });
      return { status: "execution_failed", requestId, error: (e as Error).message, outcomeReported: false };
    }
  }

  /**
   * Authorize, then (only if permitted) execute exactly the action that was authorized.
   * Pass the same `requestId` again to resume an action that returned `pending_approval`.
   */
  async run(input: ProtectedAction & { requestId?: string }, wait: { waitForApprovalMs?: number; pollMs?: number } = {}): Promise<RunResult> {
    const { requestId: given, ...rest } = input;
    const requestId = given ?? `req_${randomUUID()}`;
    const entry = this.handlers[rest.tool];
    if (!entry) return { status: "not_authorized", requestId, reasonCode: "NO_HANDLER", message: `No executor is registered for tool '${rest.tool}'`, executed: false };
    const def: ToolDefinition = typeof entry === "function" ? { execute: entry } : entry;
    let binding: unknown;
    let candidate: ProtectedAction = structuredClone(rest);
    if (def.prepare) {
      try {
        const p = await def.prepare(deepFreeze(structuredClone(rest)));
        candidate = structuredClone(p.action);
        binding = p.binding;
      } catch (e) {
        return { status: "not_authorized", requestId, reasonCode: "PREPARE_FAILED", message: (e as Error).message, executed: false };
      }
    }
    const snapshot = deepFreeze(candidate) as Readonly<ProtectedAction>; // later mutation of the caller's object cannot change what runs
    const digest = actionDigest(snapshot);

    if (this.opts.fastPath) {
      // Fast path: decided in-process from the signed policy. Approval-required actions (including a resumed one) and any
      // moment without a valid bundle continue to the service below.
      const fast = this.opts.fastPath.decide(snapshot);
      if (fast.kind === "decided") return this.runFast(requestId, snapshot, digest, def, binding, fast);
    }

    let view: AuthorizeResponse;
    try {
      view = await this.client.authorize(requestId, snapshot);
      this.afterOnline();
    } catch (e) {
      if (this.opts.offline && this.isOutage(e)) return this.runOffline(requestId, snapshot, digest, def, binding);
      return this.failClosed(requestId, e);
    }
    if (view.action_digest !== digest) {
      return { status: "not_authorized", requestId, reasonCode: "DIGEST_MISMATCH", message: "The service bound a different action than the one submitted", executed: false };
    }

    const deadline = Date.now() + (wait.waitForApprovalMs ?? 0);
    while (view.decision === "require_approval" && view.approval?.status === "pending") {
      if (Date.now() >= deadline) return { status: "pending_approval", requestId, approvalId: view.approval.id, expiresAt: view.approval.expires_at, executed: false };
      await sleep(wait.pollMs ?? 1000);
      try {
        view = await this.client.getAction(requestId);
      } catch (e) {
        return this.failClosed(requestId, e);
      }
    }

    const approved = view.decision === "require_approval" && view.approval?.status === "approved";
    if (view.decision === "deny" || (view.decision === "require_approval" && !approved)) {
      const reason = view.decision === "deny" ? view.reason_code : `APPROVAL_${(view.approval?.status ?? "unavailable").toUpperCase()}`;
      const refusalReported = await this.tryReport(requestId, { status: "refused", error_code: reason });
      return { status: "denied", requestId, reasonCode: reason, explanation: view.explanation, executed: false, refusalReported };
    }

    // Trusted pre-claim validation: refusing here does not consume the one-time permit.
    if (def.verify) {
      try {
        await def.verify(snapshot, { requestId, destinationHost: view.destination_host, binding });
      } catch (e) {
        const code = e instanceof ExecutorRefusal ? `EXECUTOR_${e.code}` : "EXECUTOR_VERIFY_FAILED";
        const refusalReported = await this.tryReport(requestId, { status: "refused", error_code: code });
        return { status: "denied", requestId, reasonCode: code, explanation: (e as Error).message, executed: false, refusalReported };
      }
    }

    // Allowed (or approved): obtain the one-time execution claim, bound to the digest of what we are about to run.
    let claim: Awaited<ReturnType<GuardianClient["claim"]>>;
    try {
      claim = await this.client.claim(requestId, actionDigest(snapshot));
    } catch (e) {
      return this.failClosed(requestId, e);
    }
    if (!claim.permitted) {
      const refusalReported = await this.tryReport(requestId, { status: "refused", error_code: claim.code });
      return { status: "denied", requestId, reasonCode: claim.code ?? "CLAIM_REFUSED", explanation: claim.message ?? "Execution was not permitted", executed: false, refusalReported };
    }

    try {
      const result = await this.withTimeout(def.execute(snapshot, { requestId, destinationHost: view.destination_host, binding }));
      const outcomeReported = await this.tryReport(requestId, { status: "succeeded" });
      return { status: "executed", requestId, result, outcomeReported };
    } catch (e) {
      const code = e instanceof ExecutorRefusal ? `EXECUTOR_REFUSED_${e.code}` : (e as Error).name === "TimeoutError" ? "EXECUTION_TIMEOUT" : "HANDLER_ERROR";
      const outcomeReported = await this.tryReport(requestId, { status: "failed", error_code: code });
      return { status: "execution_failed", requestId, error: (e as Error).message, outcomeReported };
    }
  }

  private failClosed(requestId: string, e: unknown): RunResult {
    const err = e as GuardianError;
    return { status: "not_authorized", requestId, reasonCode: err.code ?? "UNAVAILABLE", message: err.message, executed: false };
  }

  private async tryReport(requestId: string, outcome: Parameters<GuardianClient["reportOutcome"]>[1]): Promise<boolean> {
    try {
      await this.client.reportOutcome(requestId, outcome);
      return true;
    } catch {
      return false; // never turns a refusal into an execution; the dashboard shows the missing confirmation
    }
  }

  private async withTimeout<T>(p: Promise<T>): Promise<T> {
    const ms = this.opts.executionTimeoutMs;
    if (!ms) return p;
    let t: NodeJS.Timeout;
    const timeout = new Promise<never>((_, rej) => {
      t = setTimeout(() => rej(Object.assign(new Error("Execution timed out"), { name: "TimeoutError" })), ms);
    });
    try {
      return await Promise.race([p, timeout]);
    } finally {
      clearTimeout(t!);
    }
  }
}
