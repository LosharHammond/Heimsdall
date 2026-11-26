import { actionDigest } from "../shared/action.js";
import { evaluate, normalizeDestination, type PolicyDocument } from "../shared/policy.js";
import type { GuardianClient, ProtectedAction } from "../sdk/index.js";

/**
 * An in-memory stand-in for the Heimdall service that uses the SAME deterministic engine. It lets the companion's safe
 * protection test run the real ProtectedExecutor and trusted tools against disposable fixtures with no cloud involved.
 * It is a TEST AUTHORITY: it knows nothing about your organization's policies.
 */
export class LocalPolicyClient {
  private store = new Map<string, { decision: any; digest: string; claimed: boolean; action: ProtectedAction }>();
  constructor(private policy: PolicyDocument) {}

  async authorize(requestId: string, action: ProtectedAction) {
    const digest = actionDigest(action);
    const d = evaluate(this.policy, action, { allowedInWindow: 0, hasValidApproval: false });
    const dest = action.destination ? normalizeDestination(action.destination) : null;
    this.store.set(requestId, { decision: d, digest, claimed: false, action });
    return {
      request_id: requestId, action_id: requestId, decision: d.decision, policy_decision: d.decision, reason_code: d.reason_code, explanation: d.explanation,
      policy_version: 1, enforcement_mode: "enforce" as const, action_digest: digest, destination_host: dest && dest.ok ? dest.host : null,
      approval: d.decision === "require_approval" ? { id: "local-test-approval", status: "pending" as const, expires_at: new Date(Date.now() + 60_000).toISOString() } : null, execution: null,
    };
  }
  async getAction(requestId: string) {
    const e = this.store.get(requestId);
    if (!e) throw new Error("unknown");
    return this.authorize(requestId, e.action);
  }
  async claim(requestId: string, digest: string) {
    const e = this.store.get(requestId);
    if (!e || e.decision.decision !== "allow" || e.digest !== digest || e.claimed) return { permitted: false, code: "NOT_PERMITTED", message: "not permitted" };
    e.claimed = true;
    return { permitted: true };
  }
  async reportOutcome() {
    return { ok: true };
  }
  async whoami() {
    return { agent_id: "local", agent_name: "local-selftest", scopes: [], enforcement_mode: "enforce", policy_assigned: true };
  }
  asClient(): GuardianClient {
    return this as unknown as GuardianClient;
  }
}
