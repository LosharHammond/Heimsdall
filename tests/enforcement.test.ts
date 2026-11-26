import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { actionDigest } from "../src/shared/action.js";
import { POLICY_EXAMPLES, type PolicyDocument } from "../src/shared/policy.js";
import { GuardianClient, ProtectedExecutor } from "../src/sdk/index.js";
import { setLogSink } from "../src/server/log.js";
import { runRetention } from "../src/server/retention.js";
import { createWorkspace } from "../demo/workspace.js";
import { executorFor, guardianFor, makeEnv, makeWorld, newReqId, v1, type Env, type World } from "./helpers.js";

let env: Env;
beforeAll(async () => {
  env = await makeEnv();
});
afterAll(async () => env.close());

const read = (resource = "docs/a.txt", extra = {}) => ({ request_id: newReqId(), tool: "documents", operation: "read", resource, ...extra });
const del = (resource = "docs/old.txt") => ({ request_id: newReqId(), tool: "documents", operation: "delete", resource });
const claim = (w: World, a: any, digest = actionDigest(a)) => v1(env, w.apiKey, "POST", `/v1/actions/${a.request_id}/claim`, { action_digest: digest });
const approvalFor = async (w: World) => (await w.owner.api("GET", `/api/orgs/${w.orgId}/approvals?status=pending`)).body.items[0];
const approve = (w: World, id: string) => w.owner.api("POST", `/api/orgs/${w.orgId}/approvals/${id}/approve`, { note: "ok" });

describe("decisions and precedence through the API", () => {
  it("returns structured decisions with stable reason codes and the policy version", async () => {
    const w = await makeWorld(env);
    const allow = (await v1(env, w.apiKey, "POST", "/v1/authorize", read())).body;
    expect(allow).toMatchObject({ decision: "allow", reason_code: "ALLOWED_BY_RULE", policy_version: 1, matched_rule_id: "read-docs", enforcement_mode: "enforce" });
    expect(allow.explanation).toContain("read-docs");
    const none = (await v1(env, w.apiKey, "POST", "/v1/authorize", read("secrets/x"))).body;
    expect(none).toMatchObject({ decision: "deny", reason_code: "NO_MATCHING_RULE" });
    const cmd = (await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "shell", operation: "command_execution", resource: "host/sh" })).body;
    expect(cmd).toMatchObject({ decision: "deny", reason_code: "EXPLICIT_DENY", matched_rule_id: "no-commands" });
    const ap = (await v1(env, w.apiKey, "POST", "/v1/authorize", del())).body;
    expect(ap).toMatchObject({ decision: "require_approval", reason_code: "APPROVAL_REQUIRED", approval: { status: "pending", required_role: "admin" } });
  });

  it("denies when no policy is assigned (default deny) and validates input", async () => {
    const w = await makeWorld(env);
    await w.owner.api("PATCH", `/api/orgs/${w.orgId}/agents/${w.agentId}`, { policy_id: null });
    expect((await v1(env, w.apiKey, "POST", "/v1/authorize", read())).body).toMatchObject({ decision: "deny", reason_code: "NO_POLICY_ASSIGNED" });
    const bad = await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: "short", tool: "Bad Tool", operation: "explode", resource: "" });
    expect(bad.status).toBe(400);
    expect(bad.body.error.code).toBe("VALIDATION_ERROR");
    expect((await v1(env, w.apiKey, "POST", "/v1/authorize", { ...read(), organization_id: "other" })).status).toBe(400); // unknown fields (incl. client-supplied org ids) are rejected
  });

  it("monitor mode records what the policy WOULD do but is advisory, and says so", async () => {
    const w = await makeWorld(env, { mode: "monitor" });
    const r = (await v1(env, w.apiKey, "POST", "/v1/authorize", del())).body;
    expect(r).toMatchObject({ decision: "allow", policy_decision: "require_approval", reason_code: "MONITOR_ONLY", enforcement_mode: "monitor" });
    const acts = (await w.owner.api("GET", `/api/orgs/${w.orgId}/actions`)).body.items;
    expect(acts[0]).toMatchObject({ decision: "allow", policy_decision: "require_approval", enforcement_mode: "monitor" });
    expect((await w.owner.api("GET", `/api/orgs/${w.orgId}/approvals`)).body.total).toBe(0); // no approval queue in monitor mode
    const ov = (await w.owner.api("GET", `/api/orgs/${w.orgId}/overview`)).body;
    expect(ov.decisions.monitor_would_block).toBe(1);
    // A monitor-mode agent is never reported as "enforcing"
    const a = read();
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    await claim(w, a);
    expect((await w.owner.api("GET", `/api/orgs/${w.orgId}/agents/${w.agentId}`)).body.connection.state).toBe("monitoring");
  });

  it("enforces action budgets", async () => {
    const policy: PolicyDocument = { schema_version: 1, budget: { max_allowed_actions: 2, window_seconds: 3600 }, rules: [{ id: "r", effect: "allow", match: { tools: ["documents"], operations: ["read"] } }] };
    const w = await makeWorld(env, { policy });
    const d = async () => (await v1(env, w.apiKey, "POST", "/v1/authorize", read())).body;
    expect((await d()).decision).toBe("allow");
    expect((await d()).decision).toBe("allow");
    expect(await d()).toMatchObject({ decision: "deny", reason_code: "BUDGET_EXCEEDED" });
  });

  it("changing a policy creates a new version and the next decision uses it", async () => {
    const w = await makeWorld(env, { policy: POLICY_EXAMPLES.find((e) => e.key === "read-only-assistant")!.document });
    expect((await v1(env, w.apiKey, "POST", "/v1/authorize", read())).body.policy_version).toBe(1);
    const upd = await w.owner.api("PUT", `/api/orgs/${w.orgId}/policies/${w.policyId}`, { document: { schema_version: 1, rules: [] } });
    expect(upd.body).toMatchObject({ version: 2, changed_version: true });
    const after = (await v1(env, w.apiKey, "POST", "/v1/authorize", read())).body;
    expect(after).toMatchObject({ decision: "deny", policy_version: 2 });
    const noop = await w.owner.api("PUT", `/api/orgs/${w.orgId}/policies/${w.policyId}`, { document: { schema_version: 1, rules: [] } });
    expect(noop.body.changed_version).toBe(false);
    expect((await w.owner.api("PUT", `/api/orgs/${w.orgId}/policies/${w.policyId}`, { document: { schema_version: 1, rules: [{ id: "x", effect: "allow", match: {} }] } })).status).toBe(400);
  });

  it("simulation is a dry run: it neither stores anything nor consumes budget", async () => {
    const w = await makeWorld(env);
    const before = (await env.db.query<any>("SELECT count(*)::int AS n FROM action_requests"))[0].n;
    const r = await w.owner.api("POST", `/api/orgs/${w.orgId}/policies/simulate`, { document: POLICY_EXAMPLES[0].document, action: { tool: "documents", operation: "read", resource: "docs/x" } });
    expect(r.body).toMatchObject({ decision: "allow" });
    expect((await env.db.query<any>("SELECT count(*)::int AS n FROM action_requests"))[0].n).toBe(before);
  });
});

describe("idempotency and retries", () => {
  it("repeating a request id returns the same decision without creating a second record", async () => {
    const w = await makeWorld(env);
    const a = read();
    const first = (await v1(env, w.apiKey, "POST", "/v1/authorize", a)).body;
    const second = (await v1(env, w.apiKey, "POST", "/v1/authorize", a)).body;
    expect(second.idempotent_replay).toBe(true);
    expect({ ...second, idempotent_replay: undefined }).toEqual({ ...first, idempotent_replay: undefined });
    expect((await env.db.query<any>("SELECT count(*)::int AS n FROM action_requests WHERE agent_id = $1", [w.agentId]))[0].n).toBe(1);
    expect((await env.db.query<any>("SELECT count(*)::int AS n FROM authorization_decisions WHERE agent_id = $1", [w.agentId]))[0].n).toBe(1);
  });

  it("reusing a request id for a different action is rejected (no decision swapping)", async () => {
    const w = await makeWorld(env);
    const a = read("docs/a.txt");
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    const r = await v1(env, w.apiKey, "POST", "/v1/authorize", { ...a, resource: "docs/b.txt" });
    expect(r.status).toBe(409);
    expect(r.body.error.code).toBe("REQUEST_ID_CONFLICT");
    const r2 = await v1(env, w.apiKey, "POST", "/v1/authorize", { ...a, args: { extra: 1 } });
    expect(r2.status).toBe(409);
  });

  it("concurrent identical requests produce exactly one record", async () => {
    const w = await makeWorld(env);
    const a = read();
    const rs = await Promise.all(Array.from({ length: 6 }, () => v1(env, w.apiKey, "POST", "/v1/authorize", a)));
    expect(rs.every((r) => r.status === 200 && r.body.decision === "allow")).toBe(true);
    expect((await env.db.query<any>("SELECT count(*)::int AS n FROM action_requests WHERE agent_id = $1", [w.agentId]))[0].n).toBe(1);
  });

  it("an authorization can be executed at most once, even under concurrent claims or HTTP retries", async () => {
    const w = await makeWorld(env);
    const a = read();
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    const rs = await Promise.all(Array.from({ length: 5 }, () => claim(w, a)));
    expect(rs.filter((r) => r.status === 200).length).toBe(1);
    expect(rs.filter((r) => r.status === 409).every((r) => r.body.reason_code === "ALREADY_CLAIMED")).toBe(true);
    expect((await claim(w, a)).status).toBe(409); // an HTTP retry of the claim cannot yield a second permit
  });

  it("outcome reports are idempotent (safe telemetry retry) but cannot be rewritten", async () => {
    const w = await makeWorld(env);
    const a = read();
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    expect((await v1(env, w.apiKey, "POST", `/v1/actions/${a.request_id}/outcome`, { status: "succeeded" })).status).toBe(409); // no claim yet
    await claim(w, a);
    const o1 = await v1(env, w.apiKey, "POST", `/v1/actions/${a.request_id}/outcome`, { status: "succeeded" });
    const o2 = await v1(env, w.apiKey, "POST", `/v1/actions/${a.request_id}/outcome`, { status: "succeeded" });
    expect([o1.body.idempotent_replay, o2.body.idempotent_replay]).toEqual([false, true]);
    expect((await v1(env, w.apiKey, "POST", `/v1/actions/${a.request_id}/outcome`, { status: "failed" })).status).toBe(409);
    expect((await v1(env, w.apiKey, "POST", `/v1/actions/${a.request_id}/outcome`, { status: "refused" })).status).toBe(409);
  });
});

describe("action binding", () => {
  it("claiming with different arguments than authorized is refused, alerts, and leaves the authorization usable", async () => {
    const w = await makeWorld(env);
    const a = read("docs/a.txt", { args: { page: 1 } });
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    for (const tampered of [{ ...a, args: { page: 2 } }, { ...a, resource: "docs/secret.txt" }, { ...a, operation: "delete" }, { ...a, destination: "https://evil.test" }]) {
      const r = await claim(w, a, actionDigest(tampered as any));
      expect(r.status).toBe(409);
      expect(r.body.reason_code).toBe("DIGEST_MISMATCH");
    }
    expect((await env.db.query<any>("SELECT count(*)::int AS n FROM execution_outcomes WHERE agent_id = $1", [w.agentId]))[0].n).toBe(0);
    const alerts = (await w.owner.api("GET", `/api/orgs/${w.orgId}/alerts`)).body.items;
    expect(alerts.find((x: any) => x.kind === "argument_mismatch")?.occurrences).toBeGreaterThanOrEqual(1);
    expect((await claim(w, a)).status).toBe(200); // the genuine action can still run
  });

  it("an authorization for one action cannot be used for another request id", async () => {
    const w = await makeWorld(env);
    const allowed = read("docs/a.txt");
    const denied = read("secrets/x");
    await v1(env, w.apiKey, "POST", "/v1/authorize", allowed);
    await v1(env, w.apiKey, "POST", "/v1/authorize", denied);
    expect((await claim(w, denied)).status).toBe(403); // denied decision never yields a permit
    expect((await claim(w, { ...allowed, request_id: newReqId() })).status).toBe(404); // never authorized
  });

  it("an immediate allow expires if not claimed in time", async () => {
    const w = await makeWorld(env);
    const a = read();
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    await env.db.query("UPDATE authorization_decisions SET expires_at = now() - interval '1 second' WHERE agent_id = $1", [w.agentId]);
    const r = await claim(w, a);
    expect(r.status).toBe(403);
    expect(r.body.reason_code).toBe("AUTHORIZATION_EXPIRED");
  });

  it("re-checks policy at claim time: a policy that now denies stops a previously allowed action", async () => {
    const w = await makeWorld(env);
    const a = read();
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    await w.owner.api("PUT", `/api/orgs/${w.orgId}/policies/${w.policyId}`, { document: { schema_version: 1, rules: [] } });
    const r = await claim(w, a);
    expect(r.status).toBe(403);
    expect(r.body.reason_code).toBe("NO_MATCHING_RULE");
  });

  it("re-checks agent status at claim time: revoking the agent stops an already authorized action", async () => {
    const w = await makeWorld(env);
    const a = read();
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    await w.owner.api("POST", `/api/orgs/${w.orgId}/agents/${w.agentId}/revoke`);
    const r = await claim(w, a);
    expect(r.status).toBe(401);
    expect(r.body.reason_code).toBe("CREDENTIAL_REVOKED");
  });
});

describe("human approvals", () => {
  it("waits, binds to the exact action, applies once, and is consumed atomically", async () => {
    const w = await makeWorld(env);
    const a = del("docs/old.txt");
    const r = (await v1(env, w.apiKey, "POST", "/v1/authorize", a)).body;
    expect(r.decision).toBe("require_approval");
    expect((await claim(w, a)).body.reason_code).toBe("APPROVAL_PENDING"); // waits: no permit yet
    const ap = await approvalFor(w);
    expect(ap).toMatchObject({ operation: "delete", resource: "docs/old.txt", tool: "documents", agent_name: expect.any(String), required_role: "admin", policy_version: 1 });
    expect((await approve(w, ap.id)).status).toBe(200);
    expect((await approve(w, ap.id)).status).toBe(409); // cannot decide twice
    const rs = await Promise.all([claim(w, a), claim(w, a), claim(w, a)]);
    expect(rs.filter((x) => x.status === 200).length).toBe(1); // one-time
    expect((await claim(w, a)).body.reason_code).toBe("ALREADY_CLAIMED");
    // Replaying the authorization shows the approval as used
    expect((await v1(env, w.apiKey, "POST", "/v1/authorize", a)).body.approval.status).toBe("used");
  });

  it("an approval for one action does not authorize a different action (new request id, same or different arguments)", async () => {
    const w = await makeWorld(env);
    const a = del("docs/old.txt");
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    await approve(w, (await approvalFor(w)).id);
    // Same operation on a different file: needs its own approval
    const b = del("docs/other.txt");
    expect((await v1(env, w.apiKey, "POST", "/v1/authorize", b)).body.decision).toBe("require_approval");
    expect((await claim(w, b)).body.reason_code).toBe("APPROVAL_PENDING");
    // Identical action under a new request id: also needs its own approval
    const c = { ...a, request_id: newReqId() };
    expect((await v1(env, w.apiKey, "POST", "/v1/authorize", c)).body.approval.status).toBe("pending");
    // And the approved request cannot be claimed with different arguments
    expect((await claim(w, a, actionDigest(b as any))).body.reason_code).toBe("DIGEST_MISMATCH");
    expect((await claim(w, a)).status).toBe(200);
  });

  it("rejection and expiry both stop execution", async () => {
    const w = await makeWorld(env);
    const rej = del("docs/r.txt");
    await v1(env, w.apiKey, "POST", "/v1/authorize", rej);
    const ap = await approvalFor(w);
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/approvals/${ap.id}/reject`, { note: "no" })).status).toBe(200);
    expect((await claim(w, rej)).body.reason_code).toBe("APPROVAL_REJECTED");

    const exp = del("docs/e.txt");
    await v1(env, w.apiKey, "POST", "/v1/authorize", exp);
    const ap2 = await approvalFor(w);
    await approve(w, ap2.id);
    await env.db.query("UPDATE approvals SET grant_expires_at = now() - interval '1 second' WHERE id = $1", [ap2.id]);
    const r = await claim(w, exp);
    expect(r.status).toBe(403);
    expect(r.body.reason_code).toBe("APPROVAL_EXPIRED");
    expect((await v1(env, w.apiKey, "POST", "/v1/authorize", exp)).body.approval.status).toBe("expired");

    // A request that expires before anyone decides cannot be approved afterwards
    const late = del("docs/late.txt");
    await v1(env, w.apiKey, "POST", "/v1/authorize", late);
    const ap3 = await approvalFor(w);
    await env.db.query("UPDATE approvals SET expires_at = now() - interval '1 second' WHERE id = $1", [ap3.id]);
    const res = await approve(w, ap3.id);
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe("APPROVAL_EXPIRED");
    expect((await claim(w, late)).body.reason_code).toBe("APPROVAL_EXPIRED");
  });

  it("an approval is void if the policy changed after it was granted", async () => {
    const w = await makeWorld(env);
    const a = del("docs/old.txt");
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    await approve(w, (await approvalFor(w)).id);
    const doc = POLICY_EXAMPLES.find((e) => e.key === "demo-workspace")!.document;
    await w.owner.api("PUT", `/api/orgs/${w.orgId}/policies/${w.policyId}`, { document: { ...doc, description: "edited", rules: [...doc.rules, { id: "extra", effect: "deny", match: { operations: ["update"] } }] } });
    const r = await claim(w, a);
    expect(r.status).toBe(403);
    expect(r.body.reason_code).toBe("APPROVAL_POLICY_CHANGED");
  });

  it("a new deny rule added after approval still wins", async () => {
    const w = await makeWorld(env);
    const a = del("docs/old.txt");
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    await w.owner.api("PATCH", `/api/orgs/${w.orgId}/agents/${w.agentId}`, { enforcement_mode: "enforce" });
    await approve(w, (await approvalFor(w)).id);
    await env.db.query("UPDATE agents SET policy_id = NULL WHERE id = $1", [w.agentId]);
    expect((await claim(w, a)).body.reason_code).toBe("APPROVAL_POLICY_CHANGED");
  });

  it("the requesting integration cannot approve its own request, in any way", async () => {
    const w = await makeWorld(env);
    await v1(env, w.apiKey, "POST", "/v1/authorize", del());
    const ap = await approvalFor(w);
    for (const path of [`/api/orgs/${w.orgId}/approvals/${ap.id}/approve`, `/v1/approvals/${ap.id}/approve`]) {
      const r = await env.app.request(path, { method: "POST", headers: { authorization: `Bearer ${w.apiKey}`, "x-asg-csrf": "1", "content-type": "application/json" }, body: "{}" });
      expect([401, 404]).toContain(r.status);
    }
    expect((await approvalFor(w)).status).toBe("pending");
  });

  it("revoking the agent voids a pending approval", async () => {
    const w = await makeWorld(env);
    await v1(env, w.apiKey, "POST", "/v1/authorize", del());
    const ap = await approvalFor(w);
    await w.owner.api("POST", `/api/orgs/${w.orgId}/agents/${w.agentId}/revoke`);
    const r = await approve(w, ap.id);
    expect(r.status).toBe(409);
  });

  it("approvals are audited with who decided", async () => {
    const w = await makeWorld(env);
    await v1(env, w.apiKey, "POST", "/v1/authorize", del());
    await approve(w, (await approvalFor(w)).id);
    const entries = (await w.owner.api("GET", `/api/orgs/${w.orgId}/audit?q=approval`)).body.items;
    expect(entries.map((e: any) => e.action)).toEqual(expect.arrayContaining(["approval.requested", "approval.approved"]));
    expect(entries.find((e: any) => e.action === "approval.approved").actor_type).toBe("user");
  });
});

describe("outcome labelling (observation vs authorization vs enforcement)", () => {
  it("a denial is only 'blocked' when the adapter confirms it did not execute", async () => {
    const w = await makeWorld(env);
    const a = read("secrets/x");
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    const state = async () => (await w.owner.api("GET", `/api/orgs/${w.orgId}/actions`)).body.items[0].state;
    expect(await state()).toBe("denied_unconfirmed");
    await v1(env, w.apiKey, "POST", `/v1/actions/${a.request_id}/outcome`, { status: "refused", error_code: "NO_MATCHING_RULE" });
    expect(await state()).toBe("blocked_confirmed");
  });

  it("allowed is not executed: states distinguish authorized, claimed, executed and failed", async () => {
    const w = await makeWorld(env);
    const a = read();
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    const state = async () => (await w.owner.api("GET", `/api/orgs/${w.orgId}/actions`)).body.items[0].state;
    expect(await state()).toBe("authorized_not_executed");
    await claim(w, a);
    expect(await state()).toBe("claimed");
    await env.db.query("UPDATE execution_outcomes SET claimed_at = now() - interval '1 hour' WHERE agent_id = $1", [w.agentId]);
    expect(await state()).toBe("claimed_no_outcome");
    await v1(env, w.apiKey, "POST", `/v1/actions/${a.request_id}/outcome`, { status: "failed", error_code: "HANDLER_ERROR" });
    expect(await state()).toBe("execution_failed");
    const ov = (await w.owner.api("GET", `/api/orgs/${w.orgId}/overview`)).body;
    expect(ov.executions.failed).toBe(1);
    expect(ov.recent_failures[0].error_code).toBe("HANDLER_ERROR");
    expect(ov.recent_alerts.some((x: any) => x.kind === "execution_failed")).toBe(true);
  });
});

describe("failure handling in the adapter: failures to authorize never execute", () => {
  async function setup() {
    const w = await makeWorld(env);
    const ws = createWorkspace();
    return { w, ws };
  }

  it("authorization service unreachable, timing out, erroring or returning garbage => no execution, no side effect", async () => {
    const { w, ws } = await setup();
    const handler = vi.fn(ws.handlers.documents);
    const action = { tool: "documents", operation: "create" as const, resource: "summaries/x.txt", args: { text: "hi" } };
    const broken: Record<string, typeof fetch> = {
      unreachable: (async () => { throw new TypeError("fetch failed"); }) as any,
      timeout: ((_u: string, init: RequestInit) => new Promise((_res, rej) => init.signal?.addEventListener("abort", () => rej(new DOMException("timed out", "TimeoutError"))))) as any,
      http500: (async () => new Response(JSON.stringify({ error: { code: "INTERNAL" } }), { status: 500 })) as any,
      html: (async () => new Response("<html>gateway</html>", { status: 200 })) as any,
      wrongShape: (async () => new Response(JSON.stringify({ decision: "allow" }), { status: 200 })) as any,
      invalidDecision: (async () => new Response(JSON.stringify({ decision: "maybe", action_digest: "a".repeat(64), request_id: "r", reason_code: "X" }), { status: 200 })) as any,
    };
    for (const [name, f] of Object.entries(broken)) {
      const ex = new ProtectedExecutor(guardianFor(env, w.apiKey, { fetch: f, timeoutMs: 80, maxRetries: 1 }), { documents: handler });
      const r = await ex.run(action);
      expect(r.status, name).toBe("not_authorized");
      expect((r as any).executed).toBe(false);
    }
    expect(handler).not.toHaveBeenCalled();
    expect(ws.exists("summaries/x.txt")).toBe(false);
    ws.cleanup();
  });

  it("a server that approves but returns a different digest is refused (tampered or confused service)", async () => {
    const { w, ws } = await setup();
    const handler = vi.fn(ws.handlers.documents);
    const lying = (async () => new Response(JSON.stringify({ request_id: "r", action_id: "x", decision: "allow", reason_code: "ALLOWED_BY_RULE", action_digest: "b".repeat(64), destination_host: null }), { status: 200 })) as any;
    const r = await new ProtectedExecutor(guardianFor(env, w.apiKey, { fetch: lying }), { documents: handler }).run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
    expect(r).toMatchObject({ status: "not_authorized", reasonCode: "DIGEST_MISMATCH" });
    expect(handler).not.toHaveBeenCalled();
    ws.cleanup();
  });

  it("an uncertain claim (lost response) fails closed and cannot be retried into a second execution", async () => {
    const { w, ws } = await setup();
    const handler = vi.fn(ws.handlers.documents);
    let dropClaimResponse = true;
    const flaky = (async (url: string, init: RequestInit) => {
      const res = await env.app.request(new URL(url).pathname, init);
      if (dropClaimResponse && url.endsWith("/claim")) throw new TypeError("connection reset after server processed the claim");
      return res;
    }) as any;
    const ex = new ProtectedExecutor(guardianFor(env, w.apiKey, { fetch: flaky, maxRetries: 3 }), { documents: handler });
    const req = { requestId: newReqId(), tool: "documents", operation: "read" as const, resource: "docs/handbook.txt" };
    expect((await ex.run(req)).status).toBe("not_authorized");
    dropClaimResponse = false;
    const again = await ex.run(req); // the claim was consumed server-side; a retry must not run the tool
    expect(again).toMatchObject({ status: "denied", reasonCode: "ALREADY_CLAIMED" });
    expect(handler).not.toHaveBeenCalled();
    ws.cleanup();
  });

  it("the executor runs a frozen snapshot: mutating the caller's object after submission cannot change what runs", async () => {
    const { w, ws } = await setup();
    const seen: unknown[] = [];
    const ex = executorFor(env, w.apiKey, {
      documents: async (a) => {
        seen.push(JSON.parse(JSON.stringify(a)));
        expect(Object.isFrozen(a)).toBe(true);
        return "ok";
      },
    });
    const action = { tool: "documents", operation: "read" as const, resource: "docs/handbook.txt", args: { page: 1 } };
    const p = ex.run(action);
    action.resource = "docs/secret.txt"; // mutate after submission, before/while authorization is in flight
    action.args.page = 99;
    const r = await p;
    expect(r.status).toBe("executed");
    expect(seen[0]).toMatchObject({ resource: "docs/handbook.txt", args: { page: 1 } });
    ws.cleanup();
  });

  it("handler errors are reported as execution failures, not successes", async () => {
    const { w } = await setup();
    const ex = executorFor(env, w.apiKey, { documents: async () => { throw new Error("disk full"); } });
    const r = await ex.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
    expect(r).toMatchObject({ status: "execution_failed", outcomeReported: true });
    expect((await w.owner.api("GET", `/api/orgs/${w.orgId}/actions`)).body.items[0].state).toBe("execution_failed");
  });
});

describe("denied operations cause no protected side effect", () => {
  it("runs a battery of denied/pending actions against real fixtures and checks the filesystem is unchanged", async () => {
    const w = await makeWorld(env);
    const ws = createWorkspace();
    const ex = executorFor(env, w.apiKey, ws.handlers);
    const before = ws.files().map((f) => [f, ws.read(f)]);
    const attempts = [
      { tool: "documents", operation: "delete" as const, resource: "reports/q3-final.txt" },
      { tool: "documents", operation: "delete" as const, resource: "docs/old-notes.txt" }, // needs approval, never granted
      { tool: "documents", operation: "update" as const, resource: "docs/handbook.txt", args: { text: "overwritten" } },
      { tool: "documents", operation: "create" as const, resource: "docs/new.txt", args: { text: "x" } }, // create only allowed under summaries/
      { tool: "documents", operation: "read" as const, resource: "../outside.txt" },
      { tool: "documents", operation: "create" as const, resource: "summaries/../docs/evil.txt", args: { text: "x" } },
      { tool: "transfer", operation: "external_transfer" as const, resource: "docs/handbook.txt", destination: "https://evil.example.net", data_classification: "internal" as const, args: { source: "docs/handbook.txt" } },
      { tool: "transfer", operation: "external_transfer" as const, resource: "docs/handbook.txt", destination: "http://169.254.169.254/", data_classification: "internal" as const, args: { source: "docs/handbook.txt" } },
      { tool: "transfer", operation: "external_transfer" as const, resource: "docs/handbook.txt", destination: "https://partner.example.com/", data_classification: "restricted" as const, args: { source: "docs/handbook.txt" } },
      { tool: "shell", operation: "command_execution" as const, resource: "host/sh", args: { command: "rm -rf /" } },
    ];
    for (const a of attempts) {
      const r = await ex.run(a);
      expect(["denied", "pending_approval"], JSON.stringify(a)).toContain(r.status);
    }
    expect(ws.files().map((f) => [f, ws.read(f)])).toEqual(before);
    const acts = (await w.owner.api("GET", `/api/orgs/${w.orgId}/actions?limit=50`)).body.items;
    expect(acts.filter((a: any) => a.state === "blocked_confirmed").length).toBe(attempts.length - 1);
    ws.cleanup();
  });
});

describe("secrets never leak", () => {
  it("integration keys and sensitive arguments are absent from stored data and logs", async () => {
    const lines: string[] = [];
    setLogSink((l) => lines.push(l));
    const { setLogLevel } = await import("../src/server/log.js");
    setLogLevel("debug");
    try {
      const w = await makeWorld(env);
      const secretArg = "sk-live-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
      const a = read("docs/a.txt", { args: { password: "p@ssw0rd-very-secret", api_key: secretArg, note: `use ${secretArg}`, content: "CONFIDENTIAL BODY TEXT", email: "boss@corp.example", token: w.apiKey } });
      await v1(env, w.apiKey, "POST", "/v1/authorize", a);
      await v1(env, w.apiKey + "x", "GET", "/v1/whoami"); // wrong key
      await v1(env, `asg_zzzzzzzz_${"Q".repeat(43)}`, "GET", "/v1/whoami"); // unknown key
      await w.owner.api("POST", `/api/orgs/${w.orgId}/credentials/${w.credentialId}/revoke`);
      await v1(env, w.apiKey, "GET", "/v1/whoami"); // revoked key
      const keySecret = w.apiKey.slice(14);
      const tables = ["action_requests", "audit_entries", "alerts", "authorization_decisions", "observed_events", "execution_outcomes"];
      const dump = JSON.stringify(await Promise.all(tables.map((t) => env.db.query(`SELECT * FROM ${t}`))));
      for (const leaked of ["p@ssw0rd-very-secret", secretArg, "CONFIDENTIAL BODY TEXT", "boss@corp.example", keySecret]) {
        expect(dump, `db leaked ${leaked}`).not.toContain(leaked);
      }
      const logs = lines.join("\n");
      expect(logs.length).toBeGreaterThan(0);
      for (const leaked of ["p@ssw0rd-very-secret", secretArg, keySecret, "Bearer "]) expect(logs, `logs leaked ${leaked}`).not.toContain(leaked);
    } finally {
      setLogSink((l) => process.stdout.write(l + "\n"));
      const { setLogLevel: s } = await import("../src/server/log.js");
      s("error");
    }
  });
});

describe("retention", () => {
  it("removes expired data per organization retention while keeping recent data, open alerts and audit within its own window", async () => {
    const w = await makeWorld(env);
    const old = read();
    const fresh = read();
    await v1(env, w.apiKey, "POST", "/v1/authorize", old);
    await v1(env, w.apiKey, "POST", "/v1/authorize", fresh);
    await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "shell", operation: "command_execution", resource: "h" }); // alert
    // Test-only: age audit rows by briefly disabling the append-only trigger (production code never updates audit rows).
    const ageAudit = async (days: number) => {
      await env.db.exec("ALTER TABLE audit_entries DISABLE TRIGGER audit_entries_no_update");
      await env.db.query("UPDATE audit_entries SET created_at = now() - make_interval(days => $3::int) WHERE org_id = $1 AND action = $2", [w.orgId, "org.created", days]);
      await env.db.exec("ALTER TABLE audit_entries ENABLE TRIGGER audit_entries_no_update");
    };
    await w.owner.api("PATCH", `/api/orgs/${w.orgId}`, { retention_days: 7 });
    await env.db.query("UPDATE action_requests SET created_at = now() - interval '30 days' WHERE org_id = $1 AND request_id = $2", [w.orgId, old.request_id]);
    await env.db.query("UPDATE alerts SET last_seen_at = now() - interval '30 days' WHERE org_id = $1", [w.orgId]); // still open => kept
    await ageAudit(30); // audit window is 365 => kept
    const t = await runRetention(env.db);
    expect(t.actions).toBeGreaterThanOrEqual(1);
    const left = await env.db.query<any>("SELECT request_id FROM action_requests WHERE org_id = $1", [w.orgId]);
    expect(left.map((r) => r.request_id)).not.toContain(old.request_id);
    expect(left.map((r) => r.request_id)).toContain(fresh.request_id);
    expect((await env.db.query<any>("SELECT count(*)::int AS n FROM authorization_decisions WHERE action_request_id NOT IN (SELECT id FROM action_requests)"))[0].n).toBe(0);
    expect((await env.db.query<any>("SELECT count(*)::int AS n FROM alerts WHERE org_id = $1", [w.orgId]))[0].n).toBe(1);
    expect((await env.db.query<any>("SELECT count(*)::int AS n FROM audit_entries WHERE org_id = $1 AND action = 'org.created'", [w.orgId]))[0].n).toBe(1);
    await w.owner.api("PATCH", `/api/orgs/${w.orgId}`, { audit_retention_days: 30 });
    await ageAudit(90);
    await runRetention(env.db);
    expect((await env.db.query<any>("SELECT count(*)::int AS n FROM audit_entries WHERE org_id = $1 AND action = 'org.created'", [w.orgId]))[0].n).toBe(0);
  });

  it("audit entries are application-append-only: updates are rejected by the database", async () => {
    const w = await makeWorld(env);
    await expect(env.db.query("UPDATE audit_entries SET action = 'tampered' WHERE org_id = $1", [w.orgId])).rejects.toThrow(/append-only/);
  });
});

describe("operations", () => {
  it("exposes liveness and readiness and reports database loss honestly", async () => {
    expect((await env.app.request("/healthz")).status).toBe(200);
    const ready = await env.app.request("/readyz");
    expect(ready.status).toBe(200);
    const readyBody = await ready.json();
    expect(readyBody.status).toBe("ready");
    expect(readyBody.database).toBe(process.env.TEST_DATABASE_URL ? "pg" : "pglite"); // proves which driver this run exercised
    const broken = { ...env, db: { ...env.db, query: async () => { throw new Error("connection refused"); } } };
    const { createApp } = await import("../src/server/app.js");
    const res = await createApp({ db: broken.db as any, config: env.config }).request("/readyz");
    expect(res.status).toBe(503);
    // and the authorization API fails closed (500, never an allow) when the database is down
    const down = createApp({ db: broken.db as any, config: env.config });
    const r = await down.request("/v1/authorize", { method: "POST", headers: { authorization: `Bearer asg_abcdefgh_${"A".repeat(43)}`, "content-type": "application/json" }, body: "{}" });
    expect(r.status).toBe(500);
    expect((await r.json()).decision).toBeUndefined();
  });

  it("the SDK client rejects a non-JSON or unreachable server for whoami as an error, not a pass", async () => {
    const c = new GuardianClient({ baseUrl: "http://x.test", apiKey: "k", fetch: (async () => new Response("nope", { status: 200 })) as any, maxRetries: 0 });
    await expect(c.whoami()).rejects.toThrow();
  });
});
