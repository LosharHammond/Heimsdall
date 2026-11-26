import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FastPathAuthority } from "../src/executor/fast-path.js";
import { createTrustedTools } from "../src/executor/trusted.js";
import { GuardianClient, ProtectedExecutor } from "../src/sdk/index.js";
import type { PolicyDocument } from "../src/shared/policy.js";
import { verifySignature } from "../src/server/signing.js";
import { makeEnv, makeWorld, type Env, type World } from "./helpers.js";

const POLICY: PolicyDocument = {
  schema_version: 1,
  rules: [
    { id: "no-cmd", effect: "deny", match: { operations: ["command_execution"] } },
    { id: "no-secret", effect: "deny", match: { resources: ["docs/secret/**"] } },
    { id: "del-approval", effect: "require_approval", match: { tools: ["documents"], operations: ["delete"], resources: ["docs/**"] }, approval: { required_role: "admin", ttl_seconds: 900 } },
    { id: "read", effect: "allow", match: { tools: ["documents"], operations: ["read"], resources: ["docs/**"] } },
    { id: "write-summary", effect: "allow", match: { tools: ["documents"], operations: ["create"], resources: ["summaries/**"] } },
  ],
};

let env: Env;
const dirs: string[] = [];
beforeAll(async () => {
  env = await makeEnv();
});
afterAll(async () => {
  await env.close();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function setup(opts: { policy?: PolicyDocument; maxQueue?: number; world?: World; mode?: "monitor" | "enforce" } = {}) {
  const base = mkdtempSync(join(tmpdir(), "heimdall-fast-"));
  dirs.push(base);
  const root = join(base, "protected");
  mkdirSync(join(root, "docs", "secret"), { recursive: true });
  mkdirSync(join(root, "summaries"), { recursive: true });
  writeFileSync(join(root, "docs", "handbook.txt"), "HANDBOOK");
  writeFileSync(join(root, "docs", "old-notes.txt"), "OLD");
  writeFileSync(join(root, "docs", "secret", "k.txt"), "SECRET");
  const w = opts.world ?? (await makeWorld(env, { policy: opts.policy ?? POLICY, mode: opts.mode }));
  const net = { up: true, calls: [] as string[] };
  const client = new GuardianClient({
    baseUrl: "http://heimdall.test",
    apiKey: w.apiKey,
    maxRetries: 0,
    timeoutMs: 2000,
    fetch: (async (url: string, init: RequestInit) => {
      net.calls.push(`${init.method ?? "GET"} ${new URL(url).pathname}`);
      if (!net.up) throw new TypeError("fetch failed (network down)");
      return env.app.request(new URL(url).pathname, init);
    }) as unknown as typeof fetch,
  });
  const clock = { t: Date.now() };
  const errors: unknown[] = [];
  const fast = new FastPathAuthority({
    client, verify: verifySignature, publicKeyPem: env.signer!.publicKeyPem, now: () => clock.t, maxQueue: opts.maxQueue,
    refreshMs: 3_600_000, flushMs: 3_600_000, // driven by hand in these tests
    onError: (_w, e) => errors.push(e),
  });
  const executor = new ProtectedExecutor(client, createTrustedTools({ root }).tools, { fastPath: fast });
  return { w, root, net, client, clock, fast, executor, errors };
}
type T = Awaited<ReturnType<typeof setup>>;
const actions = async (t: T) => (await t.w.owner.api("GET", `/api/orgs/${t.w.orgId}/actions?limit=100`)).body.items as any[];
const alerts = async (t: T) => (await t.w.owner.api("GET", `/api/orgs/${t.w.orgId}/alerts`)).body.items as any[];

describe("fast path: routine actions are decided in-process, with no network on the caller's path", () => {
  it("allow and deny make zero network calls; the decisions reach the dashboard in the background, re-evaluated", async () => {
    const t = await setup();
    expect(await t.fast.start()).toBe("ready");
    t.net.calls.length = 0;

    const read = await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
    expect(read).toMatchObject({ status: "executed", local: true, result: { content: "HANDBOOK" } });
    const secret = await t.executor.run({ tool: "documents", operation: "read", resource: "docs/secret/k.txt" });
    expect(secret).toMatchObject({ status: "denied", reasonCode: "EXPLICIT_DENY", local: true });
    expect(JSON.stringify(secret)).not.toContain("SECRET");
    const cmd = await t.executor.run({ tool: "documents", operation: "command_execution", resource: "docs/x" });
    expect(cmd).toMatchObject({ status: "denied", reasonCode: "EXPLICIT_DENY" });
    const write = await t.executor.run({ tool: "documents", operation: "create", resource: "summaries/s.txt", args: { text: "fast" } });
    expect(write).toMatchObject({ status: "executed", local: true });
    expect(readFileSync(join(t.root, "summaries", "s.txt"), "utf8")).toBe("fast");

    expect(t.net.calls).toEqual([]); // nothing on the hot path touched the network
    expect(t.fast.stats()).toMatchObject({ queued: 4, sent: 0 });

    await t.fast.flush();
    expect(t.fast.stats()).toMatchObject({ queued: 0, sent: 4, mismatches: 0 });
    expect(t.net.calls).toEqual(["POST /v1/offline-sync"]); // one batched request for all four
    const rows = await actions(t);
    expect(rows.map((r) => `${r.operation}:${r.resource}:${r.state}`).sort()).toEqual([
      "command_execution:docs/x:blocked_confirmed",
      "create:summaries/s.txt:executed",
      "read:docs/handbook.txt:executed",
      "read:docs/secret/k.txt:blocked_confirmed",
    ]);
    const src = await env.db.query<any>("SELECT DISTINCT source FROM action_requests WHERE org_id = $1", [t.w.orgId]);
    expect(src.map((s) => s.source)).toEqual(["local_fast"]);
    expect((await alerts(t)).some((a) => a.kind === "offline_decision_mismatch")).toBe(false);
  });

  it("a request id executes at most once", async () => {
    const t = await setup();
    await t.fast.start();
    const a = { requestId: "req_fast_once_000001", tool: "documents", operation: "create" as const, resource: "summaries/once.txt", args: { text: "1" } };
    expect((await t.executor.run(a)).status).toBe("executed");
    expect(await t.executor.run(a)).toMatchObject({ status: "denied", reasonCode: "ALREADY_USED" });
  });

  it("keeps deciding when the service is unreachable, and sends the backlog once it is back", async () => {
    const t = await setup();
    await t.fast.start();
    t.net.up = false;
    for (let i = 0; i < 3; i++) expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("executed");
    await t.fast.flush();
    expect(t.fast.stats()).toMatchObject({ queued: 3, sent: 0 }); // kept, not lost
    t.net.up = true;
    await t.fast.flush();
    expect(t.fast.stats()).toMatchObject({ queued: 0, sent: 3 });
    expect(await actions(t)).toHaveLength(3);
  });

  it("refuses rather than runs unrecorded when the audit queue is full", async () => {
    const t = await setup({ maxQueue: 2 });
    await t.fast.start();
    t.net.up = false;
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("executed");
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("executed");
    expect(await t.executor.run({ tool: "documents", operation: "create", resource: "summaries/no.txt", args: { text: "x" } })).toMatchObject({ status: "not_authorized", reasonCode: "AUDIT_QUEUE_FULL" });
    expect(existsSync(join(t.root, "summaries", "no.txt"))).toBe(false);
  });
});

describe("fast path: only actions that need a person pause", () => {
  it("require_approval goes to the service and waits; after approval the same request runs once", async () => {
    const t = await setup();
    await t.fast.start();
    t.net.calls.length = 0;
    const first = await t.executor.run({ requestId: "req_fast_delete_00001", tool: "documents", operation: "delete", resource: "docs/old-notes.txt" });
    expect(first.status).toBe("pending_approval");
    expect(t.net.calls).toEqual(["POST /v1/authorize"]);
    expect(existsSync(join(t.root, "docs", "old-notes.txt"))).toBe(true);
    const approvalId = (first as any).approvalId;
    expect((await t.w.owner.api("POST", `/api/orgs/${t.w.orgId}/approvals/${approvalId}/approve`, { note: "ok" })).status).toBe(200);
    const resumed = await t.executor.run({ requestId: "req_fast_delete_00001", tool: "documents", operation: "delete", resource: "docs/old-notes.txt" });
    expect(resumed).toMatchObject({ status: "executed" });
    expect((resumed as any).local).toBeUndefined(); // approved actions use the online one-time claim
    expect(existsSync(join(t.root, "docs", "old-notes.txt"))).toBe(false);
  });
});

describe("fast path: policy changes and revocation apply on refresh", () => {
  it("a new policy version takes effect at the next refresh", async () => {
    const t = await setup();
    await t.fast.start();
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("executed");
    const upd = await t.w.owner.api("PUT", `/api/orgs/${t.w.orgId}/policies/${t.w.policyId}`, { document: { schema_version: 1, rules: [{ id: "nothing", effect: "deny", match: { tools: ["*"] } }] } });
    expect(upd.status).toBe(200);
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("executed"); // old bundle until refresh
    await t.fast.refresh();
    expect(await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).toMatchObject({ status: "denied", reasonCode: "EXPLICIT_DENY", local: true });
    await t.fast.flush();
    expect(t.fast.stats().mismatches).toBe(0); // each record is checked against the version it was decided with
  });

  it("the cheap policy-state check notices a new version and a revoked agent without waiting for the full refresh", async () => {
    const t = await setup();
    await t.fast.start();
    const v1 = t.fast.stats().policy_version;
    await t.w.owner.api("PUT", `/api/orgs/${t.w.orgId}/policies/${t.w.policyId}`, { document: { schema_version: 1, rules: [] } });
    expect(await t.fast.checkState()).toBe("ready");
    expect(t.fast.stats().policy_version).toBe((v1 ?? 0) + 1);
    expect(await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).toMatchObject({ status: "denied", reasonCode: "NO_MATCHING_RULE" });
    await t.w.owner.api("POST", `/api/orgs/${t.w.orgId}/agents/${t.w.agentId}/revoke`);
    expect(await t.fast.checkState()).toBe("revoked");
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("not_authorized");
  });

  it("a revoked key stops the fast path at the next refresh and the online path refuses", async () => {
    const t = await setup();
    await t.fast.start();
    await t.w.owner.api("POST", `/api/orgs/${t.w.orgId}/credentials/${t.w.credentialId}/revoke`);
    expect(await t.fast.refresh()).toBe("revoked");
    const r = await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
    expect(r.status).toBe("not_authorized");
  });

  it("an expired bundle is never used: the executor falls back to the online path", async () => {
    const t = await setup();
    await t.fast.start();
    t.clock.t += 365 * 24 * 3600 * 1000;
    expect(t.fast.stats().state).toBe("expired");
    t.net.calls.length = 0;
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("executed");
    expect(t.net.calls).toContain("POST /v1/authorize");
  });
});

describe("fast path: bundle integrity", () => {
  it("refuses a tampered, foreign, or rolled-back bundle", async () => {
    const t = await setup();
    const signed = await t.client.getPolicyBundle();
    expect(t.fast.accept(signed as any).ok).toBe(true);

    const tampered = structuredClone(signed) as any;
    tampered.bundle.document.rules.unshift({ id: "evil", effect: "allow", match: { tools: ["*"], operations: ["command_execution"] } });
    expect(t.fast.accept(tampered)).toMatchObject({ ok: false, code: "BAD_SIGNATURE" });

    const other = await setup();
    const foreign = await other.client.getPolicyBundle();
    expect(t.fast.accept(foreign as any)).toMatchObject({ ok: false, code: "WRONG_BINDING" });

    await t.w.owner.api("PUT", `/api/orgs/${t.w.orgId}/policies/${t.w.policyId}`, { document: POLICY });
    const newer = await t.client.getPolicyBundle();
    expect(t.fast.accept(newer as any).ok).toBe(true);
    expect(t.fast.accept(signed as any)).toMatchObject({ ok: false, code: "ROLLBACK" });
  });

  it("a forged fast-path record that claims an allow the policy does not grant raises an alert", async () => {
    const t = await setup();
    const forged = {
      request_id: "req_forged_fast_00001", action: { tool: "documents", operation: "read", resource: "docs/secret/k.txt" }, action_digest: "0".repeat(64),
      decision: "allow", reason_code: "ALLOWED_BY_RULE", policy_version: 1, decided_at: new Date().toISOString(), outcome: { status: "succeeded" }, source: "local_fast",
    };
    const res = await t.client.syncOffline([forged]);
    expect(res.results[0].status).toBe("mismatch");
    const a = (await alerts(t)).find((x) => x.kind === "offline_decision_mismatch");
    expect(a?.severity).toBe("high");
    expect(a?.title).toMatch(/^Fast-path decision/);
  });
});

describe("fast path: monitor mode and budgets", () => {
  it("monitor mode runs the action but records what the policy decided", async () => {
    const t = await setup({ mode: "monitor" });
    await t.fast.start();
    const r = await t.executor.run({ tool: "documents", operation: "read", resource: "docs/secret/k.txt" });
    expect(r.status).toBe("executed");
    await t.fast.flush();
    expect(t.fast.stats().mismatches).toBe(0);
    const [row] = await env.db.query<any>("SELECT d.decision, d.reason_code FROM authorization_decisions d JOIN action_requests a ON a.id = d.action_request_id WHERE a.org_id = $1", [t.w.orgId]);
    expect(row).toMatchObject({ decision: "deny", reason_code: "MONITOR_ONLY" });
  });

  it("enforces the action budget locally, and the server accepts the stricter local count", async () => {
    const t = await setup({ policy: { ...POLICY, budget: { max_allowed_actions: 2, window_seconds: 60 } } });
    await t.fast.start();
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("executed");
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("executed");
    expect(await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).toMatchObject({ status: "denied", reasonCode: "BUDGET_EXCEEDED" });
    t.clock.t += 61_000;
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("executed");
    await t.fast.flush();
    expect(t.fast.stats().mismatches).toBe(0);
  });
});
