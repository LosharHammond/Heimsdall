import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OfflineAuthority } from "../src/executor/offline.js";
import { createTrustedTools } from "../src/executor/trusted.js";
import { GuardianClient, ProtectedExecutor } from "../src/sdk/index.js";
import type { PolicyDocument } from "../src/shared/policy.js";
import { verifySignature } from "../src/server/signing.js";
import { makeEnv, makeWorld, type Env, type World } from "./helpers.js";

const POLICY: PolicyDocument = {
  schema_version: 1,
  budget: { max_allowed_actions: 50, window_seconds: 3600 },
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

async function setup(opts: { maxOutbox?: number; world?: World } = {}) {
  const base = mkdtempSync(join(tmpdir(), "heimdall-off-"));
  dirs.push(base);
  const root = join(base, "protected");
  mkdirSync(join(root, "docs", "secret"), { recursive: true });
  mkdirSync(join(root, "summaries"), { recursive: true });
  writeFileSync(join(root, "docs", "handbook.txt"), "HANDBOOK");
  writeFileSync(join(root, "docs", "old-notes.txt"), "OLD");
  writeFileSync(join(root, "docs", "secret", "k.txt"), "SECRET");
  const w = opts.world ?? (await makeWorld(env, { policy: POLICY }));
  const net = { up: true };
  const client = new GuardianClient({
    baseUrl: "http://heimdall.test",
    apiKey: w.apiKey,
    maxRetries: 0,
    timeoutMs: 2000,
    fetch: (async (url: string, init: RequestInit) => {
      if (!net.up) throw new TypeError("fetch failed (network down)");
      return env.app.request(new URL(url).pathname, init);
    }) as unknown as typeof fetch,
  });
  const clock = { t: Date.now() };
  const authority = new OfflineAuthority({ dir: join(base, "cache"), publicKeyPem: env.signer!.publicKeyPem, verify: verifySignature, now: () => clock.t, maxOutbox: opts.maxOutbox });
  const executor = new ProtectedExecutor(client, createTrustedTools({ root }).tools, { offline: authority });
  return { w, root, net, client, clock, authority, executor, cache: join(base, "cache") };
}
const fileSet = (root: string) => ["docs/handbook.txt", "docs/old-notes.txt", "docs/secret/k.txt", "summaries/s.txt", "summaries/s2.txt"].map((f) => existsSync(join(root, f)));

describe("cloud offline: documented cached-policy strategy", () => {
  it("online refresh caches a verified bundle; offline allowed work continues, everything else is refused, no side effects", async () => {
    const t = await setup();
    expect((await t.authority.refresh(t.client)).ok).toBe(true);
    expect(t.authority.status()).toMatchObject({ cache: "fresh", queued: 0, has_pin: true });
    t.net.up = false;

    const read = await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
    expect(read).toMatchObject({ status: "executed", offline: true, result: { content: "HANDBOOK" } });
    const sum = await t.executor.run({ requestId: "req_offline_summary_0001", tool: "documents", operation: "create", resource: "summaries/s.txt", args: { text: "offline summary" } });
    expect(sum).toMatchObject({ status: "executed", offline: true });
    expect(readFileSync(join(t.root, "summaries", "s.txt"), "utf8")).toBe("offline summary");
    const replay = await t.executor.run({ requestId: "req_offline_summary_0001", tool: "documents", operation: "create", resource: "summaries/s.txt", args: { text: "offline summary" } });
    expect(replay).toMatchObject({ status: "denied", reasonCode: "OFFLINE_ALREADY_USED" }); // duplicate request: no second execution

    const before = fileSet(t.root);
    const secret = await t.executor.run({ tool: "documents", operation: "read", resource: "docs/secret/k.txt" });
    expect(secret).toMatchObject({ status: "denied", reasonCode: "EXPLICIT_DENY", offline: true });
    expect(JSON.stringify(secret)).not.toContain("SECRET");
    const del = await t.executor.run({ tool: "documents", operation: "delete", resource: "docs/old-notes.txt" });
    expect(del).toMatchObject({ status: "denied", reasonCode: "APPROVAL_REQUIRED", offline: true }); // a pending approval never becomes an allow
    expect(existsSync(join(t.root, "docs", "old-notes.txt"))).toBe(true);
    const cmd = await t.executor.run({ tool: "shell", operation: "command_execution", resource: "host/sh" });
    expect(cmd.status).toBe("not_authorized"); // no shell tool at all
    const dflt = await t.executor.run({ tool: "documents", operation: "read", resource: "reports/q3.txt" });
    expect(dflt.status).toBe("denied"); // path does not exist / default deny: nothing executed
    expect(fileSet(t.root)).toEqual(before);
    expect(t.authority.queued()).toBeGreaterThanOrEqual(4);
  });

  it("with no valid cache the executor fails closed instead of guessing", async () => {
    const t = await setup();
    t.net.up = false;
    const r = await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
    expect(r).toMatchObject({ status: "not_authorized", reasonCode: "OFFLINE_NO_CACHE", executed: false });
    expect(JSON.stringify(r)).not.toContain("HANDBOOK");
  });

  it("refuses a tampered cache (bad signature), a bundle for another agent, and an expired bundle", async () => {
    const t = await setup();
    await t.authority.refresh(t.client);
    t.net.up = false;
    // tamper: grant everything
    const file = join(t.cache, "bundle.json");
    const good = readFileSync(file, "utf8");
    const forged = JSON.parse(good);
    forged.bundle.document.rules = [{ id: "all", effect: "allow", match: { tools: ["documents"], operations: ["read", "create", "delete"] } }];
    writeFileSync(file, JSON.stringify(forged));
    let r = await t.executor.run({ tool: "documents", operation: "read", resource: "docs/secret/k.txt" });
    expect(r).toMatchObject({ status: "not_authorized", reasonCode: "OFFLINE_BAD_SIGNATURE" });
    expect(JSON.stringify(r)).not.toContain("SECRET");
    // extending the expiry also breaks the signature
    const extended = JSON.parse(good);
    extended.bundle.expires_at = "2099-01-01T00:00:00.000Z";
    writeFileSync(file, JSON.stringify(extended));
    expect(t.authority.load()).toMatchObject({ ok: false, code: "BAD_SIGNATURE" });
    // someone else's genuine, correctly signed bundle
    const other = await makeWorld(env, { policy: POLICY });
    const otherBundle = (await new GuardianClient({ baseUrl: "http://x.test", apiKey: other.apiKey, fetch: ((u: string, i: RequestInit) => env.app.request(new URL(u).pathname, i)) as any }).getPolicyBundle());
    writeFileSync(file, JSON.stringify(otherBundle));
    expect(t.authority.load()).toMatchObject({ ok: false, code: "WRONG_BINDING" });
    // restore the genuine bundle, then let it expire
    writeFileSync(file, good);
    expect(t.authority.load().ok).toBe(true);
    t.clock.t = new Date(JSON.parse(good).bundle.expires_at).getTime() + 1000;
    r = await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
    expect(r).toMatchObject({ status: "not_authorized", reasonCode: "OFFLINE_EXPIRED" });
    expect(t.authority.status().cache).toBe("expired");
    // coming back online restores protection
    t.net.up = true;
    t.clock.t = Date.now();
    expect((await t.authority.refresh(t.client)).ok).toBe(true);
    expect(t.authority.status().cache).toBe("fresh");
  });

  it("rejects policy rollback: an older signed bundle cannot replace a newer one", async () => {
    const t = await setup();
    await t.authority.refresh(t.client);
    const v1 = readFileSync(join(t.cache, "bundle.json"), "utf8");
    await t.w.owner.api("PUT", `/api/orgs/${t.w.orgId}/policies/${t.w.policyId}`, { document: { ...POLICY, description: "v2" } });
    expect((await t.authority.refresh(t.client)).ok).toBe(true);
    expect(JSON.parse(readFileSync(join(t.cache, "bundle.json"), "utf8")).bundle.policy_version).toBe(2);
    // replaying the older (genuinely signed, still unexpired) bundle from disk
    writeFileSync(join(t.cache, "bundle.json"), v1);
    expect(t.authority.load()).toMatchObject({ ok: false, code: "ROLLBACK" });
    // and a server (or man-in-the-middle) offering the old bundle on refresh
    const stale = JSON.parse(v1);
    const bad = new GuardianClient({ baseUrl: "http://x.test", apiKey: t.w.apiKey, fetch: (async (u: string, i: RequestInit) => (String(u).endsWith("/v1/policy-bundle") ? new Response(JSON.stringify(stale), { status: 200 }) : env.app.request(new URL(u).pathname, i))) as any });
    expect(await t.authority.refresh(bad)).toMatchObject({ ok: false, code: "ROLLBACK" });
    t.net.up = false;
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("not_authorized");
  });

  it("a revoked credential is a decision, not an outage: no offline fallback while the service answers", async () => {
    const t = await setup();
    await t.authority.refresh(t.client);
    await t.w.owner.api("POST", `/api/orgs/${t.w.orgId}/credentials/${t.w.credentialId}/revoke`);
    const r = await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
    expect(r).toMatchObject({ status: "not_authorized", reasonCode: "CREDENTIAL_REVOKED" });
    expect(JSON.stringify(r)).not.toContain("HANDBOOK");
  });

  it("documented limit: revocation cannot reach an executor that is offline; it keeps working only until the bundle expires", async () => {
    const t = await setup();
    await t.authority.refresh(t.client);
    t.net.up = false;
    await t.w.owner.api("POST", `/api/orgs/${t.w.orgId}/agents/${t.w.agentId}/revoke`); // revoked while the laptop is offline
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("executed"); // bounded by TTL
    t.clock.t = Date.now() + env.config.POLICY_BUNDLE_TTL_MINUTES * 60_000 + 5000;
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("not_authorized");
    t.net.up = true; // and once back online the revocation takes effect immediately
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("not_authorized");
  });

  it("the offline queue is bounded and the executor refuses to act when it cannot record", async () => {
    const t = await setup({ maxOutbox: 2 });
    await t.authority.refresh(t.client);
    t.net.up = false;
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("executed");
    expect((await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" })).status).toBe("executed");
    const third = await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
    expect(third).toMatchObject({ status: "not_authorized", reasonCode: "OFFLINE_OUTBOX_FULL" });
  });
});

describe("reconnect: queued records are synchronized once, with provenance, and re-evaluated", () => {
  it("flushes the outbox idempotently; the dashboard shows offline-decided actions as such", async () => {
    const t = await setup();
    await t.authority.refresh(t.client);
    t.net.up = false;
    await t.executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
    await t.executor.run({ tool: "documents", operation: "read", resource: "docs/secret/k.txt" });
    await t.executor.run({ tool: "documents", operation: "delete", resource: "docs/old-notes.txt" });
    const snapshot = readFileSync(join(t.cache, "outbox.jsonl"), "utf8");
    expect(snapshot.split("\n").filter(Boolean)).toHaveLength(3);
    t.net.up = true;
    const first = await t.authority.flush(t.client);
    expect(first).toEqual({ sent: 3, mismatches: 0 });
    expect(t.authority.queued()).toBe(0);
    // a crash between sync and truncate would replay the same records: the server treats them as duplicates
    writeFileSync(join(t.cache, "outbox.jsonl"), snapshot);
    await t.authority.flush(t.client);
    const rows = (await t.w.owner.api("GET", `/api/orgs/${t.w.orgId}/actions?limit=50`)).body.items;
    expect(rows).toHaveLength(3);
    const states = rows.map((r: any) => `${r.operation}:${r.state}`).sort();
    expect(states).toEqual(["delete:blocked_confirmed", "read:blocked_confirmed", "read:executed"]);
    const src = await env.db.query<any>("SELECT DISTINCT source FROM action_requests WHERE org_id = $1", [t.w.orgId]);
    expect(src.map((s) => s.source)).toEqual(["offline_cache"]);
    expect((await t.w.owner.api("GET", `/api/orgs/${t.w.orgId}/alerts`)).body.items.some((a: any) => a.kind === "offline_decision_mismatch")).toBe(false);
  });
});
