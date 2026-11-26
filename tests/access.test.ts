import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { actionDigest } from "../src/shared/action.js";
import { Session, makeEnv, makeWorld, newReqId, newUser, uniq, v1, type Env, type World } from "./helpers.js";

let env: Env;
beforeAll(async () => {
  env = await makeEnv();
});
afterAll(async () => env.close());

async function seedActivity(w: World) {
  // one denied action, one approval request, one alert
  await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "shell", operation: "command_execution", resource: "host/sh" });
  const id = newReqId();
  await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: id, tool: "documents", operation: "delete", resource: "docs/x.txt" });
  const approvals = await w.owner.api("GET", `/api/orgs/${w.orgId}/approvals`);
  const alerts = await w.owner.api("GET", `/api/orgs/${w.orgId}/alerts`);
  const actions = await w.owner.api("GET", `/api/orgs/${w.orgId}/actions`);
  return { approvalId: approvals.body.items[0].id as string, alertId: alerts.body.items[0].id as string, actionId: actions.body.items[0].id as string };
}

describe("authentication", () => {
  it("rejects weak passwords, duplicate emails, wrong passwords; sign-out invalidates the session", async () => {
    const email = `${uniq("a")}@example.test`;
    const s = new Session(env, email);
    expect((await s.api("POST", "/api/auth/register", { email, name: "A", password: "short" })).status).toBe(400);
    expect((await s.api("POST", "/api/auth/register", { email, name: "A", password: s.password })).status).toBe(201);
    expect((await s.api("POST", "/api/auth/register", { email: email.toUpperCase(), name: "A", password: s.password })).status).toBe(409);
    expect((await s.api("POST", "/api/auth/login", { email, password: "wrong wrong wrong" })).status).toBe(401);
    await s.signIn();
    expect((await s.api("GET", "/api/auth/me")).status).toBe(200);
    const stale = s.cookie;
    await s.api("POST", "/api/auth/logout");
    s.cookie = stale; // replaying the old cookie must fail after sign-out
    expect((await s.api("GET", "/api/auth/me")).status).toBe(401);
  });

  it("session cookie is HttpOnly + SameSite and the password is never stored in plain text", async () => {
    const email = `${uniq("c")}@example.test`;
    const s = new Session(env, email);
    await s.api("POST", "/api/auth/register", { email, name: "C", password: s.password });
    const r = await s.api("POST", "/api/auth/login", { email, password: s.password });
    const cookie = r.headers.get("set-cookie") ?? "";
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Lax/i);
    const [row] = await env.db.query<any>("SELECT password_hash FROM users WHERE email = $1", [email]);
    expect(row.password_hash.startsWith("scrypt$")).toBe(true);
    expect(row.password_hash).not.toContain(s.password);
    const sessions = await env.db.query<any>("SELECT token_hash FROM sessions");
    expect(sessions.every((x) => !cookie.includes(x.token_hash))).toBe(true); // only a hash of the token is stored
  });

  it("blocks cross-site state changes (missing CSRF header / foreign Origin) and unauthenticated access", async () => {
    const s = await newUser(env);
    const noHeader = await env.app.request("/api/orgs", { method: "POST", headers: { "content-type": "application/json", cookie: s.cookie }, body: JSON.stringify({ name: "Evil Org" }) });
    expect(noHeader.status).toBe(403);
    const foreign = await env.app.request("/api/orgs", { method: "POST", headers: { "content-type": "application/json", "x-asg-csrf": "1", origin: "https://evil.test", cookie: s.cookie }, body: JSON.stringify({ name: "Evil Org" }) });
    expect(foreign.status).toBe(403);
    const anon = new Session(env, "nobody@example.test");
    expect((await anon.api("GET", "/api/orgs/00000000-0000-0000-0000-000000000000/agents")).status).toBe(401);
  });

  it("rate-limits repeated failed sign-ins", async () => {
    const email = `${uniq("rl")}@example.test`;
    const s = new Session(env, email);
    let last = 0;
    for (let i = 0; i < 12; i++) last = (await s.api("POST", "/api/auth/login", { email, password: "wrong wrong wrong" })).status;
    expect(last).toBe(429);
  });

  it("sets security headers and enforces request size limits", async () => {
    const r = await env.app.request("/healthz");
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    expect(r.headers.get("x-frame-options")).toBe("DENY");
    expect(r.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    const w = await makeWorld(env);
    const big = await env.app.request("/v1/authorize", { method: "POST", headers: { authorization: `Bearer ${w.apiKey}`, "content-type": "application/json" }, body: JSON.stringify({ pad: "x".repeat(70_000) }) });
    expect(big.status).toBe(413);
    const huge = await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "d", operation: "read", resource: "docs/a", args: { blob: "x".repeat(20_000) } });
    expect(huge.status).toBe(400);
  });
});

describe("organization isolation", () => {
  it("another organization cannot read or change agents, credentials, policies, actions, approvals, alerts, audit or members", async () => {
    const a = await makeWorld(env);
    const ids = await seedActivity(a);
    const b = await makeWorld(env); // a different, fully separate org with its own owner
    const attackerOrg = b.orgId;

    // Direct access to org A's resources with the attacker's valid session -> not found (existence not revealed)
    const probes: Array<[string, string]> = [
      ["GET", `/api/orgs/${a.orgId}`],
      ["GET", `/api/orgs/${a.orgId}/overview`],
      ["GET", `/api/orgs/${a.orgId}/agents`],
      ["GET", `/api/orgs/${a.orgId}/agents/${a.agentId}`],
      ["GET", `/api/orgs/${a.orgId}/credentials`],
      ["GET", `/api/orgs/${a.orgId}/policies`],
      ["GET", `/api/orgs/${a.orgId}/policies/${a.policyId}`],
      ["GET", `/api/orgs/${a.orgId}/actions`],
      ["GET", `/api/orgs/${a.orgId}/actions/${ids.actionId}`],
      ["GET", `/api/orgs/${a.orgId}/approvals`],
      ["GET", `/api/orgs/${a.orgId}/alerts`],
      ["GET", `/api/orgs/${a.orgId}/audit`],
      ["GET", `/api/orgs/${a.orgId}/members`],
    ];
    for (const [m, p] of probes) expect((await b.owner.api(m, p)).status, `${m} ${p}`).toBe(404);
    const writes: Array<[string, string, unknown]> = [
      ["POST", `/api/orgs/${a.orgId}/agents`, { name: "x", environment: "development", integration_type: "typescript_sdk" }],
      ["POST", `/api/orgs/${a.orgId}/agents/${a.agentId}/revoke`, {}],
      ["PATCH", `/api/orgs/${a.orgId}/agents/${a.agentId}`, { name: "pwned" }],
      ["POST", `/api/orgs/${a.orgId}/credentials`, { agent_id: a.agentId, name: "steal" }],
      ["POST", `/api/orgs/${a.orgId}/credentials/${a.credentialId}/revoke`, {}],
      ["POST", `/api/orgs/${a.orgId}/credentials/${a.credentialId}/replace`, {}],
      ["PUT", `/api/orgs/${a.orgId}/policies/${a.policyId}`, { name: "pwned" }],
      ["POST", `/api/orgs/${a.orgId}/approvals/${ids.approvalId}/approve`, {}],
      ["POST", `/api/orgs/${a.orgId}/alerts/${ids.alertId}/resolve`, {}],
      ["PATCH", `/api/orgs/${a.orgId}`, { name: "pwned" }],
      ["POST", `/api/orgs/${a.orgId}/members`, { email: b.owner.email, role: "owner" }],
    ];
    for (const [m, p, body] of writes) expect((await b.owner.api(m, p, body)).status, `${m} ${p}`).toBe(404);

    // The client-supplied org id is only a selector: using MY org id with THEIR object ids reveals nothing and changes nothing.
    for (const p of [
      `/api/orgs/${attackerOrg}/agents/${a.agentId}`,
      `/api/orgs/${attackerOrg}/policies/${a.policyId}`,
      `/api/orgs/${attackerOrg}/actions/${ids.actionId}`,
    ]) expect((await b.owner.api("GET", p)).status, p).toBe(404);
    expect((await b.owner.api("POST", `/api/orgs/${attackerOrg}/approvals/${ids.approvalId}/approve`, {})).status).toBe(404);
    expect((await b.owner.api("POST", `/api/orgs/${attackerOrg}/agents/${a.agentId}/revoke`, {})).status).toBe(404);
    expect((await b.owner.api("POST", `/api/orgs/${attackerOrg}/credentials/${a.credentialId}/revoke`, {})).status).toBe(404);
    expect((await b.owner.api("POST", `/api/orgs/${attackerOrg}/alerts/${ids.alertId}/resolve`, {})).status).toBe(404);

    // Cross-org references are refused at create/update time
    const mine = await b.owner.api("POST", `/api/orgs/${attackerOrg}/agents`, { name: uniq("x"), environment: "development", integration_type: "typescript_sdk", policy_id: a.policyId });
    expect(mine.status).toBe(400);
    expect((await b.owner.api("PATCH", `/api/orgs/${attackerOrg}/agents/${b.agentId}`, { policy_id: a.policyId })).status).toBe(400);
    expect((await b.owner.api("POST", `/api/orgs/${attackerOrg}/credentials`, { agent_id: a.agentId, name: "steal" })).status).toBe(404);

    // Nothing changed in org A
    const still = await a.owner.api("GET", `/api/orgs/${a.orgId}/agents/${a.agentId}`);
    expect(still.body.status).toBe("active");
    expect(still.body.name).not.toBe("pwned");
    const ap = await a.owner.api("GET", `/api/orgs/${a.orgId}/approvals?status=pending`);
    expect(ap.body.items.length).toBe(1);

    // Lists in org B never contain org A rows
    const bActions = await b.owner.api("GET", `/api/orgs/${b.orgId}/actions`);
    expect(bActions.body.items).toEqual([]);
    expect(JSON.stringify((await b.owner.api("GET", `/api/orgs/${b.orgId}/agents`)).body)).not.toContain(a.agentId);
  });

  it("the database refuses cross-organization references even if the application had a bug", async () => {
    const a = await makeWorld(env);
    const b = await makeWorld(env);
    await expect(env.db.query("UPDATE agents SET policy_id = $1 WHERE id = $2", [a.policyId, b.agentId])).rejects.toThrow();
    await expect(env.db.query("INSERT INTO integration_credentials (org_id, agent_id, name, prefix, secret_hash, scopes) VALUES ($1,$2,'x','zzzzzzzz','h','{actions}')", [b.orgId, a.agentId])).rejects.toThrow();
  });

  it("an integration key only ever acts for its own agent and organization", async () => {
    const a = await makeWorld(env);
    const b = await makeWorld(env);
    const reqId = newReqId();
    const act = { request_id: reqId, tool: "documents", operation: "read", resource: "docs/a.txt" };
    expect((await v1(env, a.apiKey, "POST", "/v1/authorize", act)).status).toBe(200);
    // B's key cannot see, claim or report A's action (same request id string, different agent => not found)
    expect((await v1(env, b.apiKey, "GET", `/v1/actions/${reqId}`)).status).toBe(404);
    expect((await v1(env, b.apiKey, "POST", `/v1/actions/${reqId}/claim`, { action_digest: actionDigest(act as any) })).status).toBe(404);
    expect((await v1(env, b.apiKey, "POST", `/v1/actions/${reqId}/outcome`, { status: "succeeded" })).status).toBe(404);
  });
});

describe("roles", () => {
  async function team() {
    const w = await makeWorld(env);
    const admin = await newUser(env, "admin");
    const viewer = await newUser(env, "viewer");
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/members`, { email: admin.email, role: "admin" })).status).toBe(201);
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/members`, { email: viewer.email, role: "viewer" })).status).toBe(201);
    return { w, admin, viewer };
  }

  it("viewers can inspect but cannot change enforcement settings, credentials, approvals or alerts", async () => {
    const { w, viewer } = await team();
    const ids = await seedActivity(w);
    for (const p of ["agents", "policies", "credentials", "actions", "approvals", "alerts", "overview", "members"]) {
      expect((await viewer.api("GET", `/api/orgs/${w.orgId}/${p}`)).status, `GET ${p}`).toBe(200);
    }
    expect((await viewer.api("GET", `/api/orgs/${w.orgId}/audit`)).status).toBe(403); // audit needs admin
    const forbidden: Array<[string, string, unknown]> = [
      ["POST", `/api/orgs/${w.orgId}/agents`, { name: uniq("v"), environment: "development", integration_type: "typescript_sdk" }],
      ["PATCH", `/api/orgs/${w.orgId}/agents/${w.agentId}`, { enforcement_mode: "monitor" }],
      ["POST", `/api/orgs/${w.orgId}/agents/${w.agentId}/revoke`, {}],
      ["POST", `/api/orgs/${w.orgId}/credentials`, { agent_id: w.agentId, name: "v" }],
      ["POST", `/api/orgs/${w.orgId}/credentials/${w.credentialId}/revoke`, {}],
      ["POST", `/api/orgs/${w.orgId}/policies`, { name: uniq("v"), document: { schema_version: 1, rules: [] } }],
      ["PUT", `/api/orgs/${w.orgId}/policies/${w.policyId}`, { description: "x" }],
      ["POST", `/api/orgs/${w.orgId}/approvals/${ids.approvalId}/approve`, {}],
      ["POST", `/api/orgs/${w.orgId}/approvals/${ids.approvalId}/reject`, {}],
      ["POST", `/api/orgs/${w.orgId}/alerts/${ids.alertId}/resolve`, {}],
      ["PATCH", `/api/orgs/${w.orgId}`, { name: "viewer wins" }],
    ];
    for (const [m, p, body] of forbidden) expect((await viewer.api(m, p, body)).status, `${m} ${p}`).toBe(403);
    expect((await w.owner.api("GET", `/api/orgs/${w.orgId}/agents/${w.agentId}`)).body.enforcement_mode).toBe("enforce");
  });

  it("administrators configure policies, agents and credentials and decide approvals, but cannot manage owners or org settings", async () => {
    const { w, admin } = await team();
    const ids = await seedActivity(w);
    expect((await admin.api("POST", `/api/orgs/${w.orgId}/policies`, { name: uniq("p"), document: { schema_version: 1, rules: [] } })).status).toBe(201);
    expect((await admin.api("POST", `/api/orgs/${w.orgId}/credentials`, { agent_id: w.agentId, name: "second" })).status).toBe(201);
    expect((await admin.api("POST", `/api/orgs/${w.orgId}/approvals/${ids.approvalId}/approve`, {})).status).toBe(200);
    expect((await admin.api("PATCH", `/api/orgs/${w.orgId}`, { name: "Valid Name" })).status).toBe(403);
    expect((await admin.api("POST", `/api/orgs/${w.orgId}/members`, { email: "x@example.test", role: "admin" })).status).toBe(403);
    expect((await admin.api("GET", `/api/orgs/${w.orgId}/audit`)).status).toBe(200);
  });

  it("an owner-level approval rule cannot be satisfied by an administrator", async () => {
    const w = await makeWorld(env, {
      policy: { schema_version: 1, rules: [{ id: "owner-only", effect: "require_approval", match: { tools: ["documents"], operations: ["delete"] }, approval: { required_role: "owner", ttl_seconds: 600 } }] },
    });
    const admin = await newUser(env, "admin");
    await w.owner.api("POST", `/api/orgs/${w.orgId}/members`, { email: admin.email, role: "admin" });
    await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "documents", operation: "delete", resource: "docs/a" });
    const ap = (await w.owner.api("GET", `/api/orgs/${w.orgId}/approvals?status=pending`)).body.items[0];
    expect((await admin.api("POST", `/api/orgs/${w.orgId}/approvals/${ap.id}/approve`, {})).status).toBe(403);
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/approvals/${ap.id}/approve`, {})).status).toBe(200);
  });

  it("protects the last owner and validates membership changes", async () => {
    const { w, admin } = await team();
    const me = (await w.owner.api("GET", "/api/auth/me")).body.user.id as string;
    expect((await w.owner.api("PATCH", `/api/orgs/${w.orgId}/members/${me}`, { role: "admin" })).status).toBe(409);
    expect((await w.owner.api("DELETE", `/api/orgs/${w.orgId}/members/${me}`)).status).toBe(409);
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/members`, { email: "ghost@example.test", role: "viewer" })).status).toBe(400);
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/members`, { email: admin.email, role: "viewer" })).status).toBe(409);
    const adminId = (await admin.api("GET", "/api/auth/me")).body.user.id as string;
    expect((await w.owner.api("DELETE", `/api/orgs/${w.orgId}/members/${adminId}`)).status).toBe(200);
    expect((await admin.api("GET", `/api/orgs/${w.orgId}/agents`)).status).toBe(404);
  });
});

describe("agent inventory and credentials", () => {
  it("a new agent is registered-but-not-connected until it authenticates; states follow real activity", async () => {
    const w = await makeWorld(env);
    const state = async () => (await w.owner.api("GET", `/api/orgs/${w.orgId}/agents/${w.agentId}`)).body;
    let a = await state();
    expect(a.connection.state).toBe("not_connected");
    expect(a.last_seen_at).toBeNull();
    expect((await v1(env, "asg_aaaaaaaa_" + "A".repeat(43), "GET", "/v1/whoami")).status).toBe(401); // failed auth does not mark online
    expect((await state()).connection.state).toBe("not_connected");
    expect((await v1(env, w.apiKey, "GET", "/v1/whoami")).status).toBe(200);
    a = await state();
    expect(a.connection.state).toBe("connected"); // connected, but no enforcement confirmed yet
    const act = { request_id: newReqId(), tool: "documents", operation: "read", resource: "docs/a" };
    await v1(env, w.apiKey, "POST", "/v1/authorize", act);
    expect((await state()).connection.state).toBe("connected"); // authorization alone does not prove enforcement
    await v1(env, w.apiKey, "POST", `/v1/actions/${act.request_id}/claim`, { action_digest: actionDigest(act as any) });
    expect((await state()).connection.state).toBe("enforcing");
    await w.owner.api("POST", `/api/orgs/${w.orgId}/agents/${w.agentId}/revoke`);
    expect((await state()).connection.state).toBe("revoked");
  });

  it("shows the full key exactly once and stores only a hash; keys are scoped and cannot reach admin APIs", async () => {
    const w = await makeWorld(env);
    const created = await w.owner.api("POST", `/api/orgs/${w.orgId}/credentials`, { agent_id: w.agentId, name: "second" });
    const secret = created.body.secret as string;
    expect(secret).toMatch(/^asg_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{43}$/);
    const list = await w.owner.api("GET", `/api/orgs/${w.orgId}/credentials`);
    expect(JSON.stringify(list.body)).not.toContain(secret);
    expect(JSON.stringify(list.body)).not.toContain(secret.slice(14)); // not even the secret part
    const rows = await env.db.query<any>("SELECT * FROM integration_credentials WHERE id = $1", [created.body.id]);
    expect(JSON.stringify(rows)).not.toContain(secret.slice(14));
    expect(rows[0].secret_hash).toMatch(/^[0-9a-f]{64}$/);
    const audit = await env.db.query<any>("SELECT metadata FROM audit_entries WHERE org_id = $1", [w.orgId]);
    expect(JSON.stringify(audit)).not.toContain(secret.slice(14));

    // A credential is not an administrator
    const asAdmin = await env.app.request(`/api/orgs/${w.orgId}/agents`, { headers: { authorization: `Bearer ${secret}` } });
    expect(asAdmin.status).toBe(401);
    const approve = await env.app.request(`/api/orgs/${w.orgId}/approvals/00000000-0000-0000-0000-000000000000/approve`, { method: "POST", headers: { authorization: `Bearer ${secret}`, "x-asg-csrf": "1", "content-type": "application/json" }, body: "{}" });
    expect(approve.status).toBe(401);
  });

  it("event-only agents and keys cannot authorize actions", async () => {
    const w = await makeWorld(env, { integration: "event_reporting" });
    const r = await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "d", operation: "read", resource: "docs/a" });
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe("INSUFFICIENT_SCOPE");
    const noActionsScope = await w.owner.api("POST", `/api/orgs/${w.orgId}/credentials`, { agent_id: w.agentId, name: "x", scopes: ["actions"] });
    expect(noActionsScope.status).toBe(400);
    const ev = await v1(env, w.apiKey, "POST", "/v1/events", { event_id: "evt_000000001", event_type: "tool_call", tool: "documents", operation: "read", resource: "docs/a", demo: true });
    expect(ev.status).toBe(201);
    expect((await v1(env, w.apiKey, "POST", "/v1/events", { event_id: "evt_000000001", event_type: "tool_call" })).body.idempotent_replay).toBe(true);
    const obs = await w.owner.api("GET", `/api/orgs/${w.orgId}/observations`);
    expect(obs.body.total).toBe(1);
    // An observation never shows up as a decision or a "block"
    expect((await w.owner.api("GET", `/api/orgs/${w.orgId}/actions`)).body.total).toBe(0);
    const ag = (await w.owner.api("GET", `/api/orgs/${w.orgId}/agents/${w.agentId}`)).body;
    expect(ag.connection.state).toBe("reporting_only");
  });

  it("revoking a credential immediately stops authorization, claims and outcomes, and raises an alert", async () => {
    const w = await makeWorld(env);
    const pendingAct = { request_id: newReqId(), tool: "documents", operation: "read", resource: "docs/a" };
    expect((await v1(env, w.apiKey, "POST", "/v1/authorize", pendingAct)).status).toBe(200);
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/credentials/${w.credentialId}/revoke`)).status).toBe(200);
    for (const [m, p, b] of [
      ["POST", "/v1/authorize", { request_id: newReqId(), tool: "documents", operation: "read", resource: "docs/a" }],
      ["POST", `/v1/actions/${pendingAct.request_id}/claim`, { action_digest: actionDigest(pendingAct as any) }],
      ["POST", `/v1/actions/${pendingAct.request_id}/outcome`, { status: "succeeded" }],
      ["GET", "/v1/whoami", undefined],
    ] as const) {
      const r = await v1(env, w.apiKey, m, p, b);
      expect(r.status, p).toBe(401);
      expect(r.body.reason_code).toBe("CREDENTIAL_REVOKED");
      expect(r.body.decision).toBe("deny");
    }
    const alerts = await w.owner.api("GET", `/api/orgs/${w.orgId}/alerts`);
    expect(alerts.body.items.some((a: any) => a.kind === "revoked_credential_used")).toBe(true);
  });

  it("replacing a credential revokes the old key and issues a working new one", async () => {
    const w = await makeWorld(env);
    const rep = await w.owner.api("POST", `/api/orgs/${w.orgId}/credentials/${w.credentialId}/replace`);
    expect(rep.status).toBe(201);
    expect((await v1(env, w.apiKey, "GET", "/v1/whoami")).status).toBe(401);
    expect((await v1(env, rep.body.secret, "GET", "/v1/whoami")).status).toBe(200);
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/credentials/${w.credentialId}/replace`)).status).toBe(409);
  });

  it("revoking an agent revokes its keys, expires pending approvals and blocks everything", async () => {
    const w = await makeWorld(env);
    await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "documents", operation: "delete", resource: "docs/a" });
    expect((await w.owner.api("GET", `/api/orgs/${w.orgId}/approvals?status=pending`)).body.total).toBe(1);
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/agents/${w.agentId}/revoke`)).status).toBe(200);
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/agents/${w.agentId}/revoke`)).status).toBe(200); // idempotent
    expect((await v1(env, w.apiKey, "GET", "/v1/whoami")).status).toBe(401);
    expect((await w.owner.api("GET", `/api/orgs/${w.orgId}/approvals?status=pending`)).body.total).toBe(0);
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/credentials`, { agent_id: w.agentId, name: "again" })).status).toBe(409);
    expect((await w.owner.api("PATCH", `/api/orgs/${w.orgId}/agents/${w.agentId}`, { name: "renamed" })).status).toBe(409);
  });
});
