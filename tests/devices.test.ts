import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { canonicalJson } from "../src/shared/action.js";
import { sweepDevices } from "../src/server/services/devices.js";
import { verifySignature } from "../src/server/signing.js";
import { Session, makeEnv, makeWorld, newReqId, newUser, v1, type Env, type World } from "./helpers.js";

let env: Env;
beforeAll(async () => {
  env = await makeEnv();
});
afterAll(async () => env.close());

const hb = (over: Record<string, unknown> = {}) => ({
  companion_version: "0.1.0",
  uptime_s: 100,
  executor: { state: "running" },
  notifications: { state: "enabled" },
  consent: { os_security: false, process_inventory: false },
  ...over,
});

async function enrolled(w: World, name = `laptop-${Math.random().toString(36).slice(2, 7)}`) {
  const created = await w.owner.api("POST", `/api/orgs/${w.orgId}/devices`, { name });
  expect(created.status).toBe(201);
  const enr = await v1(env, created.body.enrollment_token, "POST", "/v1/device/enroll", { companion_version: "0.1.0", platform: "windows" });
  expect(enr.status).toBe(201);
  return { id: created.body.id as string, key: enr.body.device_key as string, token: created.body.enrollment_token as string, pub: enr.body.policy_signing_key };
}
const denyOne = (w: World, tag = "x") => v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "shell", operation: "command_execution", resource: `host/${tag}` });
const layer = async (w: World, key: string) => (await w.owner.api("GET", `/api/orgs/${w.orgId}/protection`)).body.layers.find((l: any) => l.key === key);
const setHeartbeatAge = (deviceId: string, minutes: number) => env.db.query("UPDATE devices SET last_heartbeat_at = now() - make_interval(mins => $2::int), notification_checked_at = now() - make_interval(mins => $2::int) WHERE id = $1", [deviceId, minutes]);

describe("device enrollment and credentials", () => {
  it("enrolls with a single-use token, then uses a separate device key; tokens and keys are scoped", async () => {
    const w = await makeWorld(env);
    const d = await enrolled(w);
    expect(d.key).toMatch(/^hdv_[A-Za-z0-9]{8}_/);
    expect(d.pub.key_id).toBeTruthy();
    // token is single-use and cannot heartbeat; the device key cannot enroll again
    expect((await v1(env, d.token, "POST", "/v1/device/enroll", { companion_version: "0.1.0" })).status).toBe(401);
    expect((await v1(env, d.token, "POST", "/v1/device/heartbeat", hb())).status).toBe(401);
    expect((await v1(env, d.key, "POST", "/v1/device/enroll", { companion_version: "0.1.0" })).status).toBe(403);
    // an agent key is not a device key and vice versa
    expect((await v1(env, w.apiKey, "POST", "/v1/device/heartbeat", hb())).status).toBe(401);
    expect((await v1(env, d.key, "POST", "/v1/authorize", { request_id: newReqId(), tool: "d", operation: "read", resource: "docs/a" })).status).toBe(401);
    expect((await v1(env, d.key, "POST", "/v1/device/heartbeat", hb())).status).toBe(200);
    // only a hash is stored
    const rows = await env.db.query<any>("SELECT secret_hash FROM device_credentials WHERE device_id = $1", [d.id]);
    expect(JSON.stringify(rows)).not.toContain(d.key.slice(13));
    expect(JSON.stringify(rows)).not.toContain(d.token.slice(13));
  });

  it("expired enrollment tokens are refused; viewers cannot add devices", async () => {
    const w = await makeWorld(env);
    const viewer = await newUser(env, "viewer");
    await w.owner.api("POST", `/api/orgs/${w.orgId}/members`, { email: viewer.email, role: "viewer" });
    expect((await viewer.api("POST", `/api/orgs/${w.orgId}/devices`, { name: "nope" })).status).toBe(403);
    const created = await w.owner.api("POST", `/api/orgs/${w.orgId}/devices`, { name: "late" });
    await env.db.query("UPDATE device_credentials SET expires_at = now() - interval '1 minute' WHERE device_id = $1", [created.body.id]);
    const r = await v1(env, created.body.enrollment_token, "POST", "/v1/device/enroll", { companion_version: "0.1.0" });
    expect(r.status).toBe(401);
    expect(r.body.error.code).toBe("ENROLLMENT_EXPIRED");
    expect((await viewer.api("GET", `/api/orgs/${w.orgId}/devices`)).status).toBe(200); // viewers may inspect
  });

  it("revocation and uninstall both kill the device key; uninstall touches nothing else", async () => {
    const w = await makeWorld(env);
    const a = await enrolled(w, "revoked-one");
    const b = await enrolled(w, "removed-one");
    const c = await enrolled(w, "bystander");
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/devices/${a.id}/revoke`)).status).toBe(200);
    const denied = await v1(env, a.key, "POST", "/v1/device/heartbeat", hb());
    expect(denied.status).toBe(401);
    expect(denied.body.error.code).toBe("DEVICE_REVOKED");
    expect((await v1(env, b.key, "POST", "/v1/device/unenroll")).status).toBe(200);
    expect((await v1(env, b.key, "POST", "/v1/device/heartbeat", hb())).status).toBe(401);
    const list = (await w.owner.api("GET", `/api/orgs/${w.orgId}/devices`)).body.items;
    expect(list.find((x: any) => x.id === a.id).status).toBe("revoked");
    expect(list.find((x: any) => x.id === b.id).status).toBe("removed");
    expect(list.find((x: any) => x.id === c.id).status).toBe("active");
    expect((await v1(env, c.key, "POST", "/v1/device/heartbeat", hb())).status).toBe(200); // other devices and the agent keep working
    expect((await v1(env, w.apiKey, "GET", "/v1/whoami")).status).toBe(200);
    const audit = (await w.owner.api("GET", `/api/orgs/${w.orgId}/audit?q=device`)).body.items.map((e: any) => e.action);
    expect(audit).toEqual(expect.arrayContaining(["device.revoked", "device.unenrolled", "device.enrolled"]));
  });
});

describe("notifications: scoped, de-duplicated, no storm after reconnect", () => {
  it("delivers each incident once per device, summarizes backlogs, and ignores alerts that predate enrollment", async () => {
    const w = await makeWorld(env);
    await denyOne(w, "before-enrollment");
    const d = await enrolled(w);
    expect((await v1(env, d.key, "GET", "/v1/device/notifications")).body.total).toBe(0); // older than enrollment
    await denyOne(w, "first");
    const p1 = (await v1(env, d.key, "GET", "/v1/device/notifications")).body;
    expect(p1.total).toBe(1);
    expect(p1.show[0]).toMatchObject({ kind: "high_risk_action_denied", severity: "high" });
    // repeated polls without ack return the same item (at-least-once)...
    expect((await v1(env, d.key, "GET", "/v1/device/notifications")).body.total).toBe(1);
    // ...and acking it makes it permanent: the same alert is never shown twice
    const ack = await v1(env, d.key, "POST", "/v1/device/notifications/ack", { items: [{ alert_id: p1.show[0].alert_id, state: "shown" }] });
    expect(ack.body.accepted).toBe(1);
    expect((await v1(env, d.key, "POST", "/v1/device/notifications/ack", { items: [{ alert_id: p1.show[0].alert_id, state: "shown" }] })).body.accepted).toBe(0);
    expect((await v1(env, d.key, "GET", "/v1/device/notifications")).body.total).toBe(0);
    await denyOne(w, "first"); // same condition again: de-duplicated into the same (already delivered) alert
    expect((await v1(env, d.key, "GET", "/v1/device/notifications")).body.total).toBe(0);

    // laptop was off while 8 distinct incidents happened: on reconnect show a few, coalesce the rest
    for (let i = 0; i < 8; i++) {
      await env.db.query("INSERT INTO alerts (org_id, kind, severity, title, dedupe_key) VALUES ($1,'high_risk_action_denied','high',$2,$3)", [w.orgId, `Incident ${i}`, `burst-${i}`]);
    }
    const burst = (await v1(env, d.key, "GET", "/v1/device/notifications")).body;
    expect(burst.total).toBe(8);
    expect(burst.show).toHaveLength(3);
    expect(burst.coalesce_ids).toHaveLength(5);
    const items = [...burst.show.map((s: any) => ({ alert_id: s.alert_id, state: "shown" })), ...burst.coalesce_ids.map((id: string) => ({ alert_id: id, state: "coalesced" }))];
    expect((await v1(env, d.key, "POST", "/v1/device/notifications/ack", { items })).body.accepted).toBe(8);
    expect((await v1(env, d.key, "GET", "/v1/device/notifications")).body.total).toBe(0);
    const rows = await env.db.query<any>("SELECT state, count(*)::int AS n FROM notification_deliveries WHERE device_id = $1 GROUP BY state", [d.id]);
    expect(Object.fromEntries(rows.map((r) => [r.state, r.n]))).toEqual({ shown: 4, coalesced: 5 });
  });

  it("another organization can never receive my alerts, acknowledge them, or see my devices", async () => {
    const a = await makeWorld(env);
    const b = await makeWorld(env);
    const dev = await enrolled(a, "mine");
    const other = await enrolled(b, "theirs");
    await denyOne(a, "secret-resource-name");
    const mine = (await v1(env, dev.key, "GET", "/v1/device/notifications")).body;
    expect(mine.total).toBe(1);
    const theirs = (await v1(env, other.key, "GET", "/v1/device/notifications")).body;
    expect(theirs.total).toBe(0);
    expect(JSON.stringify(theirs)).not.toContain("secret-resource-name");
    // B's device cannot acknowledge A's alert, and B's admin cannot see or control A's devices
    expect((await v1(env, other.key, "POST", "/v1/device/notifications/ack", { items: [{ alert_id: mine.show[0].alert_id, state: "shown" }] })).body.accepted).toBe(0);
    expect((await b.owner.api("GET", `/api/orgs/${a.orgId}/devices`)).status).toBe(404);
    expect((await b.owner.api("GET", `/api/orgs/${a.orgId}/devices/${dev.id}`)).status).toBe(404);
    expect((await b.owner.api("GET", `/api/orgs/${b.orgId}/devices/${dev.id}`)).status).toBe(404);
    expect((await b.owner.api("POST", `/api/orgs/${b.orgId}/devices/${dev.id}/revoke`)).status).toBe(404);
    expect((await b.owner.api("POST", `/api/orgs/${b.orgId}/devices/${dev.id}/commands`, { kind: "selftest" })).status).toBe(404);
    expect((await b.owner.api("GET", `/api/orgs/${a.orgId}/protection`)).status).toBe(404);
    expect((await b.owner.api("GET", `/api/orgs/${a.orgId}/incidents`)).status).toBe(404);
    const incidents = (await a.owner.api("GET", `/api/orgs/${a.orgId}/incidents?since=2000-01-01T00:00:00Z`)).body;
    expect(incidents.items.length).toBeGreaterThan(0);
    expect(JSON.stringify((await b.owner.api("GET", `/api/orgs/${b.orgId}/incidents?since=2000-01-01T00:00:00Z`)).body)).not.toContain("secret-resource-name");
    // a device key only ever acts inside its own org's data
    await v1(env, dev.key, "POST", "/v1/device/heartbeat", hb());
    const hbRes = await v1(env, other.key, "POST", "/v1/device/heartbeat", hb({ notifications: { state: "disabled_for_user" } }));
    expect(hbRes.status).toBe(200);
    expect((await a.owner.api("GET", `/api/orgs/${a.orgId}/devices/${dev.id}`)).body.notification_state).toBe("enabled"); // untouched
  });
});

describe("Protection Center: accurate, separate layers (no global badge)", () => {
  it("starts as Setup required everywhere and never offers an overall 'protected' status", async () => {
    const w = await makeWorld(env);
    const p = (await w.owner.api("GET", `/api/orgs/${w.orgId}/protection`)).body;
    expect(p.layers.map((l: any) => l.key)).toEqual(["ai_tool_enforcement", "protected_resources", "outbound_destinations", "device_health", "notification_delivery", "os_security"]);
    expect(Object.keys(p)).not.toContain("overall");
    expect(JSON.stringify(p).toLowerCase()).not.toMatch(/"everything protected"|"fully protected"|"overall_status"/);
    for (const k of ["protected_resources", "outbound_destinations", "device_health", "notification_delivery", "os_security"]) expect((p.layers.find((l: any) => l.key === k)).status, k).toBe("setup_required");
    expect(p.layers.find((l: any) => l.key === "ai_tool_enforcement").status).toBe("setup_required"); // registered but never connected
    for (const l of p.layers) {
      expect(l.scope.length).toBeGreaterThan(10);
      expect(l.limits.length).toBeGreaterThan(0);
      expect(l.summary.length).toBeGreaterThan(5);
    }
    expect(p.onboarding.map((s: any) => s.done)).toEqual([false, false, false, false, false, false]);
  });

  it("connected-but-not-enforcing is Observing only; a confirmed claim is Enforcing; a stale agent is Degraded", async () => {
    const w = await makeWorld(env, { policy: { schema_version: 1, rules: [{ id: "r", effect: "allow", match: { tools: ["documents"], operations: ["read"] } }] } });
    await v1(env, w.apiKey, "GET", "/v1/whoami");
    expect((await layer(w, "ai_tool_enforcement")).status).toBe("observing_only");
    const a = { request_id: newReqId(), tool: "documents", operation: "read", resource: "docs/a" };
    const { actionDigest } = await import("../src/shared/action.js");
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    await v1(env, w.apiKey, "POST", `/v1/actions/${a.request_id}/claim`, { action_digest: actionDigest(a as any) });
    expect((await layer(w, "ai_tool_enforcement")).status).toBe("enforcing");
    await env.db.query("UPDATE agents SET last_seen_at = now() - interval '2 hours' WHERE id = $1", [w.agentId]);
    const l = await layer(w, "ai_tool_enforcement");
    expect(l.status).toBe("degraded");
    expect(l.evidence.join(" ")).toMatch(/last seen/);
  });

  it("executor attestations drive the folder and destination layers, and go Degraded when they stop", async () => {
    const w = await makeWorld(env, {
      policy: { schema_version: 1, rules: [{ id: "send", effect: "allow", match: { tools: ["transfer"], operations: ["external_transfer"], destination_domains: ["partner.example.com"] } }] },
    });
    const a = { request_id: newReqId(), tool: "transfer", operation: "external_transfer", resource: "docs/a", destination: "https://partner.example.com/" };
    const { actionDigest } = await import("../src/shared/action.js");
    await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    await v1(env, w.apiKey, "POST", `/v1/actions/${a.request_id}/claim`, { action_digest: actionDigest(a as any) });
    expect((await v1(env, w.apiKey, "POST", "/v1/executor/report", { roots: [{ label: "Documents sandbox", prefix: "docs/" }], egress_enabled: true, mode: "online" })).status).toBe(200);
    const roots = await layer(w, "protected_resources");
    expect(roots.status).toBe("enforcing");
    expect(roots.scope).toContain("Documents sandbox");
    const out = await layer(w, "outbound_destinations");
    expect(out.status).toBe("enforcing");
    expect(out.scope).toContain("partner.example.com");
    expect(out.limits.join(" ")).toMatch(/Other programs' network traffic is not controlled/);
    await env.db.query("UPDATE executor_status SET reported_at = now() - interval '1 hour' WHERE agent_id = $1", [w.agentId]);
    expect((await layer(w, "protected_resources")).status).toBe("degraded");
    expect((await layer(w, "outbound_destinations")).status).toBe("setup_required"); // no running executor is reporting any more
  });

  it("device health: online+executor running = Enforcing; executor missing, stale and silent heartbeats are Degraded / Not protected", async () => {
    const w = await makeWorld(env);
    const d = await enrolled(w);
    await v1(env, d.key, "POST", "/v1/device/heartbeat", hb());
    let l = await layer(w, "device_health");
    expect(l.status).toBe("enforcing");
    expect(l.evidence.join(" ")).toMatch(/heartbeat/);
    await v1(env, d.key, "POST", "/v1/device/heartbeat", hb({ executor: { state: "missing", detail: "executor process not running" } }));
    expect((await layer(w, "device_health")).status).toBe("degraded");
    await v1(env, d.key, "POST", "/v1/device/heartbeat", hb());
    await setHeartbeatAge(d.id, 6);
    l = await layer(w, "device_health");
    expect(l.status).toBe("degraded");
    expect(l.summary).toMatch(/stale/);
    await setHeartbeatAge(d.id, 40);
    l = await layer(w, "device_health");
    expect(l.status).toBe("not_protected");
    expect(l.summary).toMatch(/No endpoint enforcement is claimed/); // laptop off / companion stopped
    const dev = (await w.owner.api("GET", `/api/orgs/${w.orgId}/devices/${d.id}`)).body;
    expect(dev.connection.state).toBe("offline");
    // the independently hosted agent path is unaffected by the laptop being off
    expect((await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "documents", operation: "read", resource: "docs/a" })).status).toBe(200);
  });

  it("notification layer explains suppression (denied / Do Not Disturb) and says protection stays active", async () => {
    const w = await makeWorld(env);
    const d = await enrolled(w);
    await v1(env, d.key, "POST", "/v1/device/heartbeat", hb({ notifications: { state: "disabled_for_user" } }));
    let l = await layer(w, "notification_delivery");
    expect(l.status).toBe("degraded");
    expect(l.evidence.join(" ")).toMatch(/disabled for user/);
    expect(l.summary).toMatch(/Protection is unaffected/);
    await v1(env, d.key, "POST", "/v1/device/heartbeat", hb({ notifications: { state: "dnd_suspected" } }));
    expect((await layer(w, "notification_delivery")).status).toBe("degraded");
    await v1(env, d.key, "POST", "/v1/device/heartbeat", hb());
    expect((await layer(w, "notification_delivery")).status).toBe("enforcing");
    // an alert whose toast was suppressed is recorded as suppressed, not as shown
    await denyOne(w, "dnd");
    const n = (await v1(env, d.key, "GET", "/v1/device/notifications")).body;
    await v1(env, d.key, "POST", "/v1/device/notifications/ack", { items: [{ alert_id: n.show[0].alert_id, state: "suppressed_disabled", detail: "Windows reports notifications disabled" }] });
    const dev = (await w.owner.api("GET", `/api/orgs/${w.orgId}/devices/${d.id}`)).body;
    expect(dev.notifications_shown).toBe(0);
  });

  it("OS security status is consent-based, observation-only, and never inflated", async () => {
    const w = await makeWorld(env);
    const d = await enrolled(w);
    const os = { provider: "windows-security", realtime_protection: true, antivirus_enabled: true, signature_age_days: 0, checked_at: new Date().toISOString() };
    // reported without consent: dropped
    await v1(env, d.key, "POST", "/v1/device/heartbeat", hb({ os_security: os, processes: { candidates: [{ name: "ollama", count: 1, confidence: "weak" }] } }));
    let dev = (await w.owner.api("GET", `/api/orgs/${w.orgId}/devices/${d.id}`)).body;
    expect(dev.health.os_security).toBeNull();
    expect(dev.health.processes).toBeNull();
    expect((await layer(w, "os_security")).status).toBe("setup_required");
    // with consent: accepted, shown as Observing only (we do not control Windows Security)
    await v1(env, d.key, "POST", "/v1/device/heartbeat", hb({ consent: { os_security: true, process_inventory: false }, os_security: os }));
    let l = await layer(w, "os_security");
    expect(l.status).toBe("observing_only");
    expect(l.limits.join(" ")).toMatch(/not an antivirus replacement/);
    await v1(env, d.key, "POST", "/v1/device/heartbeat", hb({ consent: { os_security: true, process_inventory: false }, os_security: { ...os, realtime_protection: false } }));
    l = await layer(w, "os_security");
    expect(l.status).toBe("degraded");
    // process inventory only with its own consent and always flagged weak
    await v1(env, d.key, "POST", "/v1/device/heartbeat", hb({ consent: { os_security: false, process_inventory: true }, processes: { candidates: [{ name: "ollama", count: 1, confidence: "weak" }] } }));
    dev = (await w.owner.api("GET", `/api/orgs/${w.orgId}/devices/${d.id}`)).body;
    expect(dev.health.processes.candidates[0]).toMatchObject({ name: "ollama", confidence: "weak" });
    expect((await v1(env, d.key, "POST", "/v1/device/heartbeat", hb({ consent: { os_security: false, process_inventory: true }, processes: { candidates: [{ name: "ollama", count: 1, confidence: "strong" }] } }))).status).toBe(400);
  });

  it("the safe protection test is a queued device command whose result drives onboarding; duplicates and foreign orgs are refused", async () => {
    const w = await makeWorld(env);
    const d = await enrolled(w);
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/devices/${d.id}/commands`, { kind: "selftest" })).status).toBe(201);
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/devices/${d.id}/commands`, { kind: "selftest" })).status).toBe(409);
    const r = await v1(env, d.key, "POST", "/v1/device/heartbeat", hb());
    expect(r.body.commands).toHaveLength(1);
    expect(r.body.commands[0].kind).toBe("selftest");
    expect((await v1(env, d.key, "POST", "/v1/device/heartbeat", hb())).body.commands).toHaveLength(0); // handed out once
    const result = { passed: true, checks: [{ name: "unauthorized deletion leaves file intact", pass: true }], ran_at: new Date().toISOString() };
    expect((await v1(env, d.key, "POST", `/v1/device/commands/${r.body.commands[0].id}/result`, { status: "done", result })).status).toBe(200);
    const other = await enrolled(await makeWorld(env));
    expect((await v1(env, other.key, "POST", `/v1/device/commands/${r.body.commands[0].id}/result`, { status: "done", result })).status).toBe(404);
    const p = (await w.owner.api("GET", `/api/orgs/${w.orgId}/protection`)).body;
    expect(p.onboarding.find((s: any) => s.id === "test").done).toBe(true);
    expect(p.onboarding.find((s: any) => s.id === "device").done).toBe(true);
    expect(p.last_selftest.result.passed).toBe(true);
  });

  it("a silent device raises one de-duplicated alert", async () => {
    const w = await makeWorld(env);
    const d = await enrolled(w, "will-go-silent");
    await v1(env, d.key, "POST", "/v1/device/heartbeat", hb());
    await setHeartbeatAge(d.id, 30);
    await sweepDevices(env.db);
    await sweepDevices(env.db);
    const alerts = (await w.owner.api("GET", `/api/orgs/${w.orgId}/alerts`)).body.items.filter((a: any) => a.kind === "device_offline");
    expect(alerts).toHaveLength(1);
    expect(alerts[0].title).toContain("will-go-silent");
  });
});

describe("signed policy bundles and offline sync (server side)", () => {
  it("issues an Ed25519-signed, agent-bound, expiring bundle; tampering and substitution fail verification", async () => {
    const w = await makeWorld(env);
    const r = await v1(env, w.apiKey, "GET", "/v1/policy-bundle");
    expect(r.status).toBe(200);
    const { bundle, signature } = r.body;
    expect(bundle).toMatchObject({ agent_id: w.agentId, org_id: w.orgId, policy_id: w.policyId, policy_version: 1, enforcement_mode: "enforce" });
    expect(new Date(bundle.expires_at).getTime()).toBeGreaterThan(Date.now());
    const pub = env.signer!.publicKeyPem;
    expect(verifySignature(pub, canonicalJson(bundle), signature)).toBe(true);
    expect(verifySignature(pub, canonicalJson({ ...bundle, expires_at: "2099-01-01T00:00:00.000Z" }), signature)).toBe(false);
    expect(verifySignature(pub, canonicalJson({ ...bundle, agent_id: "00000000-0000-0000-0000-000000000000" }), signature)).toBe(false);
    expect(verifySignature(pub, canonicalJson({ ...bundle, document: { ...bundle.document, rules: [] } }), signature)).toBe(false);
    const w2 = await makeWorld(env);
    const r2 = (await v1(env, w2.apiKey, "GET", "/v1/policy-bundle")).body; // each key only ever gets ITS agent's bundle
    expect(r2.bundle.agent_id).toBe(w2.agentId);
    expect((await v1(env, null, "GET", "/v1/policy-bundle")).status).toBe(401);
    const key = await (await env.app.request("/v1/signing-key")).json();
    expect(key.key_id).toBe(env.signer!.keyId);
  });

  it("offline-sync is idempotent, marks provenance, and flags decisions the policy version would not have made", async () => {
    const w = await makeWorld(env);
    const base = { action: { tool: "documents", operation: "read", resource: "docs/handbook.txt" }, action_digest: "a".repeat(64), policy_version: 1, decided_at: new Date(Date.now() - 600_000).toISOString() };
    const honest = { ...base, request_id: newReqId(), decision: "allow", reason_code: "ALLOWED_BY_RULE", outcome: { status: "succeeded" } };
    const lying = { ...base, request_id: newReqId(), action: { tool: "documents", operation: "delete", resource: "reports/x.txt" }, action_digest: "b".repeat(64), decision: "allow", reason_code: "ALLOWED_BY_RULE", outcome: { status: "succeeded" } };
    const r = await v1(env, w.apiKey, "POST", "/v1/offline-sync", { records: [honest, lying] });
    expect(r.status).toBe(200);
    expect(r.body.results.map((x: any) => x.status)).toEqual(["recorded", "mismatch"]);
    expect((await v1(env, w.apiKey, "POST", "/v1/offline-sync", { records: [honest, lying] })).body.results.map((x: any) => x.status)).toEqual(["duplicate", "duplicate"]);
    const acts = (await w.owner.api("GET", `/api/orgs/${w.orgId}/actions`)).body.items;
    expect(acts).toHaveLength(2);
    const detail = (await w.owner.api("GET", `/api/orgs/${w.orgId}/actions/${acts[0].id}`)).body;
    expect(detail.explanation).toMatch(/cached signed policy/);
    const alerts = (await w.owner.api("GET", `/api/orgs/${w.orgId}/alerts`)).body.items;
    expect(alerts.some((a: any) => a.kind === "offline_decision_mismatch" && a.severity === "high")).toBe(true);
    const src = await env.db.query<any>("SELECT source FROM action_requests WHERE org_id = $1", [w.orgId]);
    expect(src.every((s) => s.source === "offline_cache")).toBe(true);
    // an agent can only sync into its own organization
    expect((await v1(env, null, "POST", "/v1/offline-sync", { records: [honest] })).status).toBe(401);
  });
});

void Session;
