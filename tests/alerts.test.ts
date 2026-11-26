/** Slack and email alert delivery, retries, and signed exports, through the real app with fake Slack and mail. */
import { createHash } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { canonicalJson } from "../src/shared/action.js";
import { createApp } from "../src/server/app.js";
import { loadConfig } from "../src/server/config.js";
import { createDb, type Db } from "../src/server/db.js";
import { setLogLevel } from "../src/server/log.js";
import { runMigrations } from "../src/server/migrate.js";
import { raiseAlert, type Ctx } from "../src/server/services/core.js";
import { dispatchAlerts } from "../src/server/services/notify.js";
import { loadSigner, verifySignature } from "../src/server/signing.js";

const SLACK = "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop";
const slack: Array<{ url: string; body: any }> = [];
let slackStatus = 200;
const mail: Array<{ to: string[]; subject: string; text: string; html: string }> = [];
let db: Db;
let ctx: Ctx;
let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  const config = loadConfig({ NODE_ENV: "test", LOG_LEVEL: "error" } as NodeJS.ProcessEnv);
  setLogLevel("error");
  db = await createDb(config, { memory: true });
  await runMigrations(db);
  ctx = {
    db, config, signer: loadSigner(config, { ephemeral: true }),
    fetch: (async (url: string, init: RequestInit) => {
      slack.push({ url, body: JSON.parse(String(init.body)) });
      return new Response(slackStatus === 200 ? "ok" : "error", { status: slackStatus });
    }) as unknown as typeof fetch,
    sendMail: async (m) => {
      mail.push(m);
    },
  };
  app = createApp(ctx, { ipLimitsMultiplier: 1000 });
});
afterAll(async () => db.close());
beforeEach(() => {
  slack.length = 0;
  mail.length = 0;
  slackStatus = 200;
});

let n = 0;
async function user(role?: { orgId: string; owner: ReturnType<typeof browser>; role: string }) {
  const b = browser();
  const email = `u${Date.now().toString(36)}${n++}@example.test`;
  await b.req("POST", "/api/auth/register", { email, name: "U", password: "correct horse battery staple" });
  await b.req("POST", "/api/auth/login", { email, password: "correct horse battery staple" });
  if (role) await role.owner.req("POST", `/api/orgs/${role.orgId}/members`, { email, role: role.role });
  return b;
}
function browser() {
  let cookie = "";
  return {
    async req(method: string, path: string, body?: unknown) {
      const res = await app.request(path, { method, headers: { "content-type": "application/json", "x-asg-csrf": "1", ...(cookie ? { cookie } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
      const sc = res.headers.get("set-cookie");
      if (sc?.startsWith("asg_session=")) cookie = sc.split(";")[0];
      const text = await res.text();
      let json: any = text;
      try {
        json = JSON.parse(text);
      } catch {
        /* csv */
      }
      return { status: res.status, body: json, headers: res.headers };
    },
  };
}
async function org() {
  const owner = await user();
  const r = await owner.req("POST", "/api/orgs", { name: `Org ${n++}` });
  return { owner, orgId: r.body.id as string };
}

describe("alert channels", () => {
  it("only admins add channels; Slack addresses must be Slack webhooks; the target is stored encrypted", async () => {
    const { owner, orgId } = await org();
    const viewer = await user({ orgId, owner, role: "viewer" });
    expect((await viewer.req("POST", `/api/orgs/${orgId}/channels`, { kind: "slack", name: "Sec", webhook_url: SLACK })).status).toBe(403);
    expect((await owner.req("POST", `/api/orgs/${orgId}/channels`, { kind: "slack", name: "Sec", webhook_url: "https://evil.example.com/hook" })).status).toBe(400);
    const r = await owner.req("POST", `/api/orgs/${orgId}/channels`, { kind: "slack", name: "Sec", webhook_url: SLACK, min_severity: "medium" });
    expect(r.status).toBe(201);
    expect(r.body.target).toBe("hooks.slack.com/…klmnop");
    const [row] = await db.query<any>("SELECT target_enc FROM notification_channels WHERE id = $1", [r.body.id]);
    expect(row.target_enc).not.toContain("hooks.slack.com");
    expect((await viewer.req("GET", `/api/orgs/${orgId}/channels`)).body.items).toHaveLength(1);
  });

  it("delivers a new alert to Slack and email once, filtered by severity, and never re-sends repeats", async () => {
    const { owner, orgId } = await org();
    await owner.req("POST", `/api/orgs/${orgId}/channels`, { kind: "slack", name: "Sec", webhook_url: SLACK, min_severity: "medium" });
    await owner.req("POST", `/api/orgs/${orgId}/channels`, { kind: "email", name: "On-call", recipients: ["Ama@Procus.test", "kofi@procus.test"], min_severity: "high" });
    await raiseAlert(db, { orgId, kind: "offline_decision_mismatch", severity: "high", title: "Decision <script>x</script> mismatch", detail: "Re-evaluation disagrees", dedupeKey: "k1" });
    await raiseAlert(db, { orgId, kind: "agent_noisy", severity: "medium", title: "Agent noisy", dedupeKey: "k2" });
    await raiseAlert(db, { orgId, kind: "agent_quiet", severity: "low", title: "Low alert", dedupeKey: "k3" });
    await dispatchAlerts(ctx);
    expect(slack.map((s) => s.body.text).sort()).toEqual(["HIGH: Decision <script>x</script> mismatch", "MEDIUM: Agent noisy"]);
    expect(slack[0].url).toBe(SLACK);
    expect(JSON.stringify(slack)).toContain("&lt;script&gt;"); // escaped inside Slack mrkdwn
    expect(mail).toHaveLength(1);
    expect(mail[0].to).toEqual(["ama@procus.test", "kofi@procus.test"]);
    expect(mail[0].subject).toBe("[Heimdall HIGH] Decision <script>x</script> mismatch");
    expect(mail[0].html).toContain("Decision &lt;script&gt;x&lt;/script&gt; mismatch");
    expect(mail[0].html).not.toContain("<script>");
    // the same condition again only bumps the counter on the alert: no second message
    await raiseAlert(db, { orgId, kind: "offline_decision_mismatch", severity: "high", title: "Decision <script>x</script> mismatch", dedupeKey: "k1" });
    await dispatchAlerts(ctx);
    expect(slack).toHaveLength(2);
    expect(mail).toHaveLength(1);
  });

  it("retries a failed delivery with backoff and records the error on the channel", async () => {
    const { owner, orgId } = await org();
    const ch = (await owner.req("POST", `/api/orgs/${orgId}/channels`, { kind: "slack", name: "Sec", webhook_url: SLACK, min_severity: "low" })).body;
    await raiseAlert(db, { orgId, kind: "x_alert", severity: "high", title: "Retry me", dedupeKey: "r1" });
    slackStatus = 500;
    expect(await dispatchAlerts(ctx)).toEqual({ sent: 0, failed: 1 });
    const [d] = await db.query<any>("SELECT status, attempts, next_attempt_at > now() AS later FROM channel_deliveries WHERE channel_id = $1", [ch.id]);
    expect(d).toEqual({ status: "failed", attempts: 1, later: true });
    expect((await owner.req("GET", `/api/orgs/${orgId}/channels`)).body.items[0].last_error).toContain("Slack answered 500");
    await dispatchAlerts(ctx); // not due yet
    expect(slack).toHaveLength(1);
    await db.query("UPDATE channel_deliveries SET next_attempt_at = now() WHERE channel_id = $1", [ch.id]);
    slackStatus = 200;
    expect(await dispatchAlerts(ctx)).toEqual({ sent: 1, failed: 0 });
    expect((await owner.req("GET", `/api/orgs/${orgId}/channels`)).body.items[0]).toMatchObject({ sent: 1, last_error: null });
  });

  it("two dispatchers running at once send each alert once", async () => {
    const { owner, orgId } = await org();
    await owner.req("POST", `/api/orgs/${orgId}/channels`, { kind: "slack", name: "Sec", webhook_url: SLACK, min_severity: "low" });
    for (let i = 0; i < 5; i++) await raiseAlert(db, { orgId, kind: "x_alert", severity: "high", title: `A${i}`, dedupeKey: `c${i}` });
    await Promise.all([dispatchAlerts(ctx), dispatchAlerts(ctx), dispatchAlerts(ctx)]);
    expect(slack.filter((s) => s.body.text.startsWith("HIGH: A"))).toHaveLength(5);
  });

  it("the test button sends a sample and reports failures in plain words", async () => {
    const { owner, orgId } = await org();
    const ch = (await owner.req("POST", `/api/orgs/${orgId}/channels`, { kind: "slack", name: "Sec", webhook_url: SLACK })).body;
    expect((await owner.req("POST", `/api/orgs/${orgId}/channels/${ch.id}/test`)).body).toEqual({ ok: true });
    expect(slack[0].body.text).toBe("MEDIUM: Test alert from Kenuxa Heimdall");
    slackStatus = 404;
    const bad = await owner.req("POST", `/api/orgs/${orgId}/channels/${ch.id}/test`);
    expect(bad.status).toBe(502);
    expect(bad.body.error.message).toContain("the webhook may have been removed");
  });
});

describe("exports", () => {
  it("auditors export the audit log as CSV (formula-safe); viewers cannot; the export itself is audited", async () => {
    const { owner, orgId } = await org();
    const auditor = await user({ orgId, owner, role: "auditor" });
    const viewer = await user({ orgId, owner, role: "viewer" });
    await owner.req("POST", `/api/orgs/${orgId}/channels`, { kind: "slack", name: "=HYPERLINK(\"http://x\")", webhook_url: SLACK });
    expect((await viewer.req("GET", `/api/orgs/${orgId}/export?kind=audit&format=csv`)).status).toBe(403);
    const r = await auditor.req("GET", `/api/orgs/${orgId}/export?kind=audit&format=csv`);
    expect(r.status).toBe(200);
    expect(r.headers.get("content-disposition")).toMatch(/attachment; filename="heimdall-audit-.*\.csv"/);
    const csv = String(r.body).replace(/^﻿/, "");
    expect(csv.split("\r\n")[0]).toBe("time,actor_type,actor_id,actor_email,action,target_type,target_id,metadata,id");
    expect(csv).toContain("channel.created");
    expect(csv).not.toMatch(/,=HYPERLINK/); // a cell can never start a formula
    const again = await auditor.req("GET", `/api/orgs/${orgId}/export?kind=audit&format=csv`);
    expect(String(again.body)).toContain("export.downloaded");
  });

  it("JSON Lines exports end with a signed manifest that detects any change", async () => {
    const { owner, orgId } = await org();
    await owner.req("POST", `/api/orgs/${orgId}/channels`, { kind: "slack", name: "Sec", webhook_url: SLACK });
    const r = await owner.req("GET", `/api/orgs/${orgId}/export?kind=audit&format=jsonl`);
    const lines = String(r.body).split("\n").filter(Boolean);
    const manifest = JSON.parse(lines.pop()!);
    expect(manifest).toMatchObject({ _manifest: true, kind: "audit", org_id: orgId, rows: lines.length, key_id: ctx.signer!.keyId });
    const { signature, ...unsigned } = manifest;
    expect(verifySignature(ctx.signer!.publicKeyPem, canonicalJson(unsigned), signature)).toBe(true);
    expect(createHash("sha256").update(lines.map((l) => `${l}\n`).join("")).digest("hex")).toBe(manifest.sha256);
    const tampered = [...lines];
    const i = tampered.findIndex((l) => l.includes("channel.created"));
    expect(i).toBeGreaterThanOrEqual(0);
    tampered[i] = tampered[i].replace("channel.created", "channel.deleted");
    expect(createHash("sha256").update(tampered.map((l) => `${l}\n`).join("")).digest("hex")).not.toBe(manifest.sha256);
    expect(verifySignature(ctx.signer!.publicKeyPem, canonicalJson({ ...unsigned, rows: 0 }), signature)).toBe(false);
  });

  it("exports agent activity with decisions and outcomes, and refuses a bad period", async () => {
    const { owner, orgId } = await org();
    const pol = await owner.req("POST", `/api/orgs/${orgId}/policies`, { name: "p", document: { schema_version: 1, rules: [{ id: "r", effect: "allow", match: { tools: ["documents"], operations: ["read"] } }] } });
    const ag = await owner.req("POST", `/api/orgs/${orgId}/agents`, { name: "a", environment: "development", integration_type: "typescript_sdk", policy_id: pol.body.id, enforcement_mode: "enforce" });
    const key = (await owner.req("POST", `/api/orgs/${orgId}/credentials`, { agent_id: ag.body.id, name: "k" })).body.secret;
    for (const resource of ["docs/a.txt", "docs/b.txt"]) {
      await app.request("/v1/authorize", { method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, body: JSON.stringify({ request_id: `req_${resource.replace(/\W/g, "")}_123456`, tool: "documents", operation: "read", resource }) });
    }
    const r = await owner.req("GET", `/api/orgs/${orgId}/export?kind=activity&format=csv`);
    const rows = String(r.body).replace(/^﻿/, "").trim().split("\r\n");
    expect(rows).toHaveLength(3);
    expect(rows[0]).toContain("decision,policy_decision,reason_code");
    expect(rows[1]).toContain("allow");
    expect((await owner.req("GET", `/api/orgs/${orgId}/export?kind=activity&from=2026-11-25T00:00:00Z&to=2026-01-01T00:00:00Z`)).status).toBe(400);
    expect((await owner.req("GET", `/api/orgs/${orgId}/export?kind=secrets`)).status).toBe(400);
  });
});
