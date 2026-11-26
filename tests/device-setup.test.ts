/** Automatic device setup: browsers added with one click and reached by Web Push; companion pairing without tokens. */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../src/server/app.js";
import { raiseAlert, type Ctx } from "../src/server/services/core.js";
import { dispatchPushes, resetVapidCache } from "../src/server/services/device-setup.js";
import { sweepDevices } from "../src/server/services/devices.js";
import { installTokenFromPath, pairDevice, PairingError } from "../src/companion/pairing.js";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeEnv, makeWorld, newReqId, newUser, Session, v1, type Env } from "./helpers.js";

let base: Env;
let env: Env;
let ctx: Ctx;
const pushed: Array<{ endpoint: string; payload: any }> = [];
let pushStatus = 201;

beforeAll(async () => {
  base = await makeEnv();
  resetVapidCache();
  const inst = mkdtempSync(join(tmpdir(), "hd-inst-"));
  writeFileSync(join(inst, "HeimdallSetup.exe"), "MZ fake installer");
  writeFileSync(join(inst, "installer.json"), JSON.stringify({ file: "HeimdallSetup.exe", version: "0.1.0", url: "http://heimdall.test", built_at: new Date().toISOString() }));
  ctx = {
    db: base.db, config: base.config, signer: base.signer, installerDir: inst,
    webPush: async (sub, payload) => {
      if (pushStatus === 410) throw Object.assign(new Error("gone"), { statusCode: 410 });
      pushed.push({ endpoint: sub.endpoint, payload: JSON.parse(payload) });
      return { statusCode: pushStatus };
    },
  };
  env = { ...base, app: createApp(ctx, { ipLimitsMultiplier: 1000 }) };
});
afterAll(async () => base.close());
beforeEach(() => {
  pushed.length = 0;
  pushStatus = 201;
});

const SUB = (n: string) => ({ endpoint: `https://fcm.googleapis.com/fcm/send/${n}`, keys: { p256dh: "B".repeat(87), auth: "a".repeat(22) } });
const as = (s: Session) => Object.assign(new Session(env, s.email, s.password), { cookie: s.cookie });

async function addBrowser(s: Session, orgId: string, endpoint: string) {
  const r = await s.api("POST", `/api/orgs/${orgId}/browser-devices`, { label: "Chrome on Windows", platform: "windows" });
  expect(r.status).toBe(201);
  const p = await s.api("POST", `/api/orgs/${orgId}/browser-devices/${r.body.device.id}/push`, { subscription: SUB(endpoint), permission: "granted" });
  expect(p.body.notification_state).toBe("enabled");
  return r.body;
}

describe("browser devices", () => {
  it("any member adds their browser with one call; it is active at once and gets the server's push key", async () => {
    const w = await makeWorld(env);
    const owner = as(w.owner);
    const viewer = as(await newUser(env, "viewer"));
    await owner.api("POST", `/api/orgs/${w.orgId}/members`, { email: viewer.email, role: "viewer" });
    const r = await viewer.api("POST", `/api/orgs/${w.orgId}/browser-devices`, { label: "Firefox on Linux", platform: "linux" });
    expect(r.status).toBe(201);
    expect(r.body.device).toMatchObject({ kind: "browser", status: "active", platform: "linux" });
    expect(r.body.device.name).toContain("Firefox on Linux");
    expect(r.body.vapid_public_key).toMatch(/^[A-Za-z0-9_-]{80,}$/);
    // the same browser name twice gets a suffix rather than failing
    const again = await viewer.api("POST", `/api/orgs/${w.orgId}/browser-devices`, { label: "Firefox on Linux", platform: "linux" });
    expect(again.body.device.name).toMatch(/\(2\)$/);
    // VAPID keys are generated once and stored encrypted
    const [row] = await env.db.query<any>("SELECT value_enc FROM server_secrets WHERE name = 'vapid'");
    expect(row.value_enc).not.toContain(r.body.vapid_public_key);
    expect((await viewer.api("GET", `/api/orgs/${w.orgId}/push-key`)).body.vapid_public_key).toBe(r.body.vapid_public_key);
    // listed with the other devices
    const list = await owner.api("GET", `/api/orgs/${w.orgId}/devices`);
    expect(list.body.items.filter((d: any) => d.kind === "browser")).toHaveLength(2);
  });

  it("only the browser's own person can change its subscription; outsiders cannot add devices", async () => {
    const w = await makeWorld(env);
    const owner = as(w.owner);
    const other = as(await newUser(env, "other"));
    const { device } = await addBrowser(owner, w.orgId, "own1");
    expect((await other.api("POST", `/api/orgs/${w.orgId}/browser-devices`, { label: "x", platform: "other" })).status).toBe(404); // not a member: the organization is not even revealed
    await owner.api("POST", `/api/orgs/${w.orgId}/members`, { email: other.email, role: "admin" });
    expect((await other.api("POST", `/api/orgs/${w.orgId}/browser-devices/${device.id}/push`, { subscription: SUB("hijack"), permission: "granted" })).status).toBe(404);
    expect((await other.api("POST", `/api/orgs/${w.orgId}/browser-devices`, { label: "x", platform: "other" }, )).status).toBe(201);
    // non-https push endpoints are refused
    expect((await owner.api("POST", `/api/orgs/${w.orgId}/browser-devices/${device.id}/push`, { subscription: { ...SUB("x"), endpoint: "http://evil.test/x" }, permission: "granted" })).status).toBe(400);
  });

  it("pushes incident alerts to every member's browser once, and approval requests only to people who can approve", async () => {
    const w = await makeWorld(env);
    const owner = as(w.owner);
    const viewer = as(await newUser(env, "viewer"));
    await owner.api("POST", `/api/orgs/${w.orgId}/members`, { email: viewer.email, role: "viewer" });
    await addBrowser(owner, w.orgId, "owner-pc");
    await addBrowser(viewer, w.orgId, "viewer-pc");

    await raiseAlert(env.db, { orgId: w.orgId, kind: "offline_decision_mismatch", severity: "high", title: "Offline decision mismatch", detail: "Re-evaluation disagrees", dedupeKey: "pm1" });
    await raiseAlert(env.db, { orgId: w.orgId, kind: "agent_quiet", severity: "low", title: "Not an incident", dedupeKey: "pm2" });
    const ap = (await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "documents", operation: "delete", resource: "docs/old.txt" })).body;
    expect(ap.decision).toBe("require_approval");

    await dispatchPushes(ctx);
    const to = (e: string) => pushed.filter((p) => p.endpoint.endsWith(e)).map((p) => p.payload.title).sort();
    expect(to("owner-pc")).toEqual(["Approval needed: documents delete", "Offline decision mismatch"]);
    expect(to("viewer-pc")).toEqual(["Offline decision mismatch"]);
    expect(pushed.find((p) => p.payload.title.startsWith("Approval"))!.payload.url).toBe("/approvals");

    pushed.length = 0;
    await dispatchPushes(ctx);
    expect(pushed).toHaveLength(0); // never twice
  });

  it("stops pushing to a browser that unsubscribed (410) and shows notifications as off", async () => {
    const w = await makeWorld(env);
    const owner = as(w.owner);
    const { device } = await addBrowser(owner, w.orgId, "gone");
    pushStatus = 410;
    await raiseAlert(env.db, { orgId: w.orgId, kind: "execution_failed", severity: "high", title: "Tool failed", dedupeKey: "g1" });
    await dispatchPushes(ctx);
    expect(await env.db.query("SELECT 1 FROM push_subscriptions WHERE device_id = $1", [device.id])).toHaveLength(0);
    const hb = await owner.api("POST", `/api/orgs/${w.orgId}/browser-devices/${device.id}/heartbeat`);
    expect(hb.body).toMatchObject({ status: "active", notification_state: "disabled_for_user" });
  });

  it("a person can remove their own browser; removed browsers stop receiving and are never reported offline", async () => {
    const w = await makeWorld(env);
    const owner = as(w.owner);
    const viewer = as(await newUser(env, "viewer"));
    await owner.api("POST", `/api/orgs/${w.orgId}/members`, { email: viewer.email, role: "viewer" });
    const { device } = await addBrowser(viewer, w.orgId, "rm");
    await env.db.query("UPDATE devices SET last_heartbeat_at = now() - interval '2 hours' WHERE id = $1", [device.id]);
    await sweepDevices(env.db);
    expect(await env.db.query("SELECT 1 FROM alerts WHERE org_id = $1 AND kind = 'device_offline'", [w.orgId])).toHaveLength(0);
    expect((await viewer.api("POST", `/api/orgs/${w.orgId}/devices/${device.id}/revoke`)).status).toBeLessThan(300);
    expect((await viewer.api("POST", `/api/orgs/${w.orgId}/browser-devices/${device.id}/heartbeat`)).body.status).not.toBe("active");
    await raiseAlert(env.db, { orgId: w.orgId, kind: "execution_failed", severity: "high", title: "After removal", dedupeKey: "rm1" });
    await dispatchPushes(ctx);
    expect(pushed.filter((p) => p.endpoint.endsWith("rm"))).toHaveLength(0);
  });
});

describe("companion pairing", () => {
  /** The companion's own pairing code, talking to the real app in memory; the "browser" is an admin approving the code. */
  const appFetch = (async (url: string, init: RequestInit) => env.app.request(new URL(url).pathname, init)) as unknown as typeof fetch;

  it("pairs a computer with no token: code shown, admin confirms, the app receives an active device key once", async () => {
    const w = await makeWorld(env);
    const owner = as(w.owner);
    let shown = "";
    let opened = "";
    const result = await pairDevice({
      url: "http://heimdall.test", companionVersion: "0.1.0", platform: "windows", deviceName: "AMA-LAPTOP", fetch: appFetch,
      onCode: (c) => (shown = c),
      openUrl: (u) => (opened = u),
      sleep: async () => {
        if (!shown) return;
        const info = await owner.api("GET", `/api/device-pairings/${shown}`);
        if (info.status !== 200) return;
        expect(info.body).toMatchObject({ device_name: "AMA-LAPTOP", platform: "windows" });
        expect(info.body.orgs.map((o: any) => o.id)).toContain(w.orgId);
        expect((await owner.api("POST", "/api/device-pairings/decide", { code: shown, org_id: w.orgId, approve: true })).status).toBe(200);
      },
    });
    expect(shown).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    expect(opened).toContain(`/pair?code=${shown}`);
    expect(result.device_key).toMatch(/^hdv_/);
    expect(result.policy_signing_key?.public_key_pem).toContain("PUBLIC KEY");
    // the key works for the device API immediately: it is active, no enrollment step
    const hb = await env.app.request("/v1/device/heartbeat", { method: "POST", headers: { authorization: `Bearer ${result.device_key}`, "content-type": "application/json" }, body: JSON.stringify({ companion_version: "0.1.0", executor: { state: "running" }, notifications: { state: "enabled" } }) });
    expect(hb.status).toBe(200);
    const [d] = await env.db.query<any>("SELECT status, kind FROM devices WHERE id = $1", [result.device_id]);
    expect(d).toEqual({ status: "active", kind: "companion" });
    // the key was handed over once and erased from the server
    const [p] = await env.db.query<any>("SELECT status, device_key_enc FROM device_pairings WHERE device_id = $1", [result.device_id]);
    expect(p).toEqual({ status: "claimed", device_key_enc: null });
  });

  it("refuses: viewers cannot approve; a refusal or wrong poll secret gives the app nothing", async () => {
    const w = await makeWorld(env);
    const owner = as(w.owner);
    const viewer = as(await newUser(env, "viewer"));
    await owner.api("POST", `/api/orgs/${w.orgId}/members`, { email: viewer.email, role: "viewer" });
    const start = await env.app.request("/v1/device/pair/start", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ device_name: "PC", platform: "windows", companion_version: "0.1.0" }) });
    const s = (await start.json()) as any;
    expect(start.status).toBe(201);
    expect((await viewer.api("GET", `/api/device-pairings/${s.user_code}`)).body.orgs).toEqual([]);
    expect((await viewer.api("POST", "/api/device-pairings/decide", { code: s.user_code, org_id: w.orgId, approve: true })).status).toBe(403);
    const poll = (secret: string) => env.app.request("/v1/device/pair/poll", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ pairing_id: s.pairing_id, poll_secret: secret }) });
    expect((await poll("x".repeat(43))).status).toBe(404);
    expect((await poll(s.poll_secret)).status).toBe(202);
    expect((await owner.api("POST", "/api/device-pairings/decide", { code: s.user_code.toLowerCase().replace("-", ""), approve: false })).status).toBe(200);
    const denied = await poll(s.poll_secret);
    expect(denied.status).toBe(410);
    expect(((await denied.json()) as any).error.code).toBe("PAIRING_DENIED");
    // and the companion turns that into a clear error
    await expect(pairDevice({ url: "http://heimdall.test", companionVersion: "0.1.0", platform: "windows", fetch: appFetch, openUrl: () => undefined, sleep: async () => {
      const [row] = await env.db.query<any>("SELECT user_code FROM device_pairings ORDER BY created_at DESC LIMIT 1");
      await owner.api("POST", "/api/device-pairings/decide", { code: row.user_code, approve: false });
    } })).rejects.toBeInstanceOf(PairingError);
  });

  it("expired requests cannot be approved", async () => {
    const w = await makeWorld(env);
    const owner = as(w.owner);
    const start = await env.app.request("/v1/device/pair/start", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ device_name: "Old", platform: "linux", companion_version: "0.1.0" }) });
    const s = (await start.json()) as any;
    await env.db.query("UPDATE device_pairings SET expires_at = now() - interval '1 second' WHERE id = $1", [s.pairing_id]);
    expect((await owner.api("POST", "/api/device-pairings/decide", { code: s.user_code, org_id: w.orgId, approve: true })).status).toBe(404);
  });
});

describe("one-click install from the browser", () => {
  const appFetch = (async (url: string, init: RequestInit) => env.app.request(new URL(url).pathname, init)) as unknown as typeof fetch;

  it("reads the code from the downloaded file name, also after the browser renamed a duplicate", () => {
    expect(installTokenFromPath("C:\\Users\\Ama\\Downloads\\Heimdall-Setup-GQQFY9XCAG5Q5WYSNBB1N4P7.exe")).toBe("GQQFY9XCAG5Q5WYSNBB1N4P7");
    expect(installTokenFromPath("/home/a/Downloads/Heimdall-Setup-GQQFY9XCAG5Q5WYSNBB1N4P7 (1).exe")).toBe("GQQFY9XCAG5Q5WYSNBB1N4P7");
    expect(installTokenFromPath("C:\\Users\\Ama\\AppData\\Local\\Kenuxa Heimdall\\HeimdallCompanion.exe")).toBeUndefined();
  });

  it("any member downloads the app with a code; opening it adds the computer at once, active, with no confirmation", async () => {
    const w = await makeWorld(env);
    const owner = as(w.owner);
    const viewer = as(await newUser(env, "viewer"));
    await owner.api("POST", `/api/orgs/${w.orgId}/members`, { email: viewer.email, role: "viewer" });
    expect((await viewer.api("GET", `/api/orgs/${w.orgId}/installer`)).body).toMatchObject({ available: true, version: "0.1.0", approval_required: false });
    const t = await viewer.api("POST", `/api/orgs/${w.orgId}/device-installs`);
    expect(t.status).toBe(201);
    expect(t.body.filename).toMatch(/^Heimdall-Setup-[0-9A-HJKMNP-TV-Z]{24}\.exe$/);
    // only the person who asked can download it
    expect((await owner.api("GET", t.body.download_url)).status).toBe(404);
    const dl = await env.app.request(t.body.download_url, { headers: { cookie: viewer.cookie } });
    expect(dl.status).toBe(200);
    expect(dl.headers.get("content-disposition")).toContain(t.body.filename);
    expect(await dl.text()).toBe("MZ fake installer");

    const token = installTokenFromPath(`C:\\Downloads\\${t.body.filename}`)!;
    let asked = false;
    const r = await pairDevice({ url: "http://heimdall.test", companionVersion: "0.1.0", platform: "windows", deviceName: "KOFI-PC", fetch: appFetch, installToken: token, openUrl: () => (asked = true), sleep: async () => undefined });
    expect(asked).toBe(false); // no browser, no code, no administrator
    const [d] = await env.db.query<any>("SELECT status, kind, name, enrolled_by FROM devices WHERE id = $1", [r.device_id]);
    expect(d).toMatchObject({ status: "active", kind: "companion", name: "KOFI-PC" });
    const [vid] = await env.db.query<any>("SELECT id FROM users WHERE email = $1", [viewer.email]);
    expect(d.enrolled_by).toBe(vid.id);
    // the code works once; the download link is gone too
    const again = await env.app.request("/v1/device/install/claim", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ install_token: token, device_name: "X", platform: "windows", companion_version: "0.1.0" }) });
    expect(again.status).toBe(410);
    expect((await viewer.api("GET", t.body.download_url)).status).toBe(404);
  });

  it("when the organization requires approval, the app waits for an administrator instead", async () => {
    const w = await makeWorld(env);
    const owner = as(w.owner);
    expect((await owner.api("PUT", `/api/orgs/${w.orgId}/device-settings`, { device_approval_required: true })).status).toBe(200);
    const t = await owner.api("POST", `/api/orgs/${w.orgId}/device-installs`);
    const token = installTokenFromPath(t.body.filename)!;
    let code = "";
    const r = await pairDevice({
      url: "http://heimdall.test", companionVersion: "0.1.0", platform: "windows", deviceName: "LOCKED-PC", fetch: appFetch, installToken: token,
      onCode: (c) => (code = c), openUrl: () => undefined,
      sleep: async () => { if (code) await owner.api("POST", "/api/device-pairings/decide", { code, org_id: w.orgId, approve: true }); },
    });
    expect(code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    expect(r.device_key).toMatch(/^hdv_/);
  });

  it("an expired download falls back to asking an administrator, so nobody is stuck", async () => {
    const w = await makeWorld(env);
    const owner = as(w.owner);
    const t = await owner.api("POST", `/api/orgs/${w.orgId}/device-installs`);
    await env.db.query("UPDATE device_install_tokens SET expires_at = now() - interval '1 second' WHERE org_id = $1", [w.orgId]);
    let code = "";
    await pairDevice({ url: "http://heimdall.test", companionVersion: "0.1.0", platform: "windows", fetch: appFetch, installToken: installTokenFromPath(t.body.filename)!, onCode: (c) => (code = c), openUrl: () => undefined, timeoutMs: 1, sleep: async () => undefined }).catch(() => undefined);
    expect(code).toMatch(/-/);
  });

  it("non-admins cannot change the approval rule; outsiders cannot ask for downloads", async () => {
    const w = await makeWorld(env);
    const owner = as(w.owner);
    const viewer = as(await newUser(env, "viewer"));
    expect((await viewer.api("POST", `/api/orgs/${w.orgId}/device-installs`)).status).toBe(404);
    await owner.api("POST", `/api/orgs/${w.orgId}/members`, { email: viewer.email, role: "viewer" });
    expect((await viewer.api("PUT", `/api/orgs/${w.orgId}/device-settings`, { device_approval_required: false })).status).toBe(403);
  });
});
