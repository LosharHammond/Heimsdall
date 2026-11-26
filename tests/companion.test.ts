import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Companion, configPath, saveConfig, type CompanionConfig } from "../src/companion/companion.js";
import { Windows } from "../src/companion/windows.js";
import { writeExecutorStatus, executorStatusPath } from "../src/executor/status.js";
import { makeEnv, makeWorld, newReqId, v1, type Env, type World } from "./helpers.js";

let env: Env;
const dirs: string[] = [];
beforeAll(async () => {
  env = await makeEnv();
});
afterAll(async () => {
  await env.close();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

class FakeWindows {
  setting = "enabled";
  toasts: Array<{ title: string; body: string; tag?: string }> = [];
  runKey: string | null = null;
  appId = true;
  historyCleared = 0;
  osSecurityCalls = 0;
  protect = (s: string) => s;
  unprotect = (s: string) => s;
  toastSetting = () => this.setting as any;
  showToast = (t: { title: string; body: string; tag?: string }) => {
    if (this.setting !== "enabled" && this.setting !== "dnd_suspected" && this.setting !== "unknown") return { shown: false, setting: this.setting };
    this.toasts.push(t);
    return { shown: true, setting: this.setting };
  };
  deliveredTags = () => this.toasts.map((t) => t.tag ?? "");
  registerAppId = () => ({ ok: true, out: "", err: "" });
  unregisterAppId = () => {
    this.appId = false;
    return { ok: true, out: "", err: "" };
  };
  hasAppId = () => this.appId;
  setRunKey = (c: string) => {
    this.runKey = c;
    return { ok: true, out: "", err: "" };
  };
  removeRunKey = () => {
    this.runKey = null;
    return { ok: true, out: "", err: "" };
  };
  getRunKey = () => this.runKey;
  clearHistory = () => {
    this.historyCleared++;
    return { ok: true, out: "", err: "" };
  };
  osSecurity = () => {
    this.osSecurityCalls++;
    return { provider: "windows-security", realtime_protection: true, antivirus_enabled: true, signature_age_days: 0, checked_at: new Date().toISOString() };
  };
  processCandidates = () => [{ name: "ollama", count: 1, confidence: "weak" as const }];
}

const inProc = (): typeof fetch => ((url: string, init: RequestInit) => env.app.request(new URL(url).pathname, init)) as unknown as typeof fetch;

async function newDevice(w: World, name = `pc-${Math.random().toString(36).slice(2, 6)}`) {
  const created = await w.owner.api("POST", `/api/orgs/${w.orgId}/devices`, { name });
  const enr = await v1(env, created.body.enrollment_token, "POST", "/v1/device/enroll", { companion_version: "0.1.0", platform: "windows" });
  const stateDir = mkdtempSync(join(tmpdir(), "heimdall-co-"));
  dirs.push(stateDir);
  const cfg: CompanionConfig = { url: "http://heimdall.test", device_id: created.body.id, device_key_protected: enr.body.device_key, consent: { os_security: false, process_inventory: false }, enrolled_at: new Date().toISOString(), version: "0.1.0" };
  saveConfig(stateDir, cfg);
  const win = new FakeWindows();
  win.runKey = "startup-entry";
  // a healthy executor is running by default; tests that need otherwise remove or overwrite this file
  writeExecutorStatus({ updated_at: new Date().toISOString(), pid: process.pid, version: "0.1.0", state: "running", mode: "online", cache: "fresh", cache_expires_at: new Date(Date.now() + 3600_000).toISOString(), queued: 0, roots: [{ label: "Protected folder", prefix: "" }], egress_enabled: false, last_service_contact_at: new Date().toISOString() }, executorStatusPath(stateDir));
  let removed = false;
  const fetchRef = { f: inProc() };
  const companion = new Companion({ stateDir, windows: win as unknown as Windows, fetch: ((u: string, i: RequestInit) => fetchRef.f(u, i)) as typeof fetch, onRemoved: () => (removed = true) }, cfg);
  return { id: created.body.id as string, key: enr.body.device_key as string, stateDir, win, companion, fetchRef, isRemoved: () => removed };
}
const deny = (w: World, op = "command_execution") => v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "shell", operation: op, resource: "host/shell" });
const dev = async (w: World, id: string) => (await w.owner.api("GET", `/api/orgs/${w.orgId}/devices/${id}`)).body;
const layer = async (w: World, key: string) => (await w.owner.api("GET", `/api/orgs/${w.orgId}/protection`)).body.layers.find((l: any) => l.key === key);

describe("companion: notifications reach the desktop without any browser", () => {
  it("a controlled denied action becomes exactly one Windows notification, acknowledged, with no browser involved (dashboard open/minimized/closed/exited are all the same native path)", async () => {
    const w = await makeWorld(env);
    const d = await newDevice(w);
    await deny(w);
    await d.companion.tick();
    expect(d.win.toasts).toHaveLength(1);
    expect(d.win.toasts[0].title).toMatch(/Heimdall/);
    expect(d.win.toasts[0].body).toMatch(/command_execution/);
    expect((await dev(w, d.id)).notifications_shown).toBe(1);
    await d.companion.tick();
    await d.companion.tick();
    expect(d.win.toasts).toHaveLength(1); // not repeated
    await deny(w); // the same condition recurring is the same alert: cooldown, no second toast
    await d.companion.tick();
    expect(d.win.toasts).toHaveLength(1);
  });

  it("after being offline, a backlog becomes at most 3 toasts plus one summary, all acknowledged", async () => {
    const w = await makeWorld(env);
    const d = await newDevice(w);
    for (let i = 0; i < 9; i++) await env.db.query("INSERT INTO alerts (org_id, kind, severity, title, dedupe_key) VALUES ($1,'high_risk_action_denied','high',$2,$3)", [w.orgId, `Incident ${i}`, `bk-${i}`]);
    await d.companion.tick();
    expect(d.win.toasts).toHaveLength(4);
    expect(d.win.toasts[3].title).toMatch(/more incidents/);
    expect(d.win.toasts[3].body).toMatch(/6 more incidents/);
    await d.companion.tick();
    expect(d.win.toasts).toHaveLength(4);
    const rows = await env.db.query<any>("SELECT state, count(*)::int AS n FROM notification_deliveries WHERE device_id = $1 GROUP BY state", [d.id]);
    expect(Object.fromEntries(rows.map((r) => [r.state, r.n]))).toEqual({ shown: 3, coalesced: 6 });
  });

  it("notifications disabled / Do Not Disturb: protection stays active, suppression is recorded and explained, never bypassed", async () => {
    const w = await makeWorld(env, { policy: { schema_version: 1, rules: [] } });
    const d = await newDevice(w);
    d.win.setting = "disabled_for_user";
    await deny(w);
    await d.companion.tick();
    expect(d.win.toasts).toHaveLength(0); // the companion did not try to force a toast
    const dv = await dev(w, d.id);
    expect(dv.notifications_shown).toBe(0);
    expect(dv.notification_state).toBe("disabled_for_user");
    const row = (await env.db.query<any>("SELECT state, detail FROM notification_deliveries WHERE device_id = $1", [d.id]))[0];
    expect(row).toMatchObject({ state: "suppressed_disabled" });
    expect(row.detail).toMatch(/disabled_for_user/);
    const l = await layer(w, "notification_delivery");
    expect(l.status).toBe("degraded");
    expect(l.summary).toMatch(/Protection is unaffected/);
    // enforcement itself is untouched by the notification state
    const r = await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "documents", operation: "read", resource: "docs/a" });
    expect(r.body.decision).toBe("deny");
    // Do Not Disturb heuristics
    d.win.setting = "dnd_suspected";
    await d.companion.tick();
    expect((await dev(w, d.id)).notification_state).toBe("dnd_suspected");
  });

  it("test notification command reports what Windows accepted; the safe protection test runs real executor checks and passes", async () => {
    const w = await makeWorld(env);
    const d = await newDevice(w);
    await w.owner.api("POST", `/api/orgs/${w.orgId}/devices/${d.id}/commands`, { kind: "test_notification" });
    await d.companion.tick(); // heartbeat hands out the command; the same tick executes it
    expect(d.win.toasts.some((t) => t.title.includes("test notification"))).toBe(true);
    await w.owner.api("POST", `/api/orgs/${w.orgId}/devices/${d.id}/commands`, { kind: "selftest" });
    await d.companion.tick();
    const detail = await dev(w, d.id);
    const st = detail.commands.find((c: any) => c.kind === "selftest");
    expect(st.status).toBe("done");
    expect(st.result.passed).toBe(true);
    const names = st.result.checks.map((c: any) => c.name);
    expect(names).toEqual(expect.arrayContaining([
      "Allowed document read succeeds", "Allowed summary is written", "Unauthorized deletion leaves the file intact (observed on disk)", "Path traversal is refused and the outside file is untouched",
      "Upload to an unapproved destination sends no data (local receiver saw nothing)", "Upload to the approved destination does reach the receiver (the test is not vacuous)", "Arbitrary command execution is refused before any handler runs",
    ]));
    expect(st.result.checks.every((c: any) => c.pass)).toBe(true);
    expect(st.result.scope).toMatch(/does not test your organization's policies/);
    const p = (await w.owner.api("GET", `/api/orgs/${w.orgId}/protection`)).body;
    expect(p.onboarding.find((s: any) => s.id === "test").done).toBe(true);
  }, 60_000);
});

describe("companion: degraded states, cloud outage, executor health", () => {
  it("cloud outage: one local degraded notice (not a storm), recovery resets, stale heartbeat shows Degraded then Not protected, hosted agents are unaffected", async () => {
    const w = await makeWorld(env);
    const d = await newDevice(w);
    await d.companion.tick();
    expect((await layer(w, "device_health")).status).not.toBe("setup_required");
    d.fetchRef.f = (async () => { throw new TypeError("network down"); }) as unknown as typeof fetch;
    for (let i = 0; i < 6; i++) await d.companion.tick();
    const degraded = d.win.toasts.filter((t) => t.title.includes("can't reach the cloud"));
    expect(degraded).toHaveLength(1);
    expect(degraded[0].body).toMatch(/approvals can't be granted/);
    // laptop effectively dark from the cloud's point of view
    await env.db.query("UPDATE devices SET last_heartbeat_at = now() - interval '6 minutes' WHERE id = $1", [d.id]);
    expect((await layer(w, "device_health")).status).toBe("degraded");
    await env.db.query("UPDATE devices SET last_heartbeat_at = now() - interval '30 minutes' WHERE id = $1", [d.id]);
    const l = await layer(w, "device_health");
    expect(l.status).toBe("not_protected");
    expect(l.summary).toMatch(/No endpoint enforcement is claimed/);
    // independently hosted agent integrations keep working while the laptop is off
    expect((await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "documents", operation: "read", resource: "docs/a" })).status).toBe(200);
    // recovery
    d.fetchRef.f = inProc();
    await d.companion.tick();
    expect((await layer(w, "device_health")).status).not.toBe("not_protected");
    d.fetchRef.f = (async () => { throw new TypeError("network down"); }) as unknown as typeof fetch;
    for (let i = 0; i < 4; i++) await d.companion.tick();
    expect(d.win.toasts.filter((t) => t.title.includes("can't reach the cloud"))).toHaveLength(2); // a NEW outage notifies again, once
  });

  it("executor health is reported honestly: missing, running, and policy-cache expired (with a local notice)", async () => {
    const w = await makeWorld(env);
    const d = await newDevice(w);
    rmSync(executorStatusPath(d.stateDir), { force: true }); // the executor process is not running
    await d.companion.tick();
    let dv = await dev(w, d.id);
    expect(dv.health.executor.state).toBe("missing");
    expect((await layer(w, "device_health")).status).toBe("degraded");
    expect(d.win.toasts.some((t) => t.title.includes("executor not running"))).toBe(true);
    writeExecutorStatus({ updated_at: new Date().toISOString(), pid: process.pid, version: "0.1.0", state: "running", mode: "online", cache: "fresh", cache_expires_at: new Date(Date.now() + 3600_000).toISOString(), queued: 0, roots: [{ label: "Protected folder", prefix: "" }], egress_enabled: false, last_service_contact_at: new Date().toISOString() }, executorStatusPath(d.stateDir));
    await d.companion.tick();
    dv = await dev(w, d.id);
    expect(dv.health.executor.state).toBe("running");
    expect((await layer(w, "device_health")).status).toBe("enforcing");
    writeExecutorStatus({ updated_at: new Date().toISOString(), pid: process.pid, version: "0.1.0", state: "running", mode: "degraded", cache: "expired", cache_expires_at: new Date(Date.now() - 1000).toISOString(), queued: 3, roots: [], egress_enabled: false, last_service_contact_at: null }, executorStatusPath(d.stateDir));
    await d.companion.tick();
    expect(d.win.toasts.filter((t) => t.title.includes("policy cache expired"))).toHaveLength(1);
    await d.companion.tick();
    expect(d.win.toasts.filter((t) => t.title.includes("policy cache expired"))).toHaveLength(1);
    expect((await dev(w, d.id)).health.cloud).toMatchObject({ mode: "offline_cache", queued_events: 3 });
  });

  it("optional telemetry is consent-gated on the device: nothing is read or sent without consent", async () => {
    const w = await makeWorld(env);
    const d = await newDevice(w);
    await d.companion.tick();
    expect(d.win.osSecurityCalls).toBe(0);
    expect((await dev(w, d.id)).health.os_security).toBeNull();
    const cfg = { ...d.companion.cfg, consent: { os_security: true, process_inventory: true } };
    saveConfig(d.stateDir, cfg);
    const c2 = new Companion({ stateDir: d.stateDir, windows: d.win as unknown as Windows, fetch: inProc() }, cfg);
    await c2.tick();
    const dv = await dev(w, d.id);
    expect(d.win.osSecurityCalls).toBe(1);
    expect(dv.health.os_security.provider).toBe("windows-security");
    expect(dv.health.processes.candidates[0]).toEqual({ name: "ollama", count: 1, confidence: "weak" });
    expect((await layer(w, "os_security")).status).toBe("observing_only");
  });
});

describe("companion: revocation, uninstall, and what is (not) removed", () => {
  it("a revoked device cleans up only its own entries, tells the user, and other devices keep working", async () => {
    const w = await makeWorld(env);
    const gone = await newDevice(w, "to-revoke");
    const stays = await newDevice(w, "bystander");
    writeFileSync(join(gone.stateDir, "someone-elses-file.txt"), "not ours");
    mkdirSync(join(gone.stateDir, "executor-cache"), { recursive: true });
    await gone.companion.tick();
    await w.owner.api("POST", `/api/orgs/${w.orgId}/devices/${gone.id}/revoke`);
    await gone.companion.tick();
    expect(gone.isRemoved()).toBe(true);
    expect(gone.win.toasts.some((t) => t.title.includes("device removed"))).toBe(true);
    expect(gone.win.runKey).toBeNull(); // app-owned startup entry removed
    expect(gone.win.appId).toBe(false);
    expect(existsSync(configPath(gone.stateDir))).toBe(false); // credentials gone
    expect(existsSync(join(gone.stateDir, "executor-cache"))).toBe(false);
    expect(existsSync(join(gone.stateDir, "someone-elses-file.txt"))).toBe(true); // nothing it did not create is touched
    await gone.companion.tick(); // no further network use after removal
    await stays.companion.tick();
    expect((await dev(w, stays.id)).connection.state).toBe("online");
    expect(stays.win.runKey).toBe("startup-entry");
  });

  it("uninstall unenrolls, revokes the key and removes only app-owned configuration", async () => {
    const w = await makeWorld(env);
    const d = await newDevice(w);
    writeFileSync(join(d.stateDir, "unrelated.log"), "keep");
    await d.companion.tick();
    const r = await d.companion.uninstall();
    expect(r.unenrolled).toBe(true);
    expect((await dev(w, d.id)).status).toBe("removed");
    expect((await v1(env, d.key, "POST", "/v1/device/heartbeat", { companion_version: "0.1.0", executor: { state: "running" }, notifications: { state: "enabled" } })).status).toBe(401);
    expect(d.win.runKey).toBeNull();
    expect(existsSync(configPath(d.stateDir))).toBe(false);
    expect(existsSync(join(d.stateDir, "unrelated.log"))).toBe(true);
  });

  it("uninstall while the cloud is unreachable still removes local entries and says an administrator must remove the device", async () => {
    const w = await makeWorld(env);
    const d = await newDevice(w);
    d.fetchRef.f = (async () => { throw new TypeError("offline"); }) as unknown as typeof fetch;
    const r = await d.companion.uninstall();
    expect(r.unenrolled).toBe(false);
    expect(d.win.runKey).toBeNull();
    expect(existsSync(configPath(d.stateDir))).toBe(false);
    expect((await dev(w, d.id)).status).toBe("active"); // still enrolled server-side until an administrator revokes it
  });
});

describe.skipIf(process.platform !== "win32")("REAL Windows APIs (this machine): app-owned identity, toast acceptance, startup entry, DPAPI", () => {
  const AUMID = "Kenuxa.Heimdall.Companion.TestRun";
  const RUN = "KenuxaHeimdallCompanionTestRun";
  const win = new Windows(undefined, AUMID, RUN);
  afterAll(() => {
    win.clearHistory();
    win.unregisterAppId();
    win.removeRunKey();
  });

  it("registers an app identity, Windows accepts the toast into its notification history, and the setting is readable", () => {
    expect(win.registerAppId("Kenuxa Heimdall (test run)").ok).toBe(true);
    expect(win.hasAppId()).toBe(true);
    // Windows only reports a notification setting for an app identity after its first toast; before that the value is empty ("unknown").
    const r = win.showToast({ title: "Heimdall automated test", body: "A real Windows toast from the companion test suite.", tag: "autotest-1" });
    const setting = win.toastSetting();
    expect(["enabled", "dnd_suspected", "disabled_for_user", "disabled_for_application", "disabled_by_group_policy", "disabled_by_manifest"]).toContain(setting);
    if (setting === "enabled" || setting === "dnd_suspected") {
      expect(r.shown).toBe(true);
      // OS-level evidence: Windows itself lists the toast in this app's notification history (Action Center)
      expect(win.deliveredTags()).toContain("autotest-1");
    } else {
      expect(r.shown).toBe(false); // suppression is honoured and reported, never bypassed
    }
  }, 60_000);

  it("start-at-sign-in uses only an app-named HKCU Run value and leaves every other startup entry untouched", () => {
    const names = (): string[] => {
      const r = (win as any).ps(`(Get-Item 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run').Property -join '|'`);
      return String(r.out).split("|").filter(Boolean).sort();
    };
    const before = names();
    expect(win.setRunKey('"C:\\Program Files\\nodejs\\node.exe" "C:\\fake\\companion.js" run').ok).toBe(true);
    expect(win.getRunKey()).toContain("companion.js");
    const during = names();
    expect(during).toEqual([...before, RUN].sort());
    expect(win.removeRunKey().ok).toBe(true);
    expect(win.getRunKey()).toBeNull();
    expect(names()).toEqual(before); // exactly the original set: nothing else was modified or removed
  }, 60_000);

  it("DPAPI protects the device key for the current user only (round trip, not stored in clear)", () => {
    const blob = win.protect("hdv_secret_value_for_test");
    expect(blob).toBeTruthy();
    expect(blob).not.toContain("hdv_secret_value_for_test");
    expect(win.unprotect(blob!)).toBe("hdv_secret_value_for_test");
  }, 60_000);

  it("reads Windows Security status (observation only) and process NAMES only", () => {
    const os = win.osSecurity();
    if (os) {
      expect(os.provider).toBe("windows-security");
      expect(typeof os.checked_at).toBe("string");
    }
    for (const p of win.processCandidates(["node"])) {
      expect(Object.keys(p).sort()).toEqual(["confidence", "count", "name"]); // no command lines, paths or titles
      expect(p.confidence).toBe("weak");
    }
  }, 60_000);
});
