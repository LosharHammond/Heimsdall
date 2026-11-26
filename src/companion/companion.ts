/**
 * The companion's logic, separated from the process wrapper so it can be tested with a fake Windows layer and an in-process service.
 *
 * Responsibilities (and only these):
 *   heartbeat   -> tells the service the companion/executor/notification state (consent-gated optional telemetry)
 *   notify      -> shows Windows toasts for incident-class alerts, at most a few at a time, summarizing backlogs
 *   commands    -> runs the safe protection test / test notification when an administrator asks for one
 *   degraded    -> tells the local user (once) when the cloud is unreachable or the executor's policy cache expired
 *   removal     -> if the device is revoked or uninstalled, removes ONLY app-owned startup/credentials
 * It does not enforce anything itself: enforcement happens in the executor that sits in front of the protected resources.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync, readdirSync, rmdirSync } from "node:fs";
import { join } from "node:path";
import { readExecutorStatus, executorStatusPath } from "../executor/status.js";
import { runSelfTest, type SelfTestResult } from "./selftest.js";
import { Windows } from "./windows.js";

export interface CompanionConfig {
  url: string;
  device_id: string;
  device_key_protected: string; // DPAPI blob (current user) on Windows
  consent: { os_security: boolean; process_inventory: boolean };
  enrolled_at: string;
  version: string;
}

export const COMPANION_VERSION = "0.1.0";
export const configPath = (stateDir: string) => join(stateDir, "companion.json");

export function saveConfig(stateDir: string, cfg: CompanionConfig) {
  mkdirSync(stateDir, { recursive: true });
  const tmp = `${configPath(stateDir)}.tmp`;
  writeFileSync(tmp, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  renameSync(tmp, configPath(stateDir));
}
export function loadConfig(stateDir: string): CompanionConfig | null {
  try {
    return JSON.parse(readFileSync(configPath(stateDir), "utf8")) as CompanionConfig;
  } catch {
    return null;
  }
}

export interface Deps {
  stateDir: string;
  windows: Windows;
  fetch: typeof fetch;
  now?: () => number;
  selfTest?: () => Promise<SelfTestResult>;
  /** Called when the service says this device is revoked/removed, after local cleanup. */
  onRemoved?: () => void;
}

type Json = Record<string, any>;

export class Companion {
  private failures = 0;
  private degradedNotified = false;
  private lastExecutorNotice = "";
  private startedAt: number;
  private cfgCache: CompanionConfig;
  private key: string | null = null;
  removed = false;
  /** Everything shown to the local user, for tests and `status`. */
  readonly toasts: Array<{ title: string; body: string; tag?: string; shown: boolean; setting: string }> = [];

  constructor(private deps: Deps, cfg?: CompanionConfig) {
    this.startedAt = (deps.now ?? Date.now)();
    const c = cfg ?? loadConfig(deps.stateDir);
    if (!c) throw new Error("Companion is not enrolled. Run: companion enroll --url <url> --token <token>");
    this.cfgCache = c;
  }

  get cfg() {
    return this.cfgCache;
  }

  private deviceKey(): string {
    if (this.key) return this.key;
    const k = process.platform === "win32" ? this.deps.windows.unprotect(this.cfgCache.device_key_protected) : this.cfgCache.device_key_protected;
    if (!k) throw new Error("Could not unprotect the device key (different Windows user?)");
    this.key = k;
    return k;
  }

  private async api(method: "GET" | "POST", path: string, body?: unknown): Promise<{ status: number; body: Json }> {
    const res = await this.deps.fetch(`${this.cfgCache.url}${path}`, {
      method,
      headers: { authorization: `Bearer ${this.deviceKey()}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
      redirect: "error",
    });
    return { status: res.status, body: (await res.json().catch(() => ({}))) as Json };
  }

  /** Shows a toast and records exactly what Windows said. A suppressed toast is never counted as shown. */
  toast(title: string, body: string, tag?: string) {
    const r = this.deps.windows.showToast({ title, body, tag });
    this.toasts.push({ title, body, tag, shown: r.shown, setting: r.setting });
    return r;
  }

  private heartbeatBody(): Json {
    const ex = readExecutorStatus(executorStatusPath(this.deps.stateDir), (this.deps.now ?? Date.now)());
    const consent = this.cfgCache.consent;
    return {
      companion_version: COMPANION_VERSION,
      uptime_s: Math.round(((this.deps.now ?? Date.now)() - this.startedAt) / 1000),
      executor: { state: ex.state, detail: ex.detail },
      notifications: { state: this.deps.windows.toastSetting(), checked_at: new Date().toISOString() },
      // Only a LIVE executor's self-reported mode is meaningful; a stale file says nothing about the present.
      cloud: ex.status && ex.state === "running" ? { mode: ex.status.mode === "online" ? "online" : "offline_cache", cache_expires_at: ex.status.cache_expires_at ?? undefined, queued_events: ex.status.queued } : { mode: "online" },
      consent,
      ...(consent.os_security ? { os_security: this.deps.windows.osSecurity() ?? undefined } : {}),
      ...(consent.process_inventory ? { processes: { candidates: this.deps.windows.processCandidates() } } : {}),
    };
  }

  /** One pass: heartbeat, commands, notifications, local degraded notices. Safe to call repeatedly. */
  async tick(): Promise<void> {
    if (this.removed) return;
    let hb: { status: number; body: Json };
    try {
      hb = await this.api("POST", "/v1/device/heartbeat", this.heartbeatBody());
    } catch {
      this.failures++;
      if (this.failures >= 3 && !this.degradedNotified) {
        this.degradedNotified = true;
        const ex = readExecutorStatus(executorStatusPath(this.deps.stateDir));
        const until = ex.status?.cache_expires_at ? ` Cached policy is valid until ${new Date(ex.status.cache_expires_at).toLocaleString()}.` : " No policy cache is available, so tool calls through the executor are refused.";
        this.toast("Heimdall can't reach the cloud", `Protected tool calls continue from the signed policy cache; approvals can't be granted.${until}`, "degraded");
      }
      return;
    }
    if (hb.status === 401 && ["DEVICE_REVOKED", "DEVICE_CREDENTIAL_INVALID"].includes(hb.body?.error?.code)) return this.handleRemoved("revoked");
    if (hb.status !== 200) {
      this.failures++;
      return;
    }
    this.failures = 0;
    this.degradedNotified = false;

    for (const cmd of (hb.body.commands ?? []) as Array<{ id: string; kind: string }>) await this.runCommand(cmd);
    await this.deliverNotifications();
    this.executorNotice();
  }

  private async runCommand(cmd: { id: string; kind: string }) {
    let status: "done" | "failed" = "done";
    let result: Json = {};
    try {
      if (cmd.kind === "selftest") result = (await (this.deps.selfTest ?? runSelfTest)()) as unknown as Json;
      else if (cmd.kind === "test_notification") {
        const r = this.toast("Heimdall test notification", "Your administrator asked this device to show a test notification.", `test-${cmd.id.slice(0, 8)}`);
        result = { shown: r.shown, windows_setting: r.setting, accepted_by_windows: r.shown ? this.deps.windows.deliveredTags().some((t) => t === `test-${cmd.id.slice(0, 8)}`) : false };
      } else status = "failed";
    } catch (e) {
      status = "failed";
      result = { error: (e as Error).message.slice(0, 200) };
    }
    await this.api("POST", `/v1/device/commands/${cmd.id}/result`, { status, result }).catch(() => undefined);
  }

  /** At most 3 individual toasts plus one summary per poll; everything is acknowledged so nothing repeats. */
  private async deliverNotifications() {
    const r = await this.api("GET", "/v1/device/notifications").catch(() => null);
    if (!r || r.status !== 200 || !r.body.total) return;
    const acks: Array<{ alert_id: string; state: string; detail?: string }> = [];
    for (const it of r.body.show as Array<{ alert_id: string; title: string; kind: string; severity: string }>) {
      const t = this.toast(it.severity === "high" ? "Heimdall: high-risk incident" : "Heimdall: incident", it.title, `alert-${it.alert_id.slice(0, 8)}`);
      acks.push({ alert_id: it.alert_id, state: t.shown ? "shown" : t.setting === "enabled" || t.setting === "dnd_suspected" || t.setting === "unknown" ? "failed" : "suppressed_disabled", detail: t.shown ? undefined : `Windows notification setting: ${t.setting}` });
    }
    const rest = (r.body.coalesce_ids ?? []) as string[];
    if (rest.length > 0) {
      const t = this.toast("Heimdall: more incidents", `${rest.length} more incident${rest.length === 1 ? "" : "s"} happened while this device was offline or busy. Open the dashboard to review them.`, "backlog");
      for (const id of rest) acks.push({ alert_id: id, state: t.shown ? "coalesced" : "suppressed_disabled", detail: t.shown ? "summarized in one notification" : `Windows notification setting: ${t.setting}` });
    }
    if (acks.length) await this.api("POST", "/v1/device/notifications/ack", { items: acks.slice(0, 200) }).catch(() => undefined);
  }

  /** Tell the local user when the executor's policy cache has expired (protected tool calls are being refused). */
  private executorNotice() {
    const ex = readExecutorStatus(executorStatusPath(this.deps.stateDir), (this.deps.now ?? Date.now)());
    const state = ex.status ? `${ex.status.mode}:${ex.status.cache}` : ex.state;
    if (state === this.lastExecutorNotice) return;
    this.lastExecutorNotice = state;
    if (ex.status?.cache === "expired") this.toast("Heimdall: policy cache expired", "The executor can't verify policy offline any more, so protected tool calls are refused until it reconnects. Other computer activity is not affected.", "cache-expired");
    else if (ex.state === "missing") this.toast("Heimdall: executor not running", "No Heimdall executor is running. AI tool calls through it are not protected until it starts.", "executor-missing");
  }

  private handleRemoved(why: "revoked" | "uninstalled") {
    if (why === "revoked") this.toast("Heimdall: device removed", "An administrator removed this device. Heimdall is cleaning up its own startup entry and credentials. Nothing else on this computer is changed.", "removed");
    this.cleanup();
    this.removed = true;
    this.deps.onRemoved?.();
  }

  /** Removes ONLY what Heimdall created: Run entry, AppUserModelID, device config, executor status/cache. */
  cleanup() {
    this.deps.windows.removeRunKey();
    this.deps.windows.clearHistory();
    this.deps.windows.unregisterAppId();
    const dir = this.deps.stateDir;
    for (const f of ["companion.json", "companion.json.tmp", "executor-status.json", "executor-status.json.tmp"]) rmSync(join(dir, f), { force: true });
    rmSync(join(dir, "executor-cache"), { recursive: true, force: true });
    try {
      if (existsSync(dir) && readdirSync(dir).length === 0) rmdirSync(dir);
    } catch {
      /* not empty or in use: leave it */
    }
  }

  /** User-initiated uninstall: tell the service, then remove app-owned configuration. */
  async uninstall(): Promise<{ unenrolled: boolean }> {
    let unenrolled = false;
    try {
      unenrolled = (await this.api("POST", "/v1/device/unenroll")).status === 200;
    } catch {
      /* offline: an administrator can still revoke the device from the dashboard */
    }
    this.cleanup();
    this.removed = true;
    return { unenrolled };
  }
}
