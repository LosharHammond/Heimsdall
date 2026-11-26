/**
 * Runs inside the companion: every few minutes, find AI tools on this computer, switch protection on for the ones Heimdall can
 * sit in front of, tell the service what was found, and load the keys it hands back into the local decision service.
 * Nothing for a person to do. If the organization turns automatic protection off, the original settings are restored.
 */
import { existsSync, readFileSync, renameSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { applyProtection, type Launcher } from "./apply.js";
import { scan, type Found, type ScanDeps } from "./discover.js";
import type { Gate } from "./gate.js";

interface Stored { auto_protect: boolean; agents: Record<string, { agent_id: string; api_key_protected: string }>; notified: string[] }

export interface AutoDeps {
  stateDir: string;
  url: string;
  deviceKey: () => string | null;
  fetch?: typeof fetch;
  launcher: Launcher;
  scanDeps: ScanDeps;
  gate: Gate;
  seal: (plain: string) => string | null;
  unseal: (blob: string) => string | null;
  notify?: (title: string, body: string) => void;
  log?: (msg: string) => void;
}

export class AutoProtect {
  private path: string;
  private st: Stored;
  constructor(private d: AutoDeps) {
    this.path = join(d.stateDir, "protected-tools.json");
    this.st = this.load();
  }
  private load(): Stored {
    try { return { auto_protect: true, agents: {}, notified: [], ...JSON.parse(readFileSync(this.path, "utf8")) }; } catch { return { auto_protect: true, agents: {}, notified: [] }; }
  }
  private save() {
    mkdirSync(this.d.stateDir, { recursive: true });
    writeFileSync(`${this.path}.tmp`, JSON.stringify(this.st, null, 2), { mode: 0o600 });
    renameSync(`${this.path}.tmp`, this.path);
  }

  /** Loads the keys this computer already has into the local decision service. */
  async start() {
    for (const [key, a] of Object.entries(this.st.agents)) {
      const apiKey = this.d.unseal(a.api_key_protected);
      if (apiKey) await this.d.gate.setAgent({ key, apiKey });
      else delete this.st.agents[key]; // unreadable (another Windows user, reinstall): ask the service for a new one
    }
  }

  private apply(found: Found[], on: boolean) {
    for (const f of found.filter((x) => x.protectable)) {
      let changed = false;
      try { changed = applyProtection(f, this.d.launcher, on); } catch (e) { this.d.log?.(`could not ${on ? "protect" : "restore"} ${f.product}: ${(e as Error).message}`); continue; }
      if (changed && on && f.running && f.kind === "mcp_client" && !this.st.notified.includes(f.key)) {
        this.st.notified.push(f.key);
        this.d.notify?.(`Restart ${f.product} to finish protecting it`, `Heimdall now checks what ${f.product} does before it happens. Close and reopen it once.`);
      }
      // The settings now route through Heimdall; an app that was already open reads them when it restarts.
      if (on && f.protection === "unprotected") f.protection = changed && f.running && f.kind === "mcp_client" ? "restart_needed" : "protected";
      if (!on && changed) f.protection = "off";
    }
  }

  private async report(found: Found[]) {
    const key = this.d.deviceKey();
    if (!key) return null;
    const items = found.map((f) => ({
      key: f.key, kind: f.kind, product: f.product, detail: f.detail, protectable: f.protectable, running: f.running,
      protection: !this.st.auto_protect && f.protectable ? "off" : f.protection,
      needs_key: f.protectable && !this.st.agents[f.key],
    }));
    const r = await (this.d.fetch ?? fetch)(`${this.d.url}/v1/device/discovery`, {
      method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, body: JSON.stringify({ items }), redirect: "error",
    });
    if (!r.ok) throw new Error(`discovery report failed (${r.status})`);
    return (await r.json()) as { auto_protect: boolean; keys: Array<{ key: string; agent_id: string; api_key: string }> };
  }

  /** One pass. Safe to call repeatedly; does nothing when nothing changed. */
  async tick(): Promise<Found[]> {
    let found = scan(this.d.scanDeps);
    this.apply(found, this.st.auto_protect);
    const res = await this.report(found);
    if (!res) return found;
    for (const k of res.keys) {
      const sealed = this.d.seal(k.api_key);
      if (!sealed) continue;
      this.st.agents[k.key] = { agent_id: k.agent_id, api_key_protected: sealed };
      await this.d.gate.setAgent({ key: k.key, apiKey: k.api_key });
    }
    if (res.auto_protect !== this.st.auto_protect) {
      this.st.auto_protect = res.auto_protect;
      found = scan(this.d.scanDeps);
      this.apply(found, res.auto_protect);
      await this.report(scan(this.d.scanDeps)).catch(() => undefined);
    } else if (found.some((f) => f.protection === "restart_needed")) {
      await this.report(found).catch(() => undefined);
    }
    this.save();
    return found;
  }

  /** Puts every tool's settings back as they were (uninstall, or automatic protection turned off). */
  restoreAll() {
    this.apply(scan(this.d.scanDeps), false);
  }
}

/** The real computer, for scan(). */
export function systemScanDeps(listProcesses: () => Array<{ name: string; cmd: string }>): ScanDeps {
  const home = process.env.USERPROFILE ?? process.env.HOME ?? ".";
  return {
    platform: process.platform, home, appData: process.env.APPDATA ?? join(home, "AppData", "Roaming"),
    exists: (p) => existsSync(p),
    readFile: (p, max = 1024 * 1024) => {
      try {
        const b = readFileSync(p);
        return b.subarray(0, max).toString("utf8");
      } catch { return null; }
    },
    processes: listProcesses,
  };
}
