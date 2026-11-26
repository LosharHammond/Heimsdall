import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

/** What the running executor tells the local companion (and, via /v1/executor/report, the dashboard). A heartbeat, not proof. */
export interface ExecutorStatusFile {
  updated_at: string;
  pid: number;
  version: string;
  state: "running";
  mode: "online" | "offline_cache" | "degraded";
  cache: "fresh" | "expired" | "none" | "invalid";
  cache_expires_at: string | null;
  queued: number;
  roots: Array<{ label: string; prefix: string }>;
  egress_enabled: boolean;
  last_service_contact_at: string | null;
}

/** Per-user state directory. Not shared with other users; only app-owned files live here. */
export function defaultStateDir(): string {
  if (process.env.HEIMDALL_STATE_DIR) return process.env.HEIMDALL_STATE_DIR;
  if (process.platform === "win32" && process.env.LOCALAPPDATA) return join(process.env.LOCALAPPDATA, "KenuxaHeimdall");
  return join(homedir(), ".kenuxa-heimdall");
}

export const executorStatusPath = (stateDir = defaultStateDir()) => join(stateDir, "executor-status.json");

export function writeExecutorStatus(s: ExecutorStatusFile, file = executorStatusPath()) {
  mkdirSync(dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  writeFileSync(tmp, JSON.stringify(s), { mode: 0o600 });
  renameSync(tmp, file);
}

/** Reads the status file; 'missing' when absent, 'stale' when not refreshed within `staleMs`. */
export function readExecutorStatus(file = executorStatusPath(), now = Date.now(), staleMs = 90_000): { state: "running" | "missing" | "stale"; status?: ExecutorStatusFile; detail: string } {
  try {
    const s = JSON.parse(readFileSync(file, "utf8")) as ExecutorStatusFile;
    if (now - new Date(s.updated_at).getTime() > staleMs) return { state: "stale", status: s, detail: `executor status last updated ${Math.round((now - new Date(s.updated_at).getTime()) / 1000)}s ago` };
    return { state: "running", status: s, detail: `executor pid ${s.pid}, mode ${s.mode}` };
  } catch {
    return { state: "missing", detail: "no executor status file: the MCP executor is not running" };
  }
}
