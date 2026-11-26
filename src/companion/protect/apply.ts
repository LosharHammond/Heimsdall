/**
 * Switches protection on (and off) for found tools, by editing their own settings files:
 *   MCP clients: each local tool server is started through `heimdall mcp-proxy`, which asks Heimdall before every tool call.
 *   Claude Code: a PreToolUse hook asks Heimdall before every command, file change and tool call.
 * The first edit of each file keeps a copy next to it (<file>.heimdall-backup). Turning protection off restores the original
 * entries exactly (they are kept inside the wrapped entry), so nothing the person set up is lost.
 */
import { copyFileSync, existsSync, readFileSync, renameSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { isWrapped, type Found } from "./discover.js";

/** Same content regardless of key order. */
const same = (a: unknown, b: unknown): boolean => {
  const norm = (v: any): any => (Array.isArray(v) ? v.map(norm) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, norm(v[k])])) : v);
  return JSON.stringify(norm(a)) === JSON.stringify(norm(b));
};

export interface Launcher { command: string; prefix: string[] }
export const HOOK_MATCHER = "Bash|PowerShell|Read|Grep|Glob|Write|Edit|MultiEdit|NotebookEdit|WebFetch|mcp__.*";

function readJson(path: string): any {
  if (!existsSync(path)) return {};
  return JSON.parse(readFileSync(path, "utf8").replace(/^﻿/, ""));
}
function writeJson(path: string, obj: unknown) {
  mkdirSync(dirname(path), { recursive: true });
  if (existsSync(path) && !existsSync(`${path}.heimdall-backup`)) copyFileSync(path, `${path}.heimdall-backup`);
  const tmp = `${path}.heimdall-tmp`;
  writeFileSync(tmp, JSON.stringify(obj, null, 2) + "\n");
  renameSync(tmp, path);
}

/** The original server entry inside a wrapped one. */
export function unwrapEntry(entry: any): any {
  if (!isWrapped(entry)) return entry;
  const i = entry.args.indexOf("--");
  const [command, ...args] = entry.args.slice(i + 1);
  const { command: _c, args: _a, ...rest } = entry;
  return { ...rest, command, ...(args.length ? { args } : {}) };
}

export function wrapEntry(entry: any, launcher: Launcher, key: string, server: string): any {
  const orig = unwrapEntry(entry);
  return { ...orig, command: launcher.command, args: [...launcher.prefix, "mcp-proxy", "--key", key, "--server", server, "--", orig.command, ...(orig.args ?? [])] };
}

/** Wraps every local server of one MCP client. Returns whether the file changed. Remote (url) servers are left alone. */
export function protectMcpClient(f: Found, launcher: Launcher, on: boolean): boolean {
  if (!f.config) return false;
  const cfg = readJson(f.config.path);
  const servers = cfg[f.config.serversKey];
  if (!servers || typeof servers !== "object") return false;
  let changed = false;
  for (const [name, entry] of Object.entries<any>(servers)) {
    if (typeof entry?.command !== "string") continue;
    const next = on ? wrapEntry(entry, launcher, f.key, name) : unwrapEntry(entry);
    if (!same(next, entry)) { servers[name] = next; changed = true; }
  }
  if (changed) writeJson(f.config.path, cfg);
  return changed;
}

const quote = (s: string) => (/[\s"&|<>^]/.test(s) ? `"${s.replace(/"/g, '\\"')}"` : s);
export const hookCommand = (l: Launcher) => [l.command, ...l.prefix, "hook", "claude-code"].map(quote).join(" ");

/** Adds (or removes) Heimdall's hook in Claude Code's user settings, keeping every other hook and setting. */
export function protectClaudeCode(f: Found, launcher: Launcher, on: boolean): boolean {
  if (!f.settingsPath) return false;
  const s = readJson(f.settingsPath);
  const pre: any[] = Array.isArray(s?.hooks?.PreToolUse) ? s.hooks.PreToolUse : [];
  const others = pre.filter((h) => !JSON.stringify(h).includes("hook claude-code"));
  const ours = { matcher: HOOK_MATCHER, hooks: [{ type: "command", command: hookCommand(launcher), timeout: 600 }] };
  const next = on ? [...others, ours] : others;
  if (same(next, pre)) return false;
  s.hooks = { ...(s.hooks ?? {}), PreToolUse: next };
  if (!next.length) delete s.hooks.PreToolUse;
  writeJson(f.settingsPath, s);
  return true;
}

export function applyProtection(f: Found, launcher: Launcher, on: boolean): boolean {
  if (f.kind === "mcp_client") return protectMcpClient(f, launcher, on);
  if (f.key === "claude-code") return protectClaudeCode(f, launcher, on);
  return false;
}
