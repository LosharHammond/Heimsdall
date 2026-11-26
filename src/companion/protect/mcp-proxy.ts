/**
 * `heimdall mcp-proxy --key <tool> --server <name> -- <original command...>`
 *
 * Sits between an AI app (Claude Desktop, Cursor, ...) and one of its MCP tool servers. Every message passes through untouched,
 * except tools/call: Heimdall is asked first. Allowed calls go through; refused ones get an error the AI can read; calls that
 * need approval wait for a person (up to about 50 seconds, then the AI is told to try again after approval).
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { askGate, offlineDecision, type BeginResult } from "./gate.js";
import { classifyToolCall } from "./classify.js";

export interface ProxyOptions {
  key: string; server: string; command: string; args: string[]; stateDir: string;
  stdin?: NodeJS.ReadableStream; stdout?: NodeJS.WritableStream; waitMs?: number;
  ask?: (path: "/begin" | "/end", body: unknown) => Promise<any | null>;
}

/** Windows runs npx/uvx and other .cmd launchers through cmd.exe; quote every argument for it. */
function spawnArgs(command: string, args: string[]): [string, string[], { shell?: boolean }] {
  if (process.platform !== "win32" || /\.exe$/i.test(command)) return [command, args, {}];
  const q = (s: string) => (/^[A-Za-z0-9_\-.:\\/=@+,]+$/.test(s) ? s : `"${s.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1")}"`);
  return [process.env.ComSpec ?? "cmd.exe", ["/d", "/s", "/c", `"${[command, ...args].map(q).join(" ")}"`], {}];
}

export function runMcpProxy(o: ProxyOptions): Promise<number> {
  const out = o.stdout ?? process.stdout;
  const ask = o.ask ?? ((p, b) => askGate(o.stateDir, p, b));
  const [cmd, args, extra] = spawnArgs(o.command, o.args);
  const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "inherit"], windowsVerbatimArguments: process.platform === "win32" && !/\.exe$/i.test(o.command), ...extra });
  const inFlight = new Map<string, string>(); // JSON-RPC id -> gate token
  const write = (msg: unknown) => out.write(JSON.stringify(msg) + "\n");

  createInterface({ input: child.stdout! }).on("line", (line) => {
    out.write(line + "\n");
    try {
      const m = JSON.parse(line);
      const k = m && m.id !== undefined ? JSON.stringify(m.id) : null;
      if (k && inFlight.has(k) && ("result" in m || "error" in m)) {
        const token = inFlight.get(k)!;
        inFlight.delete(k);
        if (token) void ask("/end", { token, ok: !m.error && !m.result?.isError, error: m.error?.message });
      }
    } catch { /* not JSON: passed through as is */ }
  });

  createInterface({ input: o.stdin ?? process.stdin }).on("line", async (line) => {
    let m: any;
    try { m = JSON.parse(line); } catch { child.stdin!.write(line + "\n"); return; }
    if (m?.method !== "tools/call" || m.id === undefined) { child.stdin!.write(line + "\n"); return; }
    const action = classifyToolCall(o.server, String(m.params?.name ?? "tool"), m.params?.arguments ?? {});
    let r: BeginResult | null = await ask("/begin", { key: o.key, action, wait_ms: o.waitMs ?? 50_000 });
    if (!r || r.status === "not_authorized") r = offlineDecision(action);
    if (r.status === "allowed") {
      inFlight.set(JSON.stringify(m.id), r.token);
      child.stdin!.write(line + "\n");
      return;
    }
    const text = r.status === "pending"
      ? `Heimdall paused this action: it needs approval (${action.operation.replace("_", " ")} ${action.resource}). Ask an approver to approve it in Heimdall, then try again.`
      : `Heimdall blocked this action: ${r.message}`;
    write({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text }], isError: true } });
  });

  return new Promise((resolve) => {
    child.on("exit", (code) => resolve(code ?? 0));
    child.on("error", (e) => { process.stderr.write(`heimdall mcp-proxy: could not start ${o.command}: ${e.message}\n`); resolve(1); });
    ((o.stdin ?? process.stdin) as NodeJS.EventEmitter).on("end", () => child.stdin!.end());
  });
}
