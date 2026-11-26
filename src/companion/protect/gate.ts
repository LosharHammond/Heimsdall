/**
 * The local decision service. Runs inside the companion on 127.0.0.1 with a random secret (readable only by this user), and
 * holds one warm Heimdall client per protected tool, so routine decisions come from the signed policy in memory (fast path)
 * and only approvals go online. The MCP proxy and the Claude Code hook ask it before every action; they hold no keys.
 */
import { randomBytes, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { FastPathAuthority } from "../../executor/fast-path.js";
import { GuardianClient, ProtectedExecutor, type ProtectedAction } from "../../sdk/index.js";
import { verifySignature } from "../../server/signing.js";
import { evaluate } from "../../shared/policy.js";
import { STANDARD_POLICY } from "../../shared/standard-policy.js";

export interface GateAgent { key: string; apiKey: string }
export interface GateInfo { port: number; secret: string; pid: number }
export const gatePath = (stateDir: string) => join(stateDir, "gate.json");

export type BeginResult =
  | { status: "allowed"; token: string; request_id: string }
  | { status: "denied"; reason: string; message: string }
  | { status: "pending"; approval_id: string; message: string }
  | { status: "not_authorized"; message: string };

interface Slot { client: GuardianClient; fast?: FastPathAuthority; apiKey: string }

export class Gate {
  private server: Server | null = null;
  private slots = new Map<string, Slot>();
  private running = new Map<string, { finish: (ok: boolean, error?: string) => void; timer: NodeJS.Timeout }>();
  private secret = randomBytes(32).toString("base64url");

  constructor(private o: { url: string; stateDir: string; fetch?: typeof fetch; fastPath?: boolean; publicKeyPem?: string; announce?: (line: string) => void }) {}

  /** One line per check in the Heimdall window, so a person can see it working. */
  private say(key: string, a: ProtectedAction, verdict: string, why = "") {
    if (!this.o.announce) return;
    const t = new Date().toLocaleTimeString();
    const what = typeof a.args?.command === "string" ? `${a.args.command}` : `${a.operation} ${a.resource}`;
    this.o.announce(`${t}  ${verdict.padEnd(9)} ${key.padEnd(14)} ${what.slice(0, 140)}${why ? `  (${why.slice(0, 120)})` : ""}`);
  }

  /** Adds or replaces the key for one protected tool. */
  async setAgent(a: GateAgent) {
    const old = this.slots.get(a.key);
    if (old?.apiKey === a.apiKey) return;
    await old?.fast?.stop().catch(() => undefined);
    const client = new GuardianClient({ baseUrl: this.o.url, apiKey: a.apiKey, adapter: { name: "heimdall-companion-gate", version: "0.1.0" }, fetch: this.o.fetch, timeoutMs: 8000 });
    const fast = this.o.fastPath === false ? undefined : new FastPathAuthority({ client, verify: verifySignature, publicKeyPem: this.o.publicKeyPem, onError: () => undefined });
    if (fast) await fast.start().catch(() => undefined);
    this.slots.set(a.key, { client, fast, apiKey: a.apiKey });
  }
  hasAgent(key: string) { return this.slots.has(key); }

  /**
   * Asks Heimdall about one action. "allowed" means authorized AND claimed (one-time); the caller performs the action and then
   * calls end(). Waits up to waitMs for a person to approve an action that needs approval.
   */
  async begin(key: string, action: ProtectedAction, waitMs = 0): Promise<BeginResult> {
    const res = await this.decide(key, action, waitMs);
    const verdict = res.status === "allowed" ? "ALLOWED" : res.status === "denied" ? "BLOCKED" : res.status === "pending" ? "WAITING" : "CHECKING";
    this.say(key, action, verdict, res.status === "denied" ? res.message : res.status === "pending" ? "approve it in Heimdall" : res.status === "not_authorized" ? "decided on this computer" : "");
    return res;
  }

  private async decide(key: string, action: ProtectedAction, waitMs: number): Promise<BeginResult> {
    const slot = this.slots.get(key);
    if (!slot) return { status: "not_authorized", message: "This tool is not set up in Heimdall yet." };
    const token = randomUUID();
    let started!: () => void;
    const startedP = new Promise<void>((r) => (started = r));
    const ex = new ProtectedExecutor(slot.client, {
      [action.tool]: async () => {
        started();
        return new Promise((resolve, reject) => {
          const timer = setTimeout(() => this.finish(token, true), 15 * 60_000); // the caller vanished: close the record
          this.running.set(token, { timer, finish: (ok, err) => (ok ? resolve({ ok: true }) : reject(new Error(err ?? "failed"))) });
        });
      },
    }, { fastPath: slot.fast });
    const runP = ex.run(action, waitMs > 0 ? { waitForApprovalMs: waitMs, pollMs: 1500 } : {});
    const first = await Promise.race([startedP.then(() => "started" as const), runP]);
    if (first === "started") {
      void runP.catch(() => undefined);
      return { status: "allowed", token, request_id: token };
    }
    switch (first.status) {
      case "denied": return { status: "denied", reason: first.reasonCode, message: first.explanation };
      case "pending_approval": return { status: "pending", approval_id: first.approvalId, message: "Waiting for approval in Heimdall." };
      case "not_authorized": return { status: "not_authorized", message: first.message };
      default: return { status: "not_authorized", message: "Heimdall could not confirm this action." };
    }
  }

  /** The action finished (or failed): records the outcome. */
  finish(token: string, ok: boolean, error?: string) {
    const r = this.running.get(token);
    if (!r) return false;
    clearTimeout(r.timer);
    this.running.delete(token);
    r.finish(ok, error);
    return true;
  }

  async listen(): Promise<GateInfo> {
    this.server = createServer(async (req, res) => {
      const send = (code: number, body: unknown) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
      try {
        // Only from this computer, only with the secret, only JSON POSTs (a web page cannot send this header).
        if (req.method !== "POST" || req.headers["x-heimdall-gate"] !== this.secret || req.headers.origin) return send(403, { error: "forbidden" });
        const body = await readJson(req);
        if (req.url === "/begin") return send(200, await this.begin(String(body.key), body.action as ProtectedAction, Math.min(Number(body.wait_ms) || 0, 10 * 60_000)));
        if (req.url === "/end") return send(200, { ok: this.finish(String(body.token), body.ok === true, typeof body.error === "string" ? body.error : undefined) });
        return send(404, { error: "not found" });
      } catch (e) {
        send(400, { error: (e as Error).message });
      }
    });
    await new Promise<void>((r) => this.server!.listen(0, "127.0.0.1", r));
    const port = (this.server.address() as { port: number }).port;
    const info: GateInfo = { port, secret: this.secret, pid: process.pid };
    mkdirSync(this.o.stateDir, { recursive: true });
    writeFileSync(gatePath(this.o.stateDir), JSON.stringify(info), { mode: 0o600 });
    return info;
  }

  async close() {
    for (const [t] of this.running) this.finish(t, false, "Heimdall stopped");
    for (const s of this.slots.values()) await s.fast?.stop().catch(() => undefined);
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
    try {
      const cur = JSON.parse(readFileSync(gatePath(this.o.stateDir), "utf8")) as GateInfo;
      if (cur.pid === process.pid) rmSync(gatePath(this.o.stateDir), { force: true });
    } catch { /* already gone */ }
  }
}

function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let n = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => { n += c.length; if (n > 64 * 1024) { reject(new Error("too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); } catch { reject(new Error("bad json")); } });
    req.on("error", reject);
  });
}

/** Client side (MCP proxy, hook): ask the gate. Returns null when Heimdall is not running on this computer. */
export async function askGate(stateDir: string, path: "/begin" | "/end", body: unknown, timeoutMs = 11 * 60_000): Promise<any | null> {
  if (!existsSync(gatePath(stateDir))) return null;
  let info: GateInfo;
  try { info = JSON.parse(readFileSync(gatePath(stateDir), "utf8")); } catch { return null; }
  try {
    const r = await fetch(`http://127.0.0.1:${info.port}${path}`, { method: "POST", headers: { "content-type": "application/json", "x-heimdall-gate": info.secret }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) });
    return r.ok ? await r.json() : null;
  } catch {
    return null;
  }
}

/**
 * When Heimdall is not running on this computer, or this tool has no key yet: decided locally with Standard protection, the same
 * policy the service applies. Ordinary work continues; what Standard protection never allows stays refused; what needs a person
 * is refused until Heimdall is back (nobody can approve it offline).
 */
export function offlineDecision(a: ProtectedAction): BeginResult {
  const d = evaluate(STANDARD_POLICY, { tool: a.tool, operation: a.operation, resource: a.resource, destination: a.destination ?? null }, { allowedInWindow: 0, hasValidApproval: false });
  if (d.decision === "allow") return { status: "allowed", token: "", request_id: "" };
  if (d.decision === "deny") return { status: "denied", reason: d.reason_code, message: `${d.explanation} (decided on this computer: Heimdall is not reachable right now).` };
  return { status: "denied", reason: "HEIMDALL_NOT_RUNNING", message: "This needs a person's approval, and Heimdall is not running on this computer, so nobody can approve it. Start Kenuxa Heimdall and try again." };
}
