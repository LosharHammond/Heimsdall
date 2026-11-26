/**
 * `heimdall hook claude-code`: Claude Code's PreToolUse hook. Reads the tool call on stdin, asks Heimdall, and answers in
 * Claude Code's hook format. Allowed: no output (Claude Code continues normally, its own permission prompts unchanged).
 * Refused: a "deny" with the reason, which Claude sees and can explain. Needs approval: waits for a person (up to 9 minutes).
 */
import { askGate, offlineDecision, type BeginResult } from "./gate.js";
import { classifyClaudeCode } from "./classify.js";

export async function runClaudeCodeHook(input: string, stateDir: string, ask = (p: "/begin" | "/end", b: unknown) => askGate(stateDir, p, b), waitMs = 9 * 60_000): Promise<string> {
  let ev: any;
  try { ev = JSON.parse(input); } catch { return ""; }
  const action = classifyClaudeCode(String(ev?.tool_name ?? ""), ev?.tool_input ?? {}, ev?.cwd);
  if (!action) return "";
  let r: BeginResult | null = await ask("/begin", { key: "claude-code", action, wait_ms: waitMs });
  if (!r || r.status === "not_authorized") r = offlineDecision(action);
  if (r.status === "allowed") {
    if (r.token) await ask("/end", { token: r.token, ok: true });
    return "";
  }
  const reason = r.status === "pending"
    ? "Heimdall: this needs approval and nobody approved it in time. Ask an approver to approve it in Heimdall, then try again."
    : `Heimdall blocked this: ${r.message}`;
  return JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } });
}
