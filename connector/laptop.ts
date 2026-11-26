/**
 * Laptop test connector: links THIS computer to an agent registered in the dashboard.
 *
 *   npm run connect -- --url http://localhost:8787 --key asg_xxxxxxxx_...
 *   (or set HEIMDALL_URL and HEIMDALL_KEY)
 *
 * What it does, honestly:
 *  - authenticates with the agent's integration key and sends a heartbeat every 30 s, which is what makes the agent
 *    show as "Connected / online" in the dashboard;
 *  - starts a small interactive prompt where every action you type goes through the ProtectedExecutor:
 *    authorize -> (wait for human approval) -> claim -> execute on a sandbox folder -> report outcome.
 *  - the sandbox folder (./laptop-sandbox) is the ONLY place the handlers touch. It does not read your real files,
 *    make network calls or run shell commands.
 */
import { createInterface } from "node:readline/promises";
import { hostname, platform } from "node:os";
import { join } from "node:path";
import { GuardianClient, ProtectedExecutor, type ProtectedAction } from "../src/sdk/index.js";
import { createWorkspace } from "../demo/workspace.js";

const arg = (name: string) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
};
const url = arg("url") ?? process.env.HEIMDALL_URL ?? "http://localhost:8787";
const key = arg("key") ?? process.env.HEIMDALL_KEY;
if (!key) {
  console.error("Missing integration key. Run: npm run connect -- --url <dashboard url> --key <key from the dashboard>");
  process.exit(2);
}

const ws = createWorkspace(join(process.cwd(), "laptop-sandbox"));
const client = new GuardianClient({ baseUrl: url, apiKey: key, adapter: { name: `laptop-connector (${hostname()}/${platform()})`, version: "0.1.0" }, maxRetries: 1 });
const executor = new ProtectedExecutor(client, ws.handlers);

let who;
try {
  who = await client.whoami();
} catch (e) {
  console.error(`Could not connect: ${(e as Error).message}`);
  process.exit(1);
}
console.log(`\nConnected to ${url}`);
console.log(`  agent: ${who.agent_name}   mode: ${who.enforcement_mode}   policy assigned: ${who.policy_assigned ? "yes" : "NO (everything will be denied)"}`);
console.log(`  sandbox folder: ${ws.root}\n`);

const beat = setInterval(() => client.whoami().catch((e) => console.error(`heartbeat failed: ${(e as Error).message}`)), 30_000);

const HELP = `Commands (each one is authorized by your policy before anything happens):
  read <path>                    e.g. read docs/handbook.txt
  create <path> <text...>        e.g. create summaries/note.txt hello
  update <path> <text...>        overwrite an existing file
  delete <path>                  e.g. delete docs/old-notes.txt   (the example policy requires human approval)
  send <path> <url>              simulated external transfer, e.g. send docs/q3-draft.txt https://partner.example.com/inbox
  exec <command...>              command execution (the example policy denies it)
  files                          list sandbox files
  help | quit`;
console.log(HELP + "\n");

const show = (r: Awaited<ReturnType<ProtectedExecutor["run"]>>) => {
  switch (r.status) {
    case "executed": return console.log(`  EXECUTED  ${JSON.stringify(r.result)}${r.outcomeReported ? "" : "  (outcome report failed)"}`);
    case "denied": return console.log(`  REFUSED   ${r.reasonCode}: ${r.explanation}${r.refusalReported ? "  (refusal confirmed to Heimdall)" : ""}`);
    case "pending_approval": return console.log(`  WAITING   approval ${r.approvalId} (open Approvals in the dashboard)`);
    case "execution_failed": return console.log(`  FAILED    ${r.error}`);
    case "not_authorized": return console.log(`  NOT RUN   ${r.reasonCode}: ${r.message}  (failed closed: nothing executed)`);
  }
};

const rl = createInterface({ input: process.stdin, output: process.stdout, prompt: "heimdall> " });
let closed = false;
rl.on("close", () => (closed = true));
const prompt = () => { if (!closed) rl.prompt(); };
prompt();
for await (const raw of rl) {
  const line = raw.trim();
  if (!line) { prompt(); continue; }
  const [cmd, a, ...rest] = line.split(/\s+/);
  if (cmd === "quit" || cmd === "exit") break;
  if (cmd === "help") { console.log(HELP); continue; }
  if (cmd === "files") { console.log(ws.files().map((f) => "  " + f).join("\n")); continue; }
  let action: ProtectedAction | null = null;
  const text = rest.join(" ");
  if (cmd === "read" && a) action = { tool: "documents", operation: "read", resource: a };
  else if (cmd === "create" && a) action = { tool: "documents", operation: "create", resource: a, args: { text } };
  else if (cmd === "update" && a) action = { tool: "documents", operation: "update", resource: a, args: { text } };
  else if (cmd === "delete" && a) action = { tool: "documents", operation: "delete", resource: a };
  else if (cmd === "send" && a && rest[0]) action = { tool: "transfer", operation: "external_transfer", resource: a, destination: rest[0], data_classification: "internal", args: { source: a } };
  else if (cmd === "exec" && a) action = { tool: "shell", operation: "command_execution", resource: "host/shell", args: { command: [a, ...rest].join(" ") } };
  if (!action) { console.log("  unknown command; type help"); prompt(); continue; }
  let r = await executor.run(action, { waitForApprovalMs: 0 });
  show(r);
  if (r.status === "pending_approval") {
    console.log("  ...waiting up to 5 minutes for a human to approve or reject it");
    r = await executor.run({ ...action, requestId: r.requestId }, { waitForApprovalMs: 300_000, pollMs: 2000 });
    show(r);
  }
  prompt();
}
clearInterval(beat);
rl.close();
console.log("Disconnected. (The agent will show as idle in the dashboard after 15 minutes.)");
