/**
 * Runnable demonstration. Everything it submits is labelled `demo: true`, so the dashboard shows a
 * "Demonstration" badge and it stays distinguishable from production activity.
 *
 *   npm run dev            (in one terminal)
 *   npm run demo           (in another)   BASE_URL=http://localhost:8787 by default
 */
import { pathToFileURL } from "node:url";
import { actionDigest } from "../src/shared/action.js";
import { POLICY_EXAMPLES } from "../src/shared/policy.js";
import { GuardianClient, ProtectedExecutor } from "../src/sdk/index.js";
import { createWorkspace, type Workspace } from "./workspace.js";

export interface Check {
  name: string;
  pass: boolean;
  detail: string;
}

export interface DemoResult {
  checks: Check[];
  orgId: string;
  agentId: string;
  email: string;
  password: string;
  passed: boolean;
}

type FetchLike = typeof fetch;

class Admin {
  cookie = "";
  constructor(
    private base: string,
    private f: FetchLike,
  ) {}
  async call(method: string, path: string, body?: unknown) {
    const res = await this.f(`${this.base}${path}`, {
      method,
      headers: { "content-type": "application/json", "x-asg-csrf": "1", ...(this.cookie ? { cookie: this.cookie } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const set = res.headers.get("set-cookie");
    if (set) this.cookie = set.split(";")[0];
    const json = await res.json().catch(() => null);
    if (!res.ok) throw new Error(`${method} ${path} -> ${res.status} ${JSON.stringify(json?.error ?? json)}`);
    return json;
  }
}

export async function runDemo(opts: { baseUrl: string; fetch?: FetchLike; workspace?: Workspace; log?: (s: string) => void; keepWorkspace?: boolean }): Promise<DemoResult> {
  const f = opts.fetch ?? fetch;
  const say = opts.log ?? (() => undefined);
  const ws = opts.workspace ?? createWorkspace();
  const checks: Check[] = [];
  const check = (name: string, pass: boolean, detail: string) => {
    checks.push({ name, pass, detail });
    say(`${pass ? "PASS" : "FAIL"}  ${name}  - ${detail}`);
  };

  // 1. A human administrator sets everything up through the same API the dashboard uses.
  const admin = new Admin(opts.baseUrl, f);
  const stamp = Date.now().toString(36);
  const email = `demo-admin-${stamp}@example.test`;
  const password = `demo-${stamp}-correct-horse`;
  await admin.call("POST", "/api/auth/register", { email, name: "Demo Administrator", password });
  await admin.call("POST", "/api/auth/login", { email, password });
  const org = await admin.call("POST", "/api/orgs", { name: `Demo Org ${stamp}` });
  const policy = await admin.call("POST", `/api/orgs/${org.id}/policies`, {
    name: "Demo workspace policy",
    description: "Created by npm run demo",
    document: POLICY_EXAMPLES.find((e) => e.key === "demo-workspace")!.document,
  });
  const agent = await admin.call("POST", `/api/orgs/${org.id}/agents`, {
    name: "demo-document-assistant",
    description: "Demonstration agent. It can only act through the controlled executor.",
    environment: "development",
    integration_type: "typescript_sdk",
    policy_id: policy.id,
    enforcement_mode: "enforce",
  });
  const cred = await admin.call("POST", `/api/orgs/${org.id}/credentials`, { agent_id: agent.id, name: "demo key" });
  say(`Created organization, policy, agent and a credential (shown once, never logged).`);

  const client = new GuardianClient({ baseUrl: opts.baseUrl, apiKey: cred.secret, fetch: f, demo: true, maxRetries: 1 });
  const executor = new ProtectedExecutor(client, ws.handlers);
  const who = await client.whoami();
  check("Adapter authenticates", who.agent_id === agent.id, `authenticated as '${who.agent_name}'`);

  // 2. Allowed read.
  const read = await executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
  check("Allowed read executes", read.status === "executed", `status=${read.status}`);

  // 3. Allowed create of a summary file.
  const create = await executor.run({ tool: "documents", operation: "create", resource: "summaries/handbook-summary.txt", args: { text: "Summary: remote Fridays; 30-day reimbursement." } });
  check("Allowed summary file is created", create.status === "executed" && ws.exists("summaries/handbook-summary.txt"), `status=${create.status}; file present=${ws.exists("summaries/handbook-summary.txt")}`);

  // 4. Unauthorized deletion (outside the approved namespace): default deny, file untouched.
  const del = await executor.run({ tool: "documents", operation: "delete", resource: "reports/q3-final.txt" });
  check("Unauthorized deletion is refused and has no side effect", del.status === "denied" && ws.exists("reports/q3-final.txt"), `status=${del.status}${del.status === "denied" ? ` (${del.reasonCode})` : ""}; file still present=${ws.exists("reports/q3-final.txt")}`);

  // 5. External transfer to an unapproved destination: denied, nothing in the (simulated) outbox.
  const bad = await executor.run({ tool: "transfer", operation: "external_transfer", resource: "docs/q3-draft.txt", data_classification: "internal", destination: "https://files.evil.example.net/upload", args: { source: "docs/q3-draft.txt" } });
  const outboxBefore = ws.files().filter((p) => p.startsWith("outbox/"));
  check("Transfer to unapproved destination is refused", bad.status === "denied" && outboxBefore.length === 0, `status=${bad.status}${bad.status === "denied" ? ` (${bad.reasonCode})` : ""}; outbox files=${outboxBefore.length}`);

  // 6. A look-alike destination using URL tricks is still refused.
  const trick = await executor.run({ tool: "transfer", operation: "external_transfer", resource: "docs/q3-draft.txt", data_classification: "internal", destination: "https://partner.example.com@evil.example.net/x", args: { source: "docs/q3-draft.txt" } });
  check("Credential-in-URL destination trick is refused", trick.status === "denied" && ws.files().every((p) => !p.startsWith("outbox/")), `status=${trick.status}`);

  // 7. Approved destination: allowed (SIMULATED delivery into a local outbox folder, no network).
  const good = await executor.run({ tool: "transfer", operation: "external_transfer", resource: "docs/q3-draft.txt", data_classification: "internal", destination: "https://partner.example.com/inbox", args: { source: "docs/q3-draft.txt" } });
  check("Transfer to approved destination is allowed (simulated delivery)", good.status === "executed" && ws.exists("outbox/partner.example.com/q3-draft.txt"), `status=${good.status}`);

  // 8. Command execution is denied by an explicit rule.
  const cmd = await executor.run({ tool: "shell", operation: "command_execution", resource: "host/shell", args: { command: "echo hello" } });
  check("Command execution is denied", cmd.status === "denied", `status=${cmd.status}${cmd.status === "denied" ? ` (${cmd.reasonCode})` : ""}`);

  // 9. Human approval: destructive operation waits, nothing is deleted yet.
  const reqId = `req_demo_approval_${stamp}`;
  const pending = await executor.run({ requestId: reqId, tool: "documents", operation: "delete", resource: "docs/old-notes.txt" });
  check("Approval-required delete waits", pending.status === "pending_approval" && ws.exists("docs/old-notes.txt"), `status=${pending.status}; file still present=${ws.exists("docs/old-notes.txt")}`);

  // 10. A human administrator approves that exact action in the dashboard (here through the same API).
  const approvals = await admin.call("GET", `/api/orgs/${org.id}/approvals?status=pending`);
  const mine = approvals.items.find((a: any) => a.resource === "docs/old-notes.txt");
  await admin.call("POST", `/api/orgs/${org.id}/approvals/${mine.id}/approve`, { note: "Demo approval" });
  const resumed = await executor.run({ requestId: reqId, tool: "documents", operation: "delete", resource: "docs/old-notes.txt" });
  check("Approved action executes exactly once", resumed.status === "executed" && !ws.exists("docs/old-notes.txt"), `status=${resumed.status}; file present=${ws.exists("docs/old-notes.txt")}`);

  // 11. The approval is one-time: replaying it does nothing, and it does not cover a different file.
  const replay = await executor.run({ requestId: reqId, tool: "documents", operation: "delete", resource: "docs/old-notes.txt" });
  check("Used approval cannot be replayed", replay.status === "denied", `status=${replay.status}${replay.status === "denied" ? ` (${replay.reasonCode})` : ""}`);
  const other = await executor.run({ tool: "documents", operation: "delete", resource: "docs/q3-draft.txt" });
  check("Approval does not carry over to a different action", other.status === "pending_approval" && ws.exists("docs/q3-draft.txt"), `status=${other.status}; file still present=${ws.exists("docs/q3-draft.txt")}`);

  // 12. Simulated tampering: authorize one action, then try to claim execution of a different one.
  const tamperId = `req_demo_tamper_${stamp}`;
  await client.authorize(tamperId, { tool: "documents", operation: "read", resource: "docs/handbook.txt" });
  const forged = await client.claim(tamperId, actionDigest({ tool: "documents", operation: "read", resource: "docs/q3-draft.txt" }));
  check("Argument change after authorization is refused (simulated tampering)", forged.permitted === false && forged.code === "DIGEST_MISMATCH", `claim code=${forged.code}`);

  // 13. Revoking the credential stops further authorization, and the executor fails closed.
  await admin.call("POST", `/api/orgs/${org.id}/credentials/${cred.id}/revoke`);
  const after = await executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
  check("Revoked credential stops authorization (fail closed)", after.status === "not_authorized", `status=${after.status}${after.status === "not_authorized" ? ` (${after.reasonCode})` : ""}`);

  if (!opts.keepWorkspace && !opts.workspace) ws.cleanup();
  return { checks, orgId: org.id, agentId: agent.id, email, password, passed: checks.every((c) => c.pass) };
}

// CLI entry
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const baseUrl = process.env.BASE_URL ?? "http://localhost:8787";
  const res = await runDemo({ baseUrl, log: (s) => console.log(s), keepWorkspace: false });
  console.log(`\n${res.checks.filter((c) => c.pass).length}/${res.checks.length} checks passed.`);
  console.log(`Sign in to the dashboard to inspect the results (these are DEMONSTRATION records, labelled as such):`);
  console.log(`  email: ${res.email}\n  password: ${res.password}`);
  process.exit(res.passed ? 0 : 1);
}
