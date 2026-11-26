/**
 * Test server for the Python SDK tests (sdk/python/tests). Runs the real Heimdall app on an embedded database, creates an
 * organization, an agent with a policy and an API key, and prints one JSON line: {url, api_key, agent_id, public_key_pem}.
 * A few /__test/* control routes (this script only, never the product) let the tests act as the dashboard owner.
 *   npx tsx scripts/py-test-server.ts
 */
import { createServer } from "node:http";
import { getRequestListener } from "@hono/node-server";
import type { PolicyDocument } from "../src/shared/policy.js";
import { makeEnv, makeWorld } from "../tests/helpers.js";

const POLICY: PolicyDocument = {
  schema_version: 1,
  rules: [
    { id: "no-cmd", effect: "deny", match: { operations: ["command_execution"] } },
    { id: "no-secret", effect: "deny", match: { resources: ["docs/secret/**"] } },
    { id: "del-approval", effect: "require_approval", match: { tools: ["*"], operations: ["delete"] }, approval: { required_role: "admin", ttl_seconds: 900 } },
    { id: "read", effect: "allow", match: { tools: ["documents", "read_doc"], operations: ["read"], resources: ["docs/**"] } },
    { id: "write", effect: "allow", match: { tools: ["documents", "write_summary"], operations: ["create"], resources: ["summaries/**"] } },
    { id: "send", effect: "allow", match: { tools: ["send_report"], operations: ["external_transfer"], destination_domains: ["partner.example.com"] } },
  ],
};

const env = await makeEnv();
const w = await makeWorld(env, { policy: POLICY });
const app = getRequestListener(env.app.fetch);
const json = (res: any, status: number, body: unknown) => {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
};
const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://x");
  if (!url.pathname.startsWith("/__test/")) return app(req, res);
  let body = "";
  for await (const ch of req) body += ch;
  const input = body ? JSON.parse(body) : {};
  if (url.pathname === "/__test/approve") {
    const r = await w.owner.api("POST", `/api/orgs/${w.orgId}/approvals/${input.approval_id}/approve`, { note: "py test" });
    return json(res, r.status, r.body);
  }
  if (url.pathname === "/__test/policy") {
    const r = await w.owner.api("PUT", `/api/orgs/${w.orgId}/policies/${w.policyId}`, { document: input.document ?? POLICY });
    return json(res, r.status, r.body);
  }
  if (url.pathname === "/__test/revoke") {
    const r = await w.owner.api("POST", `/api/orgs/${w.orgId}/credentials/${w.credentialId}/revoke`);
    return json(res, r.status, r.body);
  }
  if (url.pathname === "/__test/actions") {
    const rows = await env.db.query("SELECT a.request_id, a.tool, a.operation, a.resource, a.source, d.decision, d.reason_code FROM action_requests a LEFT JOIN authorization_decisions d ON d.action_request_id = a.id WHERE a.org_id = $1 ORDER BY a.created_at", [w.orgId]);
    return json(res, 200, { items: rows });
  }
  if (url.pathname === "/__test/alerts") {
    return json(res, 200, { items: await env.db.query("SELECT kind, severity, title FROM alerts WHERE org_id = $1", [w.orgId]) });
  }
  json(res, 404, {});
});
server.listen(0, "127.0.0.1", () => {
  const addr = server.address() as { port: number };
  process.stdout.write(JSON.stringify({ url: `http://127.0.0.1:${addr.port}`, api_key: w.apiKey, agent_id: w.agentId, public_key_pem: env.signer!.publicKeyPem }) + "\n");
});
