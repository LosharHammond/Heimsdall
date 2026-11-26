import { createServer, type Server } from "node:http";
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTrustedTools } from "../src/executor/trusted.js";
import { ProtectedEgress, isPublicAddress } from "../src/executor/egress.js";
import { ProtectedFs } from "../src/executor/fs-guard.js";
import { ExecutorRefusal, ProtectedExecutor, type ToolDefinition } from "../src/sdk/index.js";
import type { PolicyDocument } from "../src/shared/policy.js";
import { guardianFor, makeEnv, makeWorld, type Env, type World } from "./helpers.js";

const POLICY: PolicyDocument = {
  schema_version: 1,
  classifications: [
    { resources: ["docs/**", "summaries/**"], level: "internal" },
    { resources: ["docs/finance/**"], level: "restricted" },
  ],
  rules: [
    { id: "no-cmd", effect: "deny", match: { operations: ["command_execution"] } },
    { id: "no-restricted-out", effect: "deny", match: { operations: ["external_transfer"], data_classifications: ["restricted"] } },
    { id: "no-secret", effect: "deny", match: { resources: ["docs/secret/**"] } },
    { id: "del-approval", effect: "require_approval", match: { tools: ["documents"], operations: ["delete"], resources: ["docs/**"] }, approval: { required_role: "admin", ttl_seconds: 900 } },
    { id: "read", effect: "allow", match: { tools: ["documents"], operations: ["read"], resources: ["docs/**"] } },
    { id: "update", effect: "allow", match: { tools: ["documents"], operations: ["update"], resources: ["docs/**"] } },
    { id: "write-summary", effect: "allow", match: { tools: ["documents"], operations: ["create"], resources: ["summaries/**"] } },
    { id: "send", effect: "allow", match: { tools: ["transfer"], operations: ["external_transfer"], destination_domains: ["partner.example.com"] } },
  ],
};

let env: Env;
const cleanup: string[] = [];
beforeAll(async () => {
  env = await makeEnv();
});
afterAll(async () => {
  await env.close();
  for (const d of cleanup) rmSync(d, { recursive: true, force: true });
});

function fixture() {
  const base = mkdtempSync(join(tmpdir(), "heimdall-fx-"));
  cleanup.push(base);
  const root = join(base, "protected");
  const outside = join(base, "outside");
  mkdirSync(join(root, "docs", "finance"), { recursive: true });
  mkdirSync(join(root, "docs", "secret"), { recursive: true });
  mkdirSync(join(root, "summaries"), { recursive: true });
  mkdirSync(outside, { recursive: true });
  writeFileSync(join(root, "docs", "handbook.txt"), "HANDBOOK CONTENT");
  writeFileSync(join(root, "docs", "old-notes.txt"), "OLD NOTES");
  writeFileSync(join(root, "docs", "other.txt"), "OTHER");
  writeFileSync(join(root, "docs", "finance", "q3.txt"), "Q3 FINANCE");
  writeFileSync(join(root, "docs", "secret", "k.txt"), "SECRET KEY MATERIAL");
  writeFileSync(join(outside, "secret.txt"), "OUTSIDE SECRET");
  return { base, root, outside };
}
const snapshot = (dir: string): Record<string, string> => {
  const out: Record<string, string> = {};
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else out[p.slice(dir.length)] = readFileSync(p, "utf8");
    }
  };
  walk(dir);
  return out;
};

async function setup(extra: { egress?: ConstructorParameters<typeof ProtectedEgress>[0] } = {}) {
  const fx = fixture();
  const w = await makeWorld(env, { policy: POLICY });
  const trusted = createTrustedTools({ root: fx.root, egress: extra.egress });
  const executor = new ProtectedExecutor(guardianFor(env, w.apiKey), trusted.tools);
  return { fx, w, trusted, executor };
}
const state = async (w: World, resource: string) => (await w.owner.api("GET", `/api/orgs/${w.orgId}/actions?q=${encodeURIComponent(resource)}`)).body.items;

describe("trusted executor: allowed operations and unauthorized deletion", () => {
  it("reads an allowed document and writes an allowed summary", async () => {
    const { fx, executor } = await setup();
    const r = await executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
    expect(r).toMatchObject({ status: "executed", result: { content: "HANDBOOK CONTENT" } });
    const c = await executor.run({ tool: "documents", operation: "create", resource: "summaries/s1.txt", args: { text: "a summary" } });
    expect(c.status).toBe("executed");
    expect(readFileSync(join(fx.root, "summaries", "s1.txt"), "utf8")).toBe("a summary");
    const again = await executor.run({ tool: "documents", operation: "create", resource: "summaries/s1.txt", args: { text: "overwrite attempt" } });
    expect(again.status).not.toBe("executed"); // creation is exclusive: never overwrites
    expect(readFileSync(join(fx.root, "summaries", "s1.txt"), "utf8")).toBe("a summary");
  });

  it("an unauthorized deletion leaves the file intact (observed on disk, not from a reported event)", async () => {
    const { fx, executor, w } = await setup();
    const before = snapshot(fx.root);
    for (const resource of ["reports/q3.txt", "docs/secret/k.txt", "summaries/s1.txt"]) {
      const r = await executor.run({ tool: "documents", operation: "delete", resource });
      expect(["denied", "pending_approval"]).toContain(r.status);
    }
    expect(snapshot(fx.root)).toEqual(before);
    expect(existsSync(join(fx.outside, "secret.txt"))).toBe(true);
    // The dashboard's "blocked" label is a report; the assertion above is the independent proof.
    expect((await state(w, "docs/secret/k.txt"))[0].state).toBe("blocked_confirmed");
  });

  it("an approval-required deletion waits, then executes exactly once after a valid approval", async () => {
    const { fx, executor, w } = await setup();
    const file = join(fx.root, "docs", "old-notes.txt");
    const requestId = `req_${Date.now().toString(36)}_del_00000`;
    const first = await executor.run({ requestId, tool: "documents", operation: "delete", resource: "docs/old-notes.txt" });
    expect(first.status).toBe("pending_approval");
    expect(existsSync(file)).toBe(true);
    const ap = (await w.owner.api("GET", `/api/orgs/${w.orgId}/approvals?status=pending`)).body.items[0];
    expect((await w.owner.api("POST", `/api/orgs/${w.orgId}/approvals/${ap.id}/approve`, {})).status).toBe(200);
    // concurrent retries of the same approved action: exactly one executes
    const results = await Promise.all([1, 2, 3].map(() => executor.run({ requestId, tool: "documents", operation: "delete", resource: "docs/old-notes.txt" })));
    expect(results.filter((r) => r.status === "executed").length).toBe(1);
    expect(existsSync(file)).toBe(false);
    // replay after consumption, and a recreated file must not be deleted by the old approval
    writeFileSync(file, "RECREATED");
    const replay = await executor.run({ requestId, tool: "documents", operation: "delete", resource: "docs/old-notes.txt" });
    expect(replay.status).toBe("denied");
    expect(readFileSync(file, "utf8")).toBe("RECREATED");
  });
});

describe("trusted executor: path attacks (Windows/NTFS and POSIX)", () => {
  it("refuses traversal, encodings, ADS, device names, short names and trailing dots with no side effect", async () => {
    const { fx, executor } = await setup();
    const before = snapshot(fx.base);
    const evil = [
      "../outside/secret.txt", "docs/../../outside/secret.txt", "..\\outside\\secret.txt", "docs/%2e%2e/%2e%2e/outside/secret.txt",
      "docs/\uFF0E\uFF0E/\uFF0E\uFF0E/outside/secret.txt", "docs/handbook.txt:hidden", "docs/handbook.txt.", "docs/handbook.txt ", "docs/CON", "docs/nul.txt",
      "DOCS~1/handbook.txt", "/etc/passwd", "C:/Windows/win.ini", "docs/ha?ndbook.txt",
    ];
    for (const resource of evil) {
      const r = await executor.run({ tool: "documents", operation: "read", resource });
      expect(r.status, resource).not.toBe("executed");
      expect(JSON.stringify(r), resource).not.toContain("OUTSIDE SECRET");
    }
    expect(snapshot(fx.base)).toEqual(before);
  });

  it("canonicalizes case BEFORE authorization so deny rules cannot be dodged on case-insensitive filesystems", async () => {
    const { executor, w } = await setup();
    if (process.platform === "win32" || process.platform === "darwin") {
      const ok = await executor.run({ tool: "documents", operation: "read", resource: "DOCS/Handbook.TXT" });
      expect(ok).toMatchObject({ status: "executed", result: { content: "HANDBOOK CONTENT" } });
      expect((await state(w, "handbook"))[0].resource).toBe("docs/handbook.txt"); // the authorized resource is the real on-disk spelling
      const secret = await executor.run({ tool: "documents", operation: "read", resource: "DOCS/SECRET/K.TXT" });
      expect(secret.status).toBe("denied");
      expect((secret as any).reasonCode).toBe("EXPLICIT_DENY"); // matched `docs/secret/**` after canonicalization
    } else {
      const r = await executor.run({ tool: "documents", operation: "read", resource: "DOCS/secret/k.txt" });
      expect(r.status).not.toBe("executed");
    }
  });

  it("refuses a junction / symlink that points outside the protected folder", async () => {
    const { fx, executor } = await setup();
    const link = join(fx.root, "docs", "linked");
    try {
      symlinkSync(fx.outside, link, process.platform === "win32" ? "junction" : "dir");
    } catch (e) {
      console.warn("link creation not permitted here; skipping junction assertion:", (e as Error).message);
      return;
    }
    const r = await executor.run({ tool: "documents", operation: "read", resource: "docs/linked/secret.txt" });
    expect(r.status).toBe("denied");
    expect((r as any).reasonCode).toMatch(/^EXECUTOR_PATH_(ESCAPES_ROOT|REDIRECTED)$/);
    expect(JSON.stringify(r)).not.toContain("OUTSIDE SECRET");
    expect(readFileSync(join(fx.outside, "secret.txt"), "utf8")).toBe("OUTSIDE SECRET");
    // a file symlink too (may need privileges on Windows)
    try {
      symlinkSync(join(fx.outside, "secret.txt"), join(fx.root, "docs", "filelink.txt"), "file");
      const r2 = await executor.run({ tool: "documents", operation: "read", resource: "docs/filelink.txt" });
      expect(r2.status).toBe("denied");
    } catch {
      /* not permitted: fine */
    }
  });

  it("refuses a hard link inside the folder that aliases a file outside it", async () => {
    const { fx, executor } = await setup();
    try {
      linkSync(join(fx.outside, "secret.txt"), join(fx.root, "docs", "hl.txt"));
    } catch {
      return;
    }
    const r = await executor.run({ tool: "documents", operation: "read", resource: "docs/hl.txt" });
    expect(r.status).toBe("denied");
    expect((r as any).reasonCode).toBe("EXECUTOR_HARDLINK");
    expect(JSON.stringify(r)).not.toContain("OUTSIDE SECRET");
  });

  it("refuses when the file is swapped between authorization and use (resource-change binding)", async () => {
    const { fx, w, trusted } = await setup();
    const file = join(fx.root, "docs", "other.txt");
    let swapped = false;
    const base = trusted.tools.documents;
    const swapping: ToolDefinition = {
      ...base,
      async execute(action, ctx) {
        // runs AFTER authorization, verify and claim: replace the file with a different one (new identity)
        unlinkSync(file);
        writeFileSync(file, "ATTACKER REPLACEMENT");
        swapped = true;
        return base.execute(action, ctx);
      },
    };
    const ex = new ProtectedExecutor(guardianFor(env, w.apiKey), { documents: swapping });
    const r = await ex.run({ tool: "documents", operation: "update", resource: "docs/other.txt", args: { text: "OVERWRITE" } });
    expect(swapped).toBe(true);
    expect(r.status).toBe("execution_failed");
    expect((r as any).error).toMatch(/not the file that was authorized|changed between/);
    expect(readFileSync(file, "utf8")).toBe("ATTACKER REPLACEMENT"); // the replacement was NOT overwritten with the authorized write
    const rows = await state(w, "docs/other.txt");
    expect(rows[0].state).toBe("execution_failed");
    expect(rows[0].error_code).toBe("EXECUTOR_REFUSED_RESOURCE_CHANGED");
  });

  it("ProtectedFs refuses stale identities directly", () => {
    const fx = fixture();
    const fs = new ProtectedFs(fx.root);
    const id = fs.resolve("docs/other.txt", "existing").identity;
    unlinkSync(join(fx.root, "docs", "other.txt"));
    writeFileSync(join(fx.root, "docs", "other.txt"), "new");
    expect(() => fs.delete("docs/other.txt", id)).toThrow(/changed|authorized/);
    expect(readFileSync(join(fx.root, "docs", "other.txt"), "utf8")).toBe("new");
  });
});

describe("command execution", () => {
  it("is denied by policy and the trusted executor has no subprocess capability at all", async () => {
    const { executor } = await setup();
    const r = await executor.run({ tool: "shell", operation: "command_execution", resource: "host/shell", args: { command: "calc.exe" } });
    expect(r.status).toBe("not_authorized"); // no 'shell' tool exists in the trusted executor
    // Even a request routed through a registered tool name is refused by policy and has nothing to run
    const sneaky = new ProtectedExecutor(guardianFor(env, (await makeWorld(env, { policy: POLICY })).apiKey), { shell: { async execute() { throw new Error("must never run"); } } });
    const d = await sneaky.run({ tool: "shell", operation: "command_execution", resource: "host/shell", args: { command: "calc.exe" } });
    expect(d).toMatchObject({ status: "denied", reasonCode: "EXPLICIT_DENY" });
    const src = ["src/executor/fs-guard.ts", "src/executor/egress.ts", "src/executor/trusted.ts", "src/integrations/mcp/server.ts"].map((f) => readFileSync(f, "utf8")).join("\n");
    // no import of the subprocess module anywhere in the trusted code, and no process-starting calls
    expect(src).not.toMatch(/(from|require\()\s*["'](node:)?child_process["']/);
    expect(src).not.toMatch(/(?<![.\w])(spawn|spawnSync|exec|execSync|execFile|execFileSync|fork)\(/); // bare calls only (RegExp#exec is fine)
  });
});

describe("egress: destinations, redirects, private addresses", () => {
  const hits: Array<{ host: string | undefined; body: string }> = [];
  let receiver: Server, decoy: Server, rport = 0, dport = 0;
  const decoyHits: string[] = [];
  beforeAll(async () => {
    receiver = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        hits.push({ host: req.headers.host, body });
        if (req.url?.startsWith("/redirect")) {
          res.writeHead(302, { Location: `http://127.0.0.1:${dport}/stolen` });
          return res.end();
        }
        res.writeHead(200).end("ok");
      });
    });
    decoy = createServer((req, res) => {
      decoyHits.push(req.url ?? "");
      res.writeHead(200).end("decoy");
    });
    await Promise.all([new Promise<void>((r) => receiver.listen(0, "127.0.0.1", r)), new Promise<void>((r) => decoy.listen(0, "127.0.0.1", r))]);
    rport = (receiver.address() as any).port;
    dport = (decoy.address() as any).port;
  });
  afterAll(() => {
    receiver.close();
    decoy.close();
  });
  const resolver = (map: Record<string, string[]>) => async (h: string) => {
    if (!map[h]) throw new Error("NXDOMAIN");
    return map[h];
  };

  it("sends data only to an approved destination; unapproved, lookalike and credentialed URLs send nothing", async () => {
    const { executor } = await setup({ egress: { testReceiver: { port: rport }, resolve: resolver({ "partner.example.com": ["127.0.0.1"], "evil.example.net": ["127.0.0.1"], "partner.example.com.evil.test": ["127.0.0.1"], "evilpartner.example.com": ["127.0.0.1"] }) } });
    hits.length = 0;
    const send = (destination: string, resource = "docs/handbook.txt") => executor.run({ tool: "transfer", operation: "external_transfer", resource, destination });
    const ok = await send("https://partner.example.com/inbox");
    expect(ok).toMatchObject({ status: "executed", result: { sent_to: "partner.example.com", status: 200 } });
    expect(hits).toHaveLength(1);
    expect(hits[0].body).toBe("HANDBOOK CONTENT");
    expect(hits[0].host).toBe("partner.example.com"); // Host header is the approved name even though the connection is pinned to the vetted IP
    const before = hits.length;
    for (const d of [
      "https://evil.example.net/up", "https://partner.example.com.evil.test/", "https://evilpartner.example.com/", "https://partner.example.com@evil.example.net/",
      "https://user:pw@partner.example.com/", "http://127.0.0.1/", "https://[::1]/", "https://2130706433/", "ftp://partner.example.com/", "https://PARTNER.example.com.evil.test./",
    ]) {
      const r = await send(d);
      expect(r.status, d).toBe("denied");
    }
    expect(hits.length).toBe(before); // nothing reached the receiver
  });

  it("never sends restricted data and ignores an agent's claim that it is public", async () => {
    const { executor } = await setup({ egress: { testReceiver: { port: rport }, resolve: resolver({ "partner.example.com": ["127.0.0.1"] }) } });
    const before = hits.length;
    const r = await executor.run({ tool: "transfer", operation: "external_transfer", resource: "docs/finance/q3.txt", destination: "https://partner.example.com/", data_classification: "public" });
    expect(r).toMatchObject({ status: "denied", reasonCode: "EXPLICIT_DENY" });
    expect(hits.length).toBe(before);
  });

  it("refuses private/loopback/mixed DNS answers before the permit is consumed", async () => {
    for (const answer of [["10.0.0.5"], ["192.168.1.9"], ["169.254.169.254"], ["127.0.0.1", "10.0.0.5"], ["8.8.8.8", "169.254.169.254"], ["::ffff:10.0.0.1"], ["fe80::1"]]) {
      const { executor, w } = await setup({ egress: { testReceiver: { port: rport }, resolve: async () => answer } });
      const before = hits.length;
      const r = await executor.run({ tool: "transfer", operation: "external_transfer", resource: "docs/handbook.txt", destination: "https://partner.example.com/x" });
      expect(r.status, answer.join(",")).toBe("denied");
      expect((r as any).reasonCode).toBe("EXECUTOR_PRIVATE_ADDRESS");
      expect(hits.length).toBe(before);
      const row = (await state(w, "handbook"))[0];
      expect(row.state).toBe("blocked_confirmed"); // refused pre-claim: no permit was consumed
    }
  });

  it("never follows redirects", async () => {
    const { executor } = await setup({ egress: { testReceiver: { port: rport }, resolve: resolver({ "partner.example.com": ["127.0.0.1"] }) } });
    decoyHits.length = 0;
    const r = await executor.run({ tool: "transfer", operation: "external_transfer", resource: "docs/handbook.txt", destination: "https://partner.example.com/redirect" });
    expect(r.status).toBe("execution_failed");
    expect((r as any).error).toMatch(/Redirects are never followed/);
    expect(decoyHits).toEqual([]);
  });

  it("rejects a destination host that differs from the authorized host, and classifies addresses correctly", async () => {
    const egress = new ProtectedEgress({ resolve: async () => ["93.184.216.34"] });
    await expect(egress.plan("https://other.example.com/", "partner.example.com")).rejects.toMatchObject({ code: "DESTINATION_MISMATCH" });
    await expect(egress.plan("http://partner.example.com/", "partner.example.com")).rejects.toMatchObject({ code: "SCHEME_NOT_ALLOWED" });
    await expect(egress.plan("https://partner.example.com:8443/", "partner.example.com")).rejects.toMatchObject({ code: "PORT_NOT_ALLOWED" });
    await expect(egress.plan("https://partner.example.com/", "partner.example.com")).resolves.toMatchObject({ address: "93.184.216.34" });
    for (const ip of ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"]) expect(isPublicAddress(ip), ip).toBe(true);
    for (const ip of ["10.1.1.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.0.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fc00::1", "fe80::1", "::ffff:10.0.0.1", "::ffff:7f00:1", "not-an-ip"]) expect(isPublicAddress(ip), ip).toBe(false);
  });
});

describe("trusted classification", () => {
  it("is taken from policy metadata, shown with its source, and unknown classification is handled conservatively", async () => {
    const { executor, w } = await setup({ egress: { testReceiver: { port: 9 }, resolve: async () => ["127.0.0.1"] } });
    await executor.run({ tool: "transfer", operation: "external_transfer", resource: "docs/finance/q3.txt", destination: "https://partner.example.com/", data_classification: "public" });
    const row = (await w.owner.api("GET", `/api/orgs/${w.orgId}/actions?q=q3`)).body.items[0];
    const detail = (await w.owner.api("GET", `/api/orgs/${w.orgId}/actions/${row.id}`)).body;
    expect(detail).toMatchObject({ classification_level: "restricted", classification_source: "policy", data_classification: "public" });
    // A resource the policy does not classify is "unclassified": deny rules naming a class still match it, so it is not exported
    const r = await executor.run({ tool: "transfer", operation: "external_transfer", resource: "docs/handbook.txt", destination: "https://partner.example.com/", data_classification: "public" });
    expect((r as any).status).not.toBe("denied"); // docs/** is classified internal by the policy map: allowed (egress then fails on the closed test port, which is fine here)
    const w2 = await makeWorld(env, { policy: { ...POLICY, classifications: [{ resources: ["summaries/**"], level: "internal" }] } });
    const fx = fixture();
    const ex2 = new ProtectedExecutor(guardianFor(env, w2.apiKey), createTrustedTools({ root: fx.root }).tools);
    const un = await ex2.run({ tool: "transfer", operation: "external_transfer", resource: "docs/handbook.txt", destination: "https://partner.example.com/", data_classification: "public" });
    expect(un).toMatchObject({ status: "denied", reasonCode: "EXPLICIT_DENY" }); // unclassified is treated as potentially restricted by the deny rule
    const d2 = (await w2.owner.api("GET", `/api/orgs/${w2.orgId}/actions`)).body.items[0];
    const dd = (await w2.owner.api("GET", `/api/orgs/${w2.orgId}/actions/${d2.id}`)).body;
    expect(dd).toMatchObject({ classification_level: "unclassified", classification_source: "policy" });
  });
});

describe("executor refusal type", () => {
  it("is exported and carries a stable code", () => {
    expect(new ExecutorRefusal("X", "y")).toMatchObject({ code: "X", name: "ExecutorRefusal" });
  });
});
