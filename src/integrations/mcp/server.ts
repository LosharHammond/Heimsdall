/**
 * Kenuxa Heimdall MCP server: the supported, real agent integration.
 *
 * Any MCP client (Claude Desktop, Claude Code, ...) launches this process over stdio and sees five tools. The agent never receives
 * a path, a file handle, a credential or a network route: every tool call is authorized by the Heimdall service and then executed
 * by the trusted executor inside THIS process, against ONE protected folder.
 *
 *   HEIMDALL_URL=https://heimdall.example.com HEIMDALL_KEY=asg_... HEIMDALL_ROOT=C:\Heimdall\Protected node dist/integrations/mcp/server.js
 *
 * Boundary: this protects what the agent does THROUGH these tools. If the same MCP client also has other tools (a shell, another
 * filesystem server), those are outside Heimdall's control. Register only this server for file access.
 */
import { pathToFileURL } from "node:url";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createTrustedTools, type TrustedOptions } from "../../executor/trusted.js";
import { join } from "node:path";
import { OfflineAuthority } from "../../executor/offline.js";
import { FastPathAuthority } from "../../executor/fast-path.js";
import { defaultStateDir, executorStatusPath, writeExecutorStatus } from "../../executor/status.js";
import { verifySignature } from "../../server/signing.js";
import { GuardianClient, ProtectedExecutor, type ProtectedAction, type RunResult } from "../../sdk/index.js";

export interface HeimdallMcpConfig {
  client: GuardianClient;
  trusted: TrustedOptions;
  /** How long a tool call waits for a human approval before returning "waiting". 0 = return immediately. */
  approvalWaitMs?: number;
  name?: string;
  /** Signed-policy cache for cloud outages (see docs/OFFLINE.md). Without it the executor fails closed when the service is unreachable. */
  offline?: OfflineAuthority;
  /** In-process decisions from the signed policy (docs/FAST-PATH.md). Only approval-required actions wait on the service. */
  fastPath?: FastPathAuthority;
}

const MAX_RESULT_CHARS = 20_000;

export function describe(r: RunResult): { text: string; isError: boolean } {
  switch (r.status) {
    case "executed": {
      const res = r.result as Record<string, unknown> | undefined;
      const body = res && typeof res.content === "string" ? `\n--- content ---\n${res.content.slice(0, MAX_RESULT_CHARS)}` : res ? `\n${JSON.stringify(res)}` : "";
      const note = r.local || r.offline ? "" : r.outcomeReported ? "" : " (outcome report to Heimdall failed; it will show as 'outcome missing')";
      return { text: `EXECUTED. request_id=${r.requestId}${note}${body}`, isError: false };
    }
    case "denied":
      return { text: `REFUSED (${r.reasonCode}): ${r.explanation} Nothing was executed.`, isError: true };
    case "pending_approval":
      return { text: `WAITING FOR HUMAN APPROVAL. Nothing was executed yet. A person must approve this exact action in the Heimdall dashboard (approval ${r.approvalId}, expires ${r.expiresAt}). Call the same tool again with request_id="${r.requestId}" after it is approved.`, isError: false };
    case "execution_failed":
      return { text: `FAILED after being permitted: ${r.error}. request_id=${r.requestId}`, isError: true };
    case "not_authorized":
      return { text: `NOT EXECUTED (${r.reasonCode}): authorization could not be established (${r.message}). The action was not run.`, isError: true };
  }
}

export function createHeimdallMcpServer(cfg: HeimdallMcpConfig) {
  const { tools } = createTrustedTools(cfg.trusted);
  const executor = new ProtectedExecutor(cfg.client, tools, { offline: cfg.offline, fastPath: cfg.fastPath });
  const server = new McpServer({ name: cfg.name ?? "kenuxa-heimdall", version: "0.1.0" });
  const wait = cfg.approvalWaitMs ?? 0;
  const rid = z.string().regex(/^[A-Za-z0-9_.:-]{8,128}$/).optional().describe("Pass the request_id from an earlier 'waiting for approval' answer to resume that exact action.");

  const run = async (a: ProtectedAction, request_id?: string) => {
    const r = await executor.run({ ...a, requestId: request_id }, { waitForApprovalMs: wait, pollMs: 1500 });
    const d = describe(r);
    return { content: [{ type: "text" as const, text: d.text }], isError: d.isError };
  };

  server.registerTool("read_document", { description: "Read a document from the protected folder (policy decides which).", inputSchema: { path: z.string().max(512), request_id: rid } }, ({ path, request_id }) =>
    run({ tool: "documents", operation: "read", resource: path }, request_id),
  );
  server.registerTool("write_summary", { description: "Create a NEW file (never overwrites) in the protected folder, for example a summary.", inputSchema: { path: z.string().max(512), text: z.string().max(100_000), request_id: rid } }, ({ path, text, request_id }) =>
    run({ tool: "documents", operation: "create", resource: path, args: { text } }, request_id),
  );
  server.registerTool("delete_document", { description: "Delete a document. Policies normally require a human to approve this exact action.", inputSchema: { path: z.string().max(512), request_id: rid } }, ({ path, request_id }) =>
    run({ tool: "documents", operation: "delete", resource: path }, request_id),
  );
  server.registerTool("send_document", { description: "Send a protected document to an approved external destination (https, approved domains only).", inputSchema: { path: z.string().max(512), destination: z.string().max(2048), request_id: rid } }, ({ path, destination, request_id }) =>
    run({ tool: "transfer", operation: "external_transfer", resource: path, destination }, request_id),
  );
  server.registerTool("run_command", { description: "Run a shell command. This is refused by policy; the executor has no way to start a process.", inputSchema: { command: z.string().max(2000) } }, async ({ command }) => {
    // Routed through the executor so the attempt is authorized, recorded and alerted. There is no handler that could run anything.
    const r = await new ProtectedExecutor(cfg.client, { shell: { execute: async () => { throw new Error("command execution is not implemented"); } } }, { offline: cfg.offline, fastPath: cfg.fastPath }).run({
      tool: "shell", operation: "command_execution", resource: "host/shell", args: { command },
    });
    const d = describe(r);
    return { content: [{ type: "text" as const, text: d.text }], isError: true };
  });
  return server;
}

async function main() {
  const url = process.env.HEIMDALL_URL;
  const key = process.env.HEIMDALL_KEY;
  const root = process.env.HEIMDALL_ROOT;
  if (!url || !key || !root) {
    process.stderr.write("HEIMDALL_URL, HEIMDALL_KEY and HEIMDALL_ROOT are required.\n");
    process.exit(2);
  }
  const client = new GuardianClient({ baseUrl: url, apiKey: key, adapter: { name: "heimdall-mcp", version: "0.1.0" }, demo: process.env.HEIMDALL_DEMO === "1" });
  try {
    const who = await client.whoami();
    process.stderr.write(`heimdall-mcp connected as '${who.agent_name}' (${who.enforcement_mode}); protected folder: ${root}\n`);
  } catch (e) {
    process.stderr.write(`heimdall-mcp could not authenticate: ${(e as Error).message}. Tools will refuse every action (fail closed).\n`);
  }
  const stateDir = defaultStateDir();
  const egressEnabled = process.env.HEIMDALL_EGRESS === "1";
  const offline = process.env.HEIMDALL_OFFLINE === "0" ? undefined : new OfflineAuthority({ dir: join(stateDir, "executor-cache"), verify: verifySignature, publicKeyPem: process.env.HEIMDALL_POLICY_PUBKEY });
  // Fast path on by default: routine decisions in-process, audit in the background. HEIMDALL_FAST_PATH=0 turns it off.
  const fastPath =
    process.env.HEIMDALL_FAST_PATH === "0"
      ? undefined
      : new FastPathAuthority({
          client, verify: verifySignature, publicKeyPem: process.env.HEIMDALL_POLICY_PUBKEY ?? offline?.pinnedKey() ?? undefined,
          refreshMs: Number(process.env.HEIMDALL_FAST_PATH_REFRESH_MS ?? 30_000),
          checkMs: Number(process.env.HEIMDALL_FAST_PATH_CHECK_MS ?? 2_000),
          onError: (where, e) => process.stderr.write(`heimdall-mcp: fast path ${where}: ${(e as Error).message}\n`),
        });
  if (fastPath) {
    const st = await fastPath.start();
    process.stderr.write(`heimdall-mcp: fast path ${st === "ready" ? "ready (routine actions decided in-process)" : `not ready (${st}); using the online path until a bundle loads`}\n`);
    const shutdown = () => void fastPath.stop().finally(() => process.exit(0));
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  }
  const server = createHeimdallMcpServer({
    client,
    trusted: { root, egressEnabled },
    approvalWaitMs: Number(process.env.HEIMDALL_APPROVAL_WAIT_MS ?? 0),
    offline,
    fastPath,
  });

  let lastContact: string | null = null;
  const tick = async (refresh: boolean) => {
    let online = true;
    try {
      await client.whoami();
      lastContact = new Date().toISOString();
      if (offline && refresh) {
        const r = await offline.refresh(client).catch(() => ({ ok: false as const }));
        if (!r.ok) process.stderr.write("heimdall-mcp: policy bundle refresh was refused or failed; keeping previous cache\n");
        await offline.flush(client).catch(() => undefined);
      }
    } catch {
      online = false;
    }
    const st = offline?.status();
    const mode = online ? "online" : st?.cache === "fresh" || fastPath?.stats().state === "ready" ? "offline_cache" : "degraded";
    const roots = [{ label: "Protected folder", prefix: "" }];
    try {
      writeExecutorStatus({ updated_at: new Date().toISOString(), pid: process.pid, version: "0.1.0", state: "running", mode, cache: st?.cache ?? "none", cache_expires_at: st?.cache_expires_at ?? null, queued: (st?.queued ?? 0) + (fastPath?.stats().queued ?? 0), roots, egress_enabled: egressEnabled, last_service_contact_at: lastContact });
    } catch {
      /* status is best effort */
    }
    if (online) await client.reportExecutor({ executor_version: "0.1.0", roots, egress_enabled: egressEnabled, mode, cache_expires_at: st?.cache_expires_at ?? undefined, queued_events: (st?.queued ?? 0) + (fastPath?.stats().queued ?? 0) }).catch(() => undefined);
  };
  await tick(true);
  process.stderr.write(`heimdall-mcp: status file ${executorStatusPath(stateDir)}; offline cache ${offline ? "enabled" : "disabled"}
`);
  let n = 0;
  setInterval(() => void tick(++n % 10 === 0), 30_000).unref();
  await server.connect(new StdioServerTransport());
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) await main();
