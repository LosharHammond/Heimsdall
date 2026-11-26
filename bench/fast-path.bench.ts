/**
 * Overhead Heimdall adds to one protected tool call, with a no-op tool so only Heimdall's own cost is measured.
 *   npx tsx bench/fast-path.bench.ts
 * The online figures use an in-process server and embedded database: no real network. Over a real network add your
 * round-trip time three times (authorize, claim, outcome) to the online path; the fast path does not change.
 */
import { performance } from "node:perf_hooks";
import { FastPathAuthority } from "../src/executor/fast-path.js";
import { ProtectedExecutor, GuardianClient } from "../src/sdk/index.js";
import { POLICY_EXAMPLES, evaluate } from "../src/shared/policy.js";
import { verifySignature } from "../src/server/signing.js";
import { makeEnv, makeWorld } from "../tests/helpers.js";

const pct = (xs: number[], p: number) => xs.slice().sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor((p / 100) * xs.length))];
const fmt = (ms: number) => (ms < 1 ? `${(ms * 1000).toFixed(1)} µs` : `${ms.toFixed(2)} ms`);
function report(name: string, xs: number[]) {
  console.log(`${name.padEnd(46)} p50 ${fmt(pct(xs, 50)).padStart(10)}   p99 ${fmt(pct(xs, 99)).padStart(10)}   n=${xs.length}`);
}

const env = await makeEnv();
const doc = POLICY_EXAMPLES.find((e) => e.key === "demo-workspace")!.document;
const w = await makeWorld(env, { policy: doc });
const client = new GuardianClient({ baseUrl: "http://h.test", apiKey: w.apiKey, maxRetries: 0, fetch: ((u: string, i: RequestInit) => env.app.request(new URL(u).pathname, i)) as unknown as typeof fetch });
const noop = { documents: async () => "ok", transfer: async () => "ok" };
const actions = [
  { tool: "documents", operation: "read" as const, resource: "docs/handbook.txt" },
  { tool: "documents", operation: "create" as const, resource: "summaries/s.txt" },
  { tool: "documents", operation: "command_execution" as const, resource: "docs/x" },
  { tool: "transfer", operation: "external_transfer" as const, resource: "reports/q3.pdf", destination: "https://partner.example.com/in" },
];

// 1. The policy engine alone.
const ev: number[] = [];
for (let i = 0; i < 200_000; i++) {
  const a = actions[i % actions.length];
  const t0 = performance.now();
  evaluate(doc, a, { allowedInWindow: 0, hasValidApproval: false });
  ev.push(performance.now() - t0);
}

// 2. Fast path: a full executor.run() with a no-op tool.
const fast = new FastPathAuthority({ client, verify: verifySignature, publicKeyPem: env.signer!.publicKeyPem, flushMs: 250, maxQueue: 1_000_000 });
await fast.start();
const fx = new ProtectedExecutor(client, noop, { fastPath: fast });
const fr: number[] = [];
for (let i = 0; i < 2_000; i++) await fx.run(actions[i % actions.length]); // warm-up
for (let i = 0; i < 50_000; i++) {
  const t0 = performance.now();
  await fx.run(actions[i % actions.length]);
  fr.push(performance.now() - t0);
}
await fast.stop();

// 3. Online path (before this change): authorize + claim + outcome, in-process server, no network.
const ox = new ProtectedExecutor(client, noop);
const on: number[] = [];
for (let i = 0; i < 50; i++) await ox.run(actions[i % actions.length]);
for (let i = 0; i < 1_000; i++) {
  const t0 = performance.now();
  await ox.run(actions[i % actions.length]);
  on.push(performance.now() - t0);
}

console.log("\nHeimdall overhead per protected tool call (no-op tool)\n");
report("policy engine alone (evaluate)", ev);
report("fast path: executor.run(), local decision", fr);
report("online path: executor.run(), in-process server", on);
console.log(`\nfast path audit: ${fast.stats().sent} records sent in background batches, ${fast.stats().mismatches} mismatches`);
console.log(`speed-up at p50: ${(pct(on, 50) / pct(fr, 50)).toFixed(0)}x (before adding any network round trip)\n`);
await env.close();
