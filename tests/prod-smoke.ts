/**
 * Production-mode smoke test on a REAL PostgreSQL server:
 *  1. refuses to boot in production without DATABASE_URL / https APP_URL
 *  2. `npm run migrate` applies the schema (AUTO_MIGRATE=0 for the server, as documented for production)
 *  3. the built server (dist/) starts, /healthz and /readyz respond
 *  4. the full demo runs over real HTTP against it
 *  5. `npm run retention` runs
 * Requires `npm run build` first.
 */
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import EmbeddedPostgres from "embedded-postgres";
import { runDemo } from "../demo/run-demo.js";
import { generateSigningKeyB64 } from "../src/server/signing.js";

const dir = mkdtempSync(join(tmpdir(), "asg-prodpg-"));
const pgPort = 54330;
const appPort = 8799;
const pg = new EmbeddedPostgres({ databaseDir: dir, user: "guardian", password: "guardian-test-only", port: pgPort, persistent: false, onLog: () => undefined, onError: () => undefined });
const step = (s: string) => console.log(`\n== ${s}`);
let failed = false;
const must = (ok: boolean, msg: string) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`);
  if (!ok) failed = true;
};

try {
  await pg.initialise();
  await pg.start();
  await pg.createDatabase("guardian");
  const DATABASE_URL = `postgres://guardian:guardian-test-only@localhost:${pgPort}/guardian`;
  const base = { ...process.env, NODE_ENV: "production", APP_URL: "https://guardian.example.test", PORT: String(appPort), DATABASE_URL, AUTO_MIGRATE: "0", LOG_LEVEL: "warn", RETENTION_INTERVAL_MINUTES: "0" };

  step("production config validation");
  const noDb = spawnSync("node", ["dist/server/main.js"], { env: { ...base, DATABASE_URL: "" }, encoding: "utf8" });
  must(noDb.status !== 0 && /DATABASE_URL is required/.test(noDb.stderr), "server refuses to start in production without DATABASE_URL");
  const http = spawnSync("node", ["dist/server/main.js"], { env: { ...base, APP_URL: "http://insecure.example.test" }, encoding: "utf8" });
  must(http.status !== 0 && /https/.test(http.stderr), "server refuses to start in production with a non-https APP_URL");

  step("migrations");
  const mig = spawnSync("npm", ["run", "migrate", "--silent"], { env: base, encoding: "utf8", shell: true });
  must(mig.status === 0 && /Applied: 0001_init\.sql, 0002_devices_protection\.sql/.test(mig.stdout), `npm run migrate applied the schema (${mig.stdout.trim()})`);
  const again = spawnSync("npm", ["run", "migrate", "--silent"], { env: base, encoding: "utf8", shell: true });
  must(/up to date/.test(again.stdout), "second migrate run is a no-op");

  step("server");
  const server = spawn("node", ["dist/server/main.js"], { env: { ...base, POLICY_SIGNING_KEY: generateSigningKeyB64() }, stdio: "ignore" });
  let ready = false;
  for (let i = 0; i < 40 && !ready; i++) {
    await new Promise((r) => setTimeout(r, 250));
    ready = await fetch(`http://localhost:${appPort}/readyz`).then((r) => r.ok, () => false);
  }
  must(ready, "GET /readyz returns 200 against PostgreSQL");
  const body = await fetch(`http://localhost:${appPort}/readyz`).then((r) => r.json());
  must(body.database === "pg", `readiness reports the pg driver (${JSON.stringify(body)})`);
  const h = await fetch(`http://localhost:${appPort}/`);
  must(h.headers.get("strict-transport-security") !== null, "HSTS header is sent in production");

  const sk = await fetch(`http://localhost:${appPort}/v1/signing-key`);
  must(sk.status === 200 && !!(await sk.json()).public_key_pem, "policy signing key is served when POLICY_SIGNING_KEY is configured (production)");
  const unauth = await fetch(`http://localhost:${appPort}/v1/device/heartbeat`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  must(unauth.status === 401, "device API rejects unauthenticated heartbeats");

  step("demo over HTTP");
  const res = await runDemo({ baseUrl: `http://localhost:${appPort}` });
  for (const c of res.checks) must(c.pass, c.name);

  step("retention CLI");
  const ret = spawnSync("npm", ["run", "retention", "--silent"], { env: base, encoding: "utf8", shell: true });
  must(ret.status === 0 && ret.stdout.includes('"actions"'), `npm run retention ran (${ret.stdout.trim().slice(0, 120)})`);
  server.kill();
} finally {
  await pg.stop().catch(() => undefined);
  rmSync(dir, { recursive: true, force: true });
}
console.log(failed ? "\nPRODUCTION SMOKE FAILED" : "\nPRODUCTION SMOKE PASSED");
process.exit(failed ? 1 : 0);
