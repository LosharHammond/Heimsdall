/**
 * Runs the whole test suite against a REAL PostgreSQL server (via the `embedded-postgres` dev dependency),
 * exercising the `pg` driver path used in production instead of the embedded PGlite used for quick local runs.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import EmbeddedPostgres from "embedded-postgres";

const dir = mkdtempSync(join(tmpdir(), "asg-pg-"));
const port = 54329;
const pg = new EmbeddedPostgres({ databaseDir: dir, user: "guardian", password: "guardian-test-only", port, persistent: false, onLog: () => undefined, onError: () => undefined });
let code = 1;
try {
  await pg.initialise();
  await pg.start();
  await pg.createDatabase("guardian_test");
  const url = `postgres://guardian:guardian-test-only@localhost:${port}/guardian_test`;
  const r = spawnSync("npx", ["vitest", "run", ...process.argv.slice(2)], { stdio: "inherit", shell: true, env: { ...process.env, TEST_DATABASE_URL: url } });
  code = r.status ?? 1;
} finally {
  await pg.stop().catch(() => undefined);
  rmSync(dir, { recursive: true, force: true });
}
process.exit(code);
