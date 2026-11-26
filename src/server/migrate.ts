import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Db } from "./db.js";
import { log } from "./log.js";

function migrationsDir(): string {
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 5; i++) {
    const candidate = join(d, "migrations");
    try {
      readdirSync(candidate);
      return candidate;
    } catch {
      d = dirname(d);
    }
  }
  throw new Error("migrations directory not found");
}

export async function runMigrations(db: Db): Promise<string[]> {
  await db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
  const done = new Set((await db.query<{ name: string }>("SELECT name FROM schema_migrations")).map((r) => r.name));
  const dir = migrationsDir();
  const files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
  const applied: string[] = [];
  for (const f of files) {
    if (done.has(f)) continue;
    const sql = readFileSync(join(dir, f), "utf8");
    const record = `INSERT INTO schema_migrations (name) VALUES ('${f.replace(/'/g, "''")}');`;
    try {
      await db.exec(`BEGIN;\n${sql}\n${record}\nCOMMIT;`);
    } catch (e) {
      await db.exec("ROLLBACK").catch(() => undefined);
      throw new Error(`Migration ${f} failed: ${(e as Error).message}`);
    }
    applied.push(f);
    log("info", "migration applied", { name: f });
  }
  return applied;
}
