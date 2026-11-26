import { mkdirSync } from "node:fs";
import pg from "pg";
import type { Config } from "./config.js";

export interface Queryable {
  query<T = Record<string, any>>(sql: string, params?: unknown[]): Promise<T[]>;
}
export interface Db extends Queryable {
  kind: "pg" | "pglite";
  exec(sql: string): Promise<void>;
  tx<T>(fn: (t: Queryable) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export async function createDb(
  config: Pick<Config, "DATABASE_URL" | "DATABASE_SSL" | "DATA_DIR"> & Partial<Pick<Config, "DATABASE_SCHEMA" | "DATABASE_POOL_MAX">>,
  opts: { memory?: boolean } = {},
): Promise<Db> {
  if (config.DATABASE_URL) return createPgDb(config.DATABASE_URL, config.DATABASE_SSL === "require", config.DATABASE_SCHEMA, config.DATABASE_POOL_MAX ?? 10);
  const dir = opts.memory ? undefined : `${config.DATA_DIR}/pglite`;
  if (dir) mkdirSync(dir, { recursive: true });
  const { PGlite } = await import("@electric-sql/pglite"); // development/test only: never loaded in production
  const lite = new PGlite(dir);
  await lite.waitReady;
  return {
    kind: "pglite",
    async query<T>(sql: string, params: unknown[] = []) {
      return (await lite.query<T>(sql, params as any[])).rows;
    },
    async exec(sql) {
      await lite.exec(sql);
    },
    async tx(fn) {
      return lite.transaction(async (t) => fn({ query: async (sql, params = []) => (await t.query(sql, params as any[])).rows as any }));
    },
    async close() {
      await lite.close();
    },
  };
}

function createPgDb(url: string, ssl: boolean, schema: string | undefined, max: number): Db {
  const pool = new pg.Pool({
    connectionString: url,
    max,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
    statement_timeout: 15000,
    ssl: ssl ? { rejectUnauthorized: true } : undefined,
  });
  // A dedicated schema (DATABASE_SCHEMA): every connection looks there first. Needs a session-level connection (Supabase's
  // "Session pooler" or direct connection), because a transaction pooler would not keep the setting between statements.
  if (schema) {
    pool.on("connect", (client) => {
      client.query(`CREATE SCHEMA IF NOT EXISTS "${schema}"; SET search_path TO "${schema}", public, extensions`).catch(() => undefined);
    });
  }
  pool.on("error", () => {
    /* idle client errors are surfaced on the next query */
  });
  return {
    kind: "pg",
    async query<T>(sql: string, params: unknown[] = []) {
      return (await pool.query(sql, params as any[])).rows as T[];
    },
    async exec(sql) {
      await pool.query(sql);
    },
    async tx(fn) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const r = await fn({ query: async (sql, params = []) => (await client.query(sql, params as any[])).rows as any });
        await client.query("COMMIT");
        return r;
      } catch (e) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw e;
      } finally {
        client.release();
      }
    },
    async close() {
      await pool.end();
    },
  };
}
