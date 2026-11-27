import { mkdirSync } from "node:fs";
import pg from "pg";
import type { Config } from "./config.js";

// Supabase database CA, published at https://supabase-downloads.s3-ap-southeast-1.amazonaws.com/prod/ssl/prod-ca-2021.crt
// Used only for Supabase hosts; certificate and hostname verification remain enabled.
const SUPABASE_CA = `-----BEGIN CERTIFICATE-----
MIIDxDCCAqygAwIBAgIUbLxMod62P2ktCiAkxnKJwtE9VPYwDQYJKoZIhvcNAQEL
BQAwazELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5l
dyBDYXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEeMBwGA1UEAwwVU3VwYWJh
c2UgUm9vdCAyMDIxIENBMB4XDTIxMDQyODEwNTY1M1oXDTMxMDQyNjEwNTY1M1ow
azELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5ldyBD
YXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEeMBwGA1UEAwwVU3VwYWJhc2Ug
Um9vdCAyMDIxIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqQXW
QyHOB+qR2GJobCq/CBmQ40G0oDmCC3mzVnn8sv4XNeWtE5XcEL0uVih7Jo4Dkx1Q
DmGHBH1zDfgs2qXiLb6xpw/CKQPypZW1JssOTMIfQppNQ87K75Ya0p25Y3ePS2t2
GtvHxNjUV6kjOZjEn2yWEcBdpOVCUYBVFBNMB4YBHkNRDa/+S4uywAoaTWnCJLUi
cvTlHmMw6xSQQn1UfRQHk50DMCEJ7Cy1RxrZJrkXXRP3LqQL2ijJ6F4yMfh+Gyb4
O4XajoVj/+R4GwywKYrrS8PrSNtwxr5StlQO8zIQUSMiq26wM8mgELFlS/32Uclt
NaQ1xBRizkzpZct9DwIDAQABo2AwXjALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFKjX
uXY32CztkhImng4yJNUtaUYsMB8GA1UdIwQYMBaAFKjXuXY32CztkhImng4yJNUt
aUYsMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAB8spzNn+4VU
tVxbdMaX+39Z50sc7uATmus16jmmHjhIHz+l/9GlJ5KqAMOx26mPZgfzG7oneL2b
VW+WgYUkTT3XEPFWnTp2RJwQao8/tYPXWEJDc0WVQHrpmnWOFKU/d3MqBgBm5y+6
jB81TU/RG2rVerPDWP+1MMcNNy0491CTL5XQZ7JfDJJ9CCmXSdtTl4uUQnSuv/Qx
Cea13BX2ZgJc7Au30vihLhub52De4P/4gonKsNHYdbWjg7OWKwNv/zitGDVDB9Y2
CMTyZKG3XEu5Ghl1LEnI3QmEKsqaCLv12BnVjbkSeZsMnevJPs1Ye6TjjJwdik5P
o/bKiIz+Fq8=
-----END CERTIFICATE-----
`;

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
    ssl: ssl ? {
      rejectUnauthorized: true,
      ...(new URL(url).hostname.endsWith(".supabase.com") || new URL(url).hostname.endsWith(".supabase.co") ? { ca: SUPABASE_CA } : {}),
    } : undefined,
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
