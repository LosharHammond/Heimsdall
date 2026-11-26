import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(8787),
  APP_URL: z.string().url().default("http://localhost:5173"),
  DATABASE_URL: z.string().optional(),
  DATABASE_SSL: z.enum(["require", "disable"]).optional(),
  /** Keep Heimdall's tables in their own Postgres schema, e.g. "heimdall" inside a shared Supabase project. Never "public" there:
   *  Supabase publishes the public schema through its REST API. */
  DATABASE_SCHEMA: z.string().regex(/^[a-z_][a-z0-9_]{0,40}$/).optional(),
  /** Connections per server process. Keep it small (2-3) on Vercel, where many short-lived copies can run at once. */
  DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(50).default(10),
  /** Shared secret for the scheduled-jobs endpoint (/api/cron/tick). Vercel Cron and the GitHub Actions workflow send it as a Bearer token. */
  CRON_SECRET: z.string().min(16).optional(),
  DATA_DIR: z.string().default(".data"),
  SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(24 * 30).default(168),
  RETENTION_INTERVAL_MINUTES: z.coerce.number().int().min(0).default(1440),
  /** Ed25519 private key (PKCS#8 DER, base64) used to sign policy bundles for offline use. Required in production for offline caching. */
  POLICY_SIGNING_KEY: z.string().optional(),
  POLICY_BUNDLE_TTL_MINUTES: z.coerce.number().min(1).max(7 * 24 * 60).default(240),
  AUTO_MIGRATE: z.enum(["0", "1"]).default("1"),
  TRUST_PROXY: z.enum(["0", "1"]).default("0"),
  LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),
  /** 32 random bytes, base64. Encrypts authenticator secrets and identity-provider client secrets at rest. Required in production. */
  AUTH_ENCRYPTION_KEY: z.string().optional(),
  /** "Continue with Google": an OAuth client from Google Cloud Console (web application). Both or neither. */
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  /** "Continue with Kenuxa Account": the Kenuxa Accounts site and the shared Supabase project behind it. All three or none. */
  KENUXA_ACCOUNTS_URL: z.string().url().optional(),
  KENUXA_SUPABASE_URL: z.string().url().optional(),
  KENUXA_SUPABASE_ANON_KEY: z.string().optional(),
  /** The client id Heimdall is registered under in Kenuxa Accounts (kenuxa_apps.client_id). */
  KENUXA_CLIENT_ID: z.string().regex(/^[a-z0-9_-]{2,40}$/).default("heimdall"),
  /** Email alerts: an SMTP URL such as smtps://user:password@smtp.example.com:465 (Gmail, Microsoft 365, SES, Mailgun...). */
  SMTP_URL: z.string().optional(),
  /** The From address for alert emails, e.g. "Kenuxa Heimdall <alerts@example.com>". */
  EMAIL_FROM: z.string().max(200).default("Kenuxa Heimdall <alerts@heimdall.local>"),
});

export type Config = z.infer<typeof schema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    throw new Error(`Invalid configuration: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
  }
  const c = parsed.data;
  if (c.NODE_ENV === "production") {
    if (!c.DATABASE_URL) throw new Error("DATABASE_URL is required in production (embedded PGlite is for development only).");
    if (!c.APP_URL.startsWith("https://")) throw new Error("APP_URL must be https:// in production.");
    if (!c.AUTH_ENCRYPTION_KEY) throw new Error("AUTH_ENCRYPTION_KEY is required in production (32 random bytes, base64).");
  }
  if (c.AUTH_ENCRYPTION_KEY && Buffer.from(c.AUTH_ENCRYPTION_KEY, "base64").length !== 32) throw new Error("AUTH_ENCRYPTION_KEY must be 32 bytes, base64-encoded.");
  if (!!c.GOOGLE_CLIENT_ID !== !!c.GOOGLE_CLIENT_SECRET) throw new Error("Set both GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, or neither.");
  // "Continue with Kenuxa Account" is on by default with the public values every Kenuxa app shares (the same ones Kenuxa
  // Accounts' .env.example lists). KENUXA_SIGNIN=0 turns it off; setting the three values yourself overrides them.
  if (!c.KENUXA_ACCOUNTS_URL && !c.KENUXA_SUPABASE_URL && !c.KENUXA_SUPABASE_ANON_KEY && c.NODE_ENV !== "test" && env.KENUXA_SIGNIN !== "0") {
    c.KENUXA_ACCOUNTS_URL = KENUXA_PUBLIC.accounts;
    c.KENUXA_SUPABASE_URL = KENUXA_PUBLIC.supabase;
    c.KENUXA_SUPABASE_ANON_KEY = KENUXA_PUBLIC.anonKey;
  }
  const kenuxa = [c.KENUXA_ACCOUNTS_URL, c.KENUXA_SUPABASE_URL, c.KENUXA_SUPABASE_ANON_KEY].filter(Boolean).length;
  if (kenuxa !== 0 && kenuxa !== 3) throw new Error("Set KENUXA_ACCOUNTS_URL, KENUXA_SUPABASE_URL and KENUXA_SUPABASE_ANON_KEY together, or none.");
  return c;
}

/** Public values shared by every Kenuxa app (browser-safe: the Supabase anon key, never a service key). */
export const KENUXA_PUBLIC = {
  accounts: "https://kenuxa-accounts.vercel.app",
  supabase: "https://mshhfieupbayynxpowit.supabase.co",
  anonKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1zaGhmaWV1cGJheXlueHBvd2l0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTEzNzg0NjYsImV4cCI6MjEwNjk1NDQ2Nn0.F5x5I4bJGu6s14dYPf_rW4kwGhYuPkWOj40LtzwAFgk",
};
