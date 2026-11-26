import { setLogLevel } from "../src/server/log.js";
import { createApp } from "../src/server/app.js";
import { loadConfig } from "../src/server/config.js";
import { createDb, type Db } from "../src/server/db.js";
import { loadSigner } from "../src/server/signing.js";
import { runMigrations } from "../src/server/migrate.js";
import { GuardianClient, ProtectedExecutor, type ToolDefinition, type ToolHandler } from "../src/sdk/index.js";
import { POLICY_EXAMPLES, type PolicyDocument } from "../src/shared/policy.js";

export interface Env {
  db: Db;
  app: ReturnType<typeof createApp>;
  signer: ReturnType<typeof loadSigner>;
  config: ReturnType<typeof loadConfig>;
  close: () => Promise<void>;
}

export async function makeEnv(): Promise<Env> {
  const url = process.env.TEST_DATABASE_URL;
  const config = loadConfig({ NODE_ENV: "test", LOG_LEVEL: "error", ...(url ? { DATABASE_URL: url } : {}) } as NodeJS.ProcessEnv);
  setLogLevel(config.LOG_LEVEL);
  const db = await createDb(config, { memory: true });
  if (url) await db.exec("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
  await runMigrations(db);
  const signer = loadSigner(config, { ephemeral: true });
  const app = createApp({ db, config, signer }, { ipLimitsMultiplier: 1000 });
  return { db, app, config, signer, close: () => db.close() };
}

let counter = 0;
export const uniq = (p = "x") => `${p}${Date.now().toString(36)}${(counter++).toString(36)}`;

/** A signed-in browser-like session using the cookie + CSRF header the real dashboard uses. */
export class Session {
  cookie = "";
  constructor(
    public env: Env,
    public email: string,
    public password = "correct horse battery staple",
  ) {}

  async api(method: string, path: string, body?: unknown, extraHeaders: Record<string, string> = {}) {
    const res = await this.env.app.request(path, {
      method,
      headers: { "content-type": "application/json", "x-asg-csrf": "1", ...(this.cookie ? { cookie: this.cookie } : {}), ...extraHeaders },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let json: any = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      /* non-json */
    }
    return { status: res.status, body: json, headers: res.headers };
  }

  async signUp(name = "Test User") {
    const r = await this.api("POST", "/api/auth/register", { email: this.email, name, password: this.password });
    if (r.status !== 201) throw new Error(`register failed ${JSON.stringify(r.body)}`);
    return this.signIn();
  }

  async signIn() {
    const r = await this.api("POST", "/api/auth/login", { email: this.email, password: this.password });
    if (r.status !== 200) throw new Error(`login failed ${JSON.stringify(r.body)}`);
    const set = r.headers.get("set-cookie") ?? "";
    this.cookie = set.split(";")[0];
    return this;
  }
}

export async function newUser(env: Env, label = "user") {
  return new Session(env, `${uniq(label)}@example.test`).signUp(label);
}

export interface World {
  owner: Session;
  orgId: string;
  agentId: string;
  policyId: string;
  apiKey: string;
  credentialId: string;
}

export async function makeWorld(env: Env, opts: { policy?: PolicyDocument; mode?: "monitor" | "enforce"; integration?: "typescript_sdk" | "event_reporting" } = {}): Promise<World> {
  const owner = await newUser(env, "owner");
  const org = await owner.api("POST", "/api/orgs", { name: uniq("Org") });
  const orgId = org.body.id as string;
  const doc = opts.policy ?? POLICY_EXAMPLES.find((e) => e.key === "demo-workspace")!.document;
  const pol = await owner.api("POST", `/api/orgs/${orgId}/policies`, { name: uniq("pol"), document: doc });
  if (pol.status !== 201) throw new Error(`policy create failed ${JSON.stringify(pol.body)}`);
  const ag = await owner.api("POST", `/api/orgs/${orgId}/agents`, {
    name: uniq("agent"), environment: "development", integration_type: opts.integration ?? "typescript_sdk", policy_id: pol.body.id, enforcement_mode: opts.mode ?? "enforce",
  });
  if (ag.status !== 201) throw new Error(`agent create failed ${JSON.stringify(ag.body)}`);
  const cred = await owner.api("POST", `/api/orgs/${orgId}/credentials`, { agent_id: ag.body.id, name: "test key" });
  if (cred.status !== 201) throw new Error(`credential failed ${JSON.stringify(cred.body)}`);
  return { owner, orgId, agentId: ag.body.id, policyId: pol.body.id, apiKey: cred.body.secret, credentialId: cred.body.id };
}

/** Raw /v1 call with a bearer key. */
export async function v1(env: Env, apiKey: string | null, method: string, path: string, body?: unknown) {
  const res = await env.app.request(path, {
    method,
    headers: { "content-type": "application/json", ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

export const guardianFor = (env: Env, apiKey: string, extra: { timeoutMs?: number; maxRetries?: number; fetch?: typeof fetch } = {}) =>
  new GuardianClient({
    baseUrl: "http://guardian.test",
    apiKey,
    demo: true,
    maxRetries: 0,
    fetch: extra.fetch ?? (((url: string, init: RequestInit) => env.app.request(new URL(url).pathname, init)) as unknown as typeof fetch),
    ...extra,
  });

export const executorFor = (env: Env, apiKey: string, handlers: Record<string, ToolHandler | ToolDefinition>, extra = {}) => new ProtectedExecutor(guardianFor(env, apiKey, extra), handlers);

export const newReqId = () => `req_${uniq("r")}${"0".repeat(8)}`;
