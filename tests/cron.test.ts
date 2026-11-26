import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../src/server/app.js";
import { due } from "../src/server/jobs.js";
import { makeEnv, type Env } from "./helpers.js";

let env: Env;
beforeAll(async () => {
  env = await makeEnv();
});
afterAll(() => env.close());

describe("scheduled jobs for serverless hosts", () => {
  it("is off without CRON_SECRET and refuses a wrong secret", async () => {
    expect((await env.app.request("/api/cron/tick", { method: "POST" })).status).toBe(401);
    const app = createApp({ db: env.db, config: { ...env.config, CRON_SECRET: "s".repeat(24) } });
    expect((await app.request("/api/cron/tick", { headers: { authorization: "Bearer wrong" } })).status).toBe(401);
  });

  it("runs every job with the right secret, without a CSRF header", async () => {
    const app = createApp({ db: env.db, config: { ...env.config, CRON_SECRET: "s".repeat(24) } });
    const r = await app.request("/api/cron/tick", { method: "POST", headers: { authorization: `Bearer ${"s".repeat(24)}` } });
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(body.ran).toMatchObject({ alerts: "ok", push: "ok", devices: "ok", retention: "ok" });
    // A second call straight away delivers again but skips the daily and 4-minute jobs.
    const again = await (await app.request("/api/cron/tick", { method: "POST", headers: { authorization: `Bearer ${"s".repeat(24)}` } })).json();
    expect(again.ran.retention).toBeUndefined();
    expect(again.ran.devices).toBeUndefined();
  });

  it("claims a job once per period", async () => {
    expect(await due(env.db, "t-job", 60)).toBe(true);
    expect(await due(env.db, "t-job", 60)).toBe(false);
  });
});
