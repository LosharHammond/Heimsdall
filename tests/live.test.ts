import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeEnv, makeWorld, newReqId, newUser, v1, type Env } from "./helpers.js";

describe("Live page data", () => {
  let env: Env;
  beforeAll(async () => { env = await makeEnv(); });
  afterAll(async () => { await env.close(); });

  it("shows every check, the last hour's counts and the rules in force; newer checks only after `since`", async () => {
    const w = await makeWorld(env);
    await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "shell", operation: "command_execution", resource: "host/sh" });
    await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "documents", operation: "delete", resource: "docs/x.txt" });
    const r = await w.owner.api("GET", `/api/orgs/${w.orgId}/live`);
    expect(r.status).toBe(200);
    expect(r.body.feed.length).toBe(2);
    expect(r.body.last_hour.checked).toBe(2);
    expect(r.body.policies[0].rules.length).toBeGreaterThan(0);
    const since = r.body.feed[0].created_at;
    expect((await w.owner.api("GET", `/api/orgs/${w.orgId}/live?since=${encodeURIComponent(since)}`)).body.feed.length).toBe(0);
    await v1(env, w.apiKey, "POST", "/v1/authorize", { request_id: newReqId(), tool: "documents", operation: "read", resource: "docs/a.txt" });
    const next = await w.owner.api("GET", `/api/orgs/${w.orgId}/live?since=${encodeURIComponent(since)}`);
    expect(next.body.feed.map((a: any) => a.resource)).toEqual(["docs/a.txt"]);
    // other organizations' members see nothing
    const stranger = await newUser(env, "stranger");
    expect((await stranger.api("GET", `/api/orgs/${w.orgId}/live`)).status).toBeGreaterThanOrEqual(403);
  });
});
