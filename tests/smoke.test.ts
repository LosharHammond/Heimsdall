import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { actionDigest } from "../src/shared/action.js";
import { makeEnv, makeWorld, newReqId, v1, type Env } from "./helpers.js";

let env: Env;
beforeAll(async () => {
  env = await makeEnv();
});
afterAll(async () => env.close());

describe("smoke", () => {
  it("authorizes, claims and reports an allowed read", async () => {
    const w = await makeWorld(env);
    const a = { request_id: newReqId(), tool: "documents", operation: "read", resource: "docs/a.txt", args: { x: 1 } };
    const r = await v1(env, w.apiKey, "POST", "/v1/authorize", a);
    expect(r.status).toBe(200);
    expect(r.body.decision).toBe("allow");
    const c = await v1(env, w.apiKey, "POST", `/v1/actions/${a.request_id}/claim`, { action_digest: actionDigest(a as any) });
    expect(c.status).toBe(200);
    const o = await v1(env, w.apiKey, "POST", `/v1/actions/${a.request_id}/outcome`, { status: "succeeded" });
    expect(o.status).toBe(200);
    const act = await w.owner.api("GET", `/api/orgs/${w.orgId}/actions`);
    expect(act.body.items[0].state).toBe("executed");
  });
});
