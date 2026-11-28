/** Browser guard: the extension's detector, and connecting a browser + its decisions against the real service. */
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeEnv, newReqId, newUser, uniq, v1, type Env } from "./helpers.js";

const sandbox: any = {};
runInNewContext(readFileSync(new URL("../browser-extension/detect.js", import.meta.url), "utf8"), sandbox);
const D = sandbox.HeimdallDetect;

describe("detector (runs in the browser)", () => {
  it("lets ordinary text through", () => {
    for (const t of ["How do I sort a list in Python?", "Order 1234 5678 9012 3456 is late", "Call +233 20 123 4567", "Is this information confidential?"]) expect(D.scan(t).findings).toEqual([]);
  });
  it("finds secrets and card numbers, and redacts them", () => {
    expect(D.scan("key sk-proj-abcdefghijklmnopqrstuvwxyz0123").level).toBe("restricted");
    expect(D.scan("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----").findings[0].label).toBe("private key");
    expect(D.scan("card 4111 1111 1111 1111").findings[0].label).toBe("payment card number");
    expect(D.scan("postgres://u:s3cretpw@db.example.com/app").level).toBe("restricted");
    expect(D.redact("use AKIAIOSFODNN7EXAMPLE now")).toBe("use [removed by Heimdall: AWS access key] now");
  });
  it("treats contact lists and confidential documents as needing approval", () => {
    expect(D.scan("a@x.io b@x.io c@x.io d@x.io e@x.io").level).toBe("confidential");
    expect(D.scan("CONFIDENTIAL board minutes").level).toBe("confidential");
    expect(D.scanFileName("C:/p/.env.local").level).toBe("restricted");
    expect(D.scanFileName("holiday.jpg")).toBeNull();
  });
});

let env: Env;
beforeAll(async () => { env = await makeEnv(); });
afterAll(async () => env.close());

describe("connecting a browser", () => {
  it("creates its own agent and key held to the Browser guard policy, and reports status", async () => {
    const owner = await newUser(env, "owner");
    const org = await owner.api("POST", "/api/orgs", { name: uniq("Org") });
    const orgId = org.body.id;
    const r = await owner.api("POST", `/api/orgs/${orgId}/browser-guard`, { browser: "Chrome on Windows" });
    expect(r.status).toBe(201);
    expect(r.body.api_key).toMatch(/^asg_/);
    const key = r.body.api_key;
    const ask = (level: string, host = "chatgpt.com") => v1(env, key, "POST", "/v1/authorize", {
      request_id: newReqId(), tool: "browser", operation: "external_transfer", resource: `browser/${host}/paste`,
      destination: `https://${host}`, data_classification: level, args: { found: ["test"] },
    });
    expect((await ask("restricted")).body.decision).toBe("deny");
    expect((await ask("confidential")).body.decision).toBe("require_approval");
    expect((await ask("internal")).body.decision).toBe("allow");
    expect((await ask("internal", "unknown-site.example")).body.decision).toBe("deny");   // only AI chat sites are listed
    expect((await v1(env, key, "GET", "/v1/whoami")).status).toBe(200);
    const s = await owner.api("GET", `/api/orgs/${orgId}/browser-guard`);
    expect(s.body.active).toBe(1);
    expect(s.body.browsers[0]).toMatchObject({ checked_24h: 4, stopped_24h: 3 });
    // a second browser reuses the same policy
    const r2 = await owner.api("POST", `/api/orgs/${orgId}/browser-guard`, { browser: "Edge on Windows" });
    expect(r2.status).toBe(201);
    const pols = await owner.api("GET", `/api/orgs/${orgId}/policies`);
    expect((pols.body.items ?? pols.body).filter((p: any) => p.name === "Browser guard (automatic)").length).toBe(1);
  });
  it("is not open to people outside the organization", async () => {
    const a = await newUser(env, "a");
    const org = await a.api("POST", "/api/orgs", { name: uniq("Org") });
    const b = await newUser(env, "b");
    expect((await b.api("POST", `/api/orgs/${org.body.id}/browser-guard`, { browser: "Chrome" })).status).toBe(404);
  });
});
