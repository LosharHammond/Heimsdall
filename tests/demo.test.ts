import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runDemo } from "../demo/run-demo.js";
import { createWorkspace } from "../demo/workspace.js";
import { Session, makeEnv, type Env } from "./helpers.js";

let env: Env;
beforeAll(async () => {
  env = await makeEnv();
});
afterAll(async () => env.close());

describe("end-to-end main workflow (demo against the real app + real fixture side effects)", () => {
  it("runs every demo check and the dashboard reflects the recorded results", async () => {
    const ws = createWorkspace();
    const inProcessFetch = ((url: string, init: RequestInit) => env.app.request(new URL(url).pathname + new URL(url).search, init)) as unknown as typeof fetch;
    const result = await runDemo({ baseUrl: "http://guardian.test", fetch: inProcessFetch, workspace: ws });
    for (const c of result.checks) expect(c.pass, `${c.name}: ${c.detail}`).toBe(true);
    expect(result.checks.length).toBeGreaterThanOrEqual(13);

    // Real fixture side effects
    expect(ws.exists("summaries/handbook-summary.txt")).toBe(true);
    expect(ws.exists("reports/q3-final.txt")).toBe(true); // denied delete: untouched
    expect(ws.exists("docs/old-notes.txt")).toBe(false); // approved delete: executed
    expect(ws.exists("docs/q3-draft.txt")).toBe(true); // approval did not carry over
    expect(ws.files().filter((f) => f.startsWith("outbox/"))).toEqual(["outbox/partner.example.com/q3-draft.txt"]);

    // The dashboard (API) shows what was actually recorded
    const admin = new Session(env, result.email, result.password);
    await admin.signIn();
    const acts = await admin.api("GET", `/api/orgs/${result.orgId}/actions?limit=100`);
    expect(acts.body.items.length).toBeGreaterThanOrEqual(10);
    expect(acts.body.items.every((a: any) => a.is_demo)).toBe(true); // labelled as demonstrations
    const stateOf = (res: string, op: string) => acts.body.items.filter((a: any) => a.resource === res && a.operation === op).map((a: any) => a.state);
    expect(stateOf("docs/handbook.txt", "read")).toContain("executed");
    expect(stateOf("reports/q3-final.txt", "delete")).toEqual(["blocked_confirmed"]);
    expect(stateOf("docs/old-notes.txt", "delete")).toEqual(["executed"]);
    expect(stateOf("docs/q3-draft.txt", "delete")).toEqual(["awaiting_approval"]);

    const ov = await admin.api("GET", `/api/orgs/${result.orgId}/overview`);
    expect(ov.body.decisions.allowed).toBeGreaterThan(0);
    expect(ov.body.decisions.denied).toBeGreaterThan(0);
    expect(ov.body.pending_approvals).toBe(1);
    expect(ov.body.executions.blocked_confirmed).toBeGreaterThan(0);
    expect(ov.body.agents.by_state.revoked).toBe(0); // credential revoked, agent itself still registered
    const alerts = await admin.api("GET", `/api/orgs/${result.orgId}/alerts`);
    const kinds = alerts.body.items.map((a: any) => a.kind);
    expect(kinds).toContain("high_risk_action_denied");
    expect(kinds).toContain("argument_mismatch");
    expect(kinds).toContain("revoked_credential_used");
    ws.cleanup();
  });
});
