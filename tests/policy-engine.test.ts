import { describe, expect, it } from "vitest";
import { actionDigest, canonicalJson } from "../src/shared/action.js";
import { POLICY_EXAMPLES, evaluate, normalizeDestination, normalizeResource, policyDocumentSchema, type PolicyDocument } from "../src/shared/policy.js";
import { redact, redactString } from "../src/shared/redact.js";

const ctx = { allowedInWindow: 0, hasValidApproval: false };
const doc = (rules: PolicyDocument["rules"], budget?: PolicyDocument["budget"]): PolicyDocument => policyDocumentSchema.parse({ schema_version: 1, rules, budget });
const example = (key: string) => POLICY_EXAMPLES.find((e) => e.key === key)!.document;

describe("policy engine: precedence", () => {
  it("denies by default when nothing matches", () => {
    const d = evaluate(doc([]), { tool: "documents", operation: "read", resource: "docs/a" }, ctx);
    expect(d).toMatchObject({ decision: "deny", reason_code: "NO_MATCHING_RULE" });
  });

  it("explicit deny overrides a matching allow, regardless of rule order", () => {
    const allowFirst = doc([
      { id: "allow-all-deletes", effect: "allow", match: { tools: ["documents"], operations: ["delete"] } },
      { id: "deny-delete", effect: "deny", match: { operations: ["delete"] } },
    ]);
    const d = evaluate(allowFirst, { tool: "documents", operation: "delete", resource: "docs/a" }, ctx);
    expect(d).toMatchObject({ decision: "deny", reason_code: "EXPLICIT_DENY", matched_rule_id: "deny-delete" });
  });

  it("explicit deny overrides an approval rule", () => {
    const p = doc([
      { id: "approve", effect: "require_approval", match: { operations: ["delete"] } },
      { id: "deny", effect: "deny", match: { operations: ["delete"], resources: ["docs/secret/**"] } },
    ]);
    expect(evaluate(p, { tool: "t", operation: "delete", resource: "docs/secret/x" }, { ...ctx, hasValidApproval: true }).decision).toBe("deny");
  });

  it("approval rules take precedence over allow rules and need a valid approval", () => {
    const p = doc([
      { id: "allow-delete", effect: "allow", match: { tools: ["documents"], operations: ["delete"] } },
      { id: "approve-delete", effect: "require_approval", match: { operations: ["delete"] } },
    ]);
    const a = { tool: "documents", operation: "delete" as const, resource: "docs/a" };
    expect(evaluate(p, a, ctx)).toMatchObject({ decision: "require_approval", reason_code: "APPROVAL_REQUIRED" });
    expect(evaluate(p, a, { ...ctx, hasValidApproval: true })).toMatchObject({ decision: "allow", reason_code: "APPROVAL_GRANTED" });
  });

  it("allows only what an explicit allow rule matches", () => {
    const p = example("read-only-assistant");
    expect(evaluate(p, { tool: "documents", operation: "read", resource: "docs/handbook.txt" }, ctx).decision).toBe("allow");
    expect(evaluate(p, { tool: "documents", operation: "read", resource: "secrets/keys.txt" }, ctx).decision).toBe("deny");
    expect(evaluate(p, { tool: "documents", operation: "update", resource: "docs/handbook.txt" }, ctx).decision).toBe("deny");
    expect(evaluate(p, { tool: "other", operation: "read", resource: "docs/handbook.txt" }, ctx).decision).toBe("deny");
  });

  it("is deterministic and returns stable reason codes", () => {
    const p = example("summarizer");
    const a = { tool: "documents", operation: "delete" as const, resource: "docs/a" };
    const first = evaluate(p, a, ctx);
    for (let i = 0; i < 20; i++) expect(evaluate(p, a, ctx)).toEqual(first);
    expect(first.reason_code).toBe("EXPLICIT_DENY");
    expect(first.explanation).toContain("never-delete");
  });

  it("enforces an action budget, which can override allow and approved actions", () => {
    const p = doc([{ id: "read", effect: "allow", match: { tools: ["d"], operations: ["read"] } }], { max_allowed_actions: 2, window_seconds: 60 });
    const a = { tool: "d", operation: "read" as const, resource: "x" };
    expect(evaluate(p, a, { allowedInWindow: 1, hasValidApproval: false }).decision).toBe("allow");
    expect(evaluate(p, a, { allowedInWindow: 2, hasValidApproval: false })).toMatchObject({ decision: "deny", reason_code: "BUDGET_EXCEEDED" });
  });

  it("covers the five documented example policies", () => {
    expect(evaluate(example("no-commands"), { tool: "shell", operation: "command_execution", resource: "host/sh" }, ctx).reason_code).toBe("EXPLICIT_DENY");
    expect(evaluate(example("destructive-needs-approval"), { tool: "documents", operation: "delete", resource: "docs/a" }, ctx).decision).toBe("require_approval");
    const tr = example("approved-destinations");
    const send = (destination: string) => evaluate(tr, { tool: "transfer", operation: "external_transfer", resource: "docs/a", destination, data_classification: "internal" }, ctx);
    expect(send("https://partner.example.com/x").decision).toBe("allow");
    expect(send("https://a.files.example.com/").decision).toBe("allow");
    expect(send("https://files.example.com/")).toMatchObject({ decision: "deny", reason_code: "DESTINATION_NOT_APPROVED" }); // wildcard needs a subdomain
    expect(send("https://evil.test/")).toMatchObject({ decision: "deny", reason_code: "DESTINATION_NOT_APPROVED" });
  });
});

describe("policy engine: destination and resource hardening", () => {
  const tr = example("approved-destinations");
  const send = (destination: string, cls: "internal" | "restricted" | null = "internal") =>
    evaluate(tr, { tool: "transfer", operation: "external_transfer", resource: "docs/a", destination, data_classification: cls ?? undefined }, ctx);

  it("rejects look-alike and trick destinations", () => {
    expect(send("https://partner.example.com.evil.test/").decision).toBe("deny");
    expect(send("https://evilpartner.example.com/").decision).toBe("deny");
    expect(send("https://partner.example.com@evil.test/").reason_code).toBe("INVALID_DESTINATION"); // credentials in URL refused
    expect(send("https://evil.test\\@partner.example.com/").decision).toBe("deny");
    expect(send("ftp://partner.example.com/").reason_code).toBe("INVALID_DESTINATION");
    expect(send("file:///etc/passwd").reason_code).toBe("INVALID_DESTINATION");
    expect(send("javascript:alert(1)").reason_code).toBe("INVALID_DESTINATION");
  });

  it("never lets IP literals or private hosts match a domain allow-list", () => {
    for (const d of ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data", "http://[::1]/", "http://2130706433/", "http://localhost/", "http://0x7f.1/"]) {
      expect(send(d).decision, d).toBe("deny");
    }
  });

  it("normalizes case, trailing dots and punycode before comparing", () => {
    expect(send("HTTPS://PARTNER.EXAMPLE.COM./path").decision).toBe("allow");
    const n = normalizeDestination("https://Bücher.example/x");
    expect(n).toMatchObject({ ok: true, host: "xn--bcher-kva.example" });
  });

  it("refuses path traversal and encoded separators in resources", () => {
    for (const r of ["../etc/passwd", "docs/../../etc/passwd", "/etc/passwd", "docs/%2e%2e/x", "docs\\..\\x", "docs/\u0000x"]) {
      expect(normalizeResource(r).ok, r).toBe(false);
    }
    expect(normalizeResource("./docs//a.txt")).toEqual({ ok: true, value: "docs/a.txt" });
    expect(evaluate(example("read-only-assistant"), { tool: "documents", operation: "read", resource: "docs/../secrets/k" }, ctx).reason_code).toBe("INVALID_RESOURCE");
  });

  it("fails closed when a deny rule constrains classification and none is declared", () => {
    expect(send("https://partner.example.com/", null)).toMatchObject({ decision: "deny", reason_code: "EXPLICIT_DENY" });
    expect(send("https://partner.example.com/", "restricted").decision).toBe("deny");
  });

  it("requires a destination for external transfers", () => {
    expect(evaluate(tr, { tool: "transfer", operation: "external_transfer", resource: "docs/a", data_classification: "internal" }, ctx).reason_code).toBe("INVALID_DESTINATION");
  });
});

describe("policy document validation", () => {
  const bad = (rules: unknown) => policyDocumentSchema.safeParse({ schema_version: 1, rules }).success;
  it("accepts all shipped examples", () => {
    for (const e of POLICY_EXAMPLES) expect(policyDocumentSchema.safeParse(e.document).success, e.key).toBe(true);
  });
  it("rejects unsafe or ambiguous rules", () => {
    expect(bad([{ id: "a", effect: "allow", match: {} }])).toBe(false); // allow-everything
    expect(bad([{ id: "a", effect: "allow", match: { tools: ["*"] } }])).toBe(false); // no operations
    expect(bad([{ id: "a", effect: "allow", match: { tools: ["t"], operations: ["external_transfer"] } }])).toBe(false); // no destinations
    expect(bad([{ id: "a", effect: "allow", match: { tools: ["t"], operations: ["external_transfer"], destination_domains: ["localhost"] } }])).toBe(false);
    expect(bad([{ id: "a", effect: "allow", match: { tools: ["t"], operations: ["external_transfer"], destination_domains: ["*.com"] } }])).toBe(false);
    expect(bad([{ id: "a", effect: "allow", match: { tools: ["t"], operations: ["read"], resources: ["../x"] } }])).toBe(false);
    expect(bad([{ id: "a", effect: "deny", match: {}, approval: { required_role: "admin" } }])).toBe(false);
    expect(bad([{ id: "a", effect: "deny", match: {}, extra: 1 }])).toBe(false); // unknown keys
    expect(bad([{ id: "a", effect: "deny", match: {} }, { id: "A", effect: "deny", match: {} }])).toBe(false); // duplicate ids
    expect(policyDocumentSchema.safeParse({ schema_version: 2, rules: [] }).success).toBe(false);
  });
});

describe("action digest (binding)", () => {
  const base = { tool: "documents", operation: "read" as const, resource: "docs/a", args: { b: 2, a: { y: 1, x: 2 } } };
  it("is stable across key order and sensitive to every bound field", () => {
    expect(actionDigest(base)).toBe(actionDigest({ ...base, args: { a: { x: 2, y: 1 }, b: 2 } }));
    expect(canonicalJson({ b: 1, a: [1, { d: 1, c: 2 }] })).toBe('{"a":[1,{"c":2,"d":1}],"b":1}');
    const d = actionDigest(base);
    expect(actionDigest({ ...base, resource: "docs/b" })).not.toBe(d);
    expect(actionDigest({ ...base, operation: "delete" })).not.toBe(d);
    expect(actionDigest({ ...base, tool: "other" })).not.toBe(d);
    expect(actionDigest({ ...base, args: { ...base.args, b: 3 } })).not.toBe(d);
    expect(actionDigest({ ...base, destination: "https://x.test" })).not.toBe(d);
    expect(actionDigest({ ...base, data_classification: "public" })).not.toBe(d);
  });
});

describe("redaction", () => {
  it("masks secrets, tokens, keys, card numbers and emails; omits content", () => {
    const r = redact({
      password: "hunter2hunter2",
      api_key: "abc",
      note: "send to alice@example.com with Bearer abcdefghijklmnop1234",
      key: "asg_abcdefgh_" + "A".repeat(43),
      aws: "AKIAABCDEFGHIJKLMNOP",
      card: "4111 1111 1111 1111",
      content: "full document text that must not be stored",
      nested: { token: "t", ok: "fine" },
      jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
    }) as Record<string, any>;
    const s = JSON.stringify(r);
    for (const leaked of ["hunter2", "alice@example.com", "abcdefghijklmnop1234", "AKIAABCDEFGHIJKLMNOP", "4111", "full document text", "eyJhbGci", "A".repeat(43)]) {
      expect(s, leaked).not.toContain(leaked);
    }
    expect(r.nested.ok).toBe("fine");
    expect(r.content).toBe("[OMITTED 42 chars]");
  });
  it("truncates long strings and bounds depth", () => {
    expect(redactString("hello world ".repeat(50))).toContain("truncated 400 chars");
    let deep: any = { v: 1 };
    for (let i = 0; i < 10; i++) deep = { d: deep };
    expect(JSON.stringify(redact(deep))).toContain("too deep");
  });
});

describe("trusted classification (agents cannot lower it, only raise it)", () => {
  const pol = policyDocumentSchema.parse({
    schema_version: 1,
    classifications: [{ resources: ["docs/**"], level: "internal" }, { resources: ["docs/finance/**"], level: "restricted" }],
    rules: [
      { id: "no-restricted-out", effect: "deny", match: { operations: ["external_transfer"], data_classifications: ["restricted"] } },
      { id: "send", effect: "allow", match: { tools: ["t"], operations: ["external_transfer"], destination_domains: ["partner.example.com"] } },
    ],
  });
  const send = (resource: string, declared?: "public" | "restricted") => evaluate(pol, { tool: "t", operation: "external_transfer", resource, destination: "https://partner.example.com/", data_classification: declared }, ctx);
  it("takes the highest matching trusted level and ignores a lower claim", () => {
    expect(send("docs/finance/q3.txt", "public")).toMatchObject({ decision: "deny", classification: { level: "restricted", source: "policy" } });
    expect(send("docs/handbook.txt", "public")).toMatchObject({ decision: "allow", classification: { level: "internal", source: "policy" } });
  });
  it("honours a HIGHER claim because it only tightens", () => {
    expect(send("docs/handbook.txt", "restricted")).toMatchObject({ decision: "deny", classification: { level: "restricted", source: "policy_raised_by_agent" } });
  });
  it("treats unclassified resources conservatively: deny/approval rules apply, allow rules requiring a class do not match", () => {
    const d = send("misc/notes.txt", "public");
    expect(d.classification).toEqual({ level: "unclassified", source: "policy" });
    expect(d.decision).toBe("deny"); // the deny rule for restricted data matches unclassified data
    const allowNeedsClass = policyDocumentSchema.parse({ schema_version: 1, classifications: [{ resources: ["docs/**"], level: "public" }], rules: [{ id: "read-public", effect: "allow", match: { tools: ["t"], operations: ["read"], data_classifications: ["public"] } }] });
    expect(evaluate(allowNeedsClass, { tool: "t", operation: "read", resource: "docs/a" }, ctx).decision).toBe("allow");
    expect(evaluate(allowNeedsClass, { tool: "t", operation: "read", resource: "other/a", data_classification: "public" }, ctx).decision).toBe("deny");
  });
  it("without a classifications map the agent's declaration is used but flagged as untrusted", () => {
    const legacy = policyDocumentSchema.parse({ schema_version: 1, rules: [] });
    expect(evaluate(legacy, { tool: "t", operation: "read", resource: "x", data_classification: "public" }, ctx).classification).toEqual({ level: "public", source: "declared" });
    expect(evaluate(legacy, { tool: "t", operation: "read", resource: "x" }, ctx).classification).toEqual({ level: "unclassified", source: "none" });
  });
});
