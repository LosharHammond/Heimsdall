/**
 * Generates policy/action cases decided by the server's engine (src/shared/policy.ts) and action digests, as JSON on stdout.
 * sdk/python/tests/test_policy_parity.py requires the Python engine to agree on every case.
 *   npx tsx scripts/policy-corpus.ts > corpus.json
 */
import { actionDigest } from "../src/shared/action.js";
import { evaluate, POLICY_EXAMPLES, policyDocumentSchema, type PolicyDocument } from "../src/shared/policy.js";

let seed = 20261125;
const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)];

const tools = ["documents", "transfer", "shell", "email", "db"];
const ops = ["read", "create", "update", "delete", "external_transfer", "command_execution"] as const;
const resources = [
  "docs/handbook.txt", "docs/secret/key.txt", "summaries/q3.md", "reports/q3.pdf", "docs/a/b/c.txt", "docs", "./docs/x.txt", "docs//double.txt",
  "../etc/passwd", "/etc/passwd", "docs/../x", "docs/%2e%2e/x", "docs\\win\\path.txt", "C:/x", "docs/con.txt", "docs/file.", "docs/file ",
  "docs/PROGRA~1/x", "ｄocs/fullwidth.txt", "docs/ok-ü.txt", "docs/a*b", "docs/a?b", "docs/<x>", "", "docs/\u0007bell", "summaries/", "a.b.c",
  "data/customers.csv", "data/public/readme.md", "data/restricted/payroll.xlsx",
];
const destinations = [
  undefined, "partner.example.com", "https://partner.example.com/in", "http://partner.example.com:8443/x?y=1#z", "https://evil.example.org",
  "https://a.files.example.com/up", "https://files.example.com", "ftp://partner.example.com", "https://user:pw@partner.example.com",
  "https://PARTNER.EXAMPLE.COM.", "https://127.0.0.1/x", "https://[::1]/", "https://0x7f.1", "https://xn--bcher-kva.example", "localhost",
  "https://partner.example.com\\@evil.org", "https://bücher.example", "https://a..b.com", "not a url", "https://partner.example.com:99999",
];
const classes = [undefined, "public", "internal", "confidential", "restricted"] as const;

const generated: PolicyDocument[] = [];
for (let i = 0; i < 40; i++) {
  const rules: any[] = [];
  const n = 1 + Math.floor(rnd() * 5);
  for (let j = 0; j < n; j++) {
    const effect = pick(["allow", "deny", "require_approval"] as const);
    const match: any = {};
    if (effect === "allow" || rnd() < 0.5) match.tools = rnd() < 0.2 ? ["*"] : [pick(tools)];
    if (effect === "allow" || rnd() < 0.6) match.operations = [pick(ops), ...(rnd() < 0.3 ? [pick(ops)] : [])].filter((v, k, a) => a.indexOf(v) === k);
    if (rnd() < 0.6) match.resources = [pick(["docs/**", "summaries/**", "docs/*", "data/**", "reports/*.pdf", "docs/secret/**", "**"])];
    if ((effect === "allow" && match.operations?.includes("external_transfer")) || rnd() < 0.2) match.destination_domains = [pick(["partner.example.com", "*.files.example.com", "files.example.com"])];
    if (rnd() < 0.25) match.data_classifications = [pick(["public", "internal", "confidential", "restricted"] as const)];
    if (!Object.keys(match).length) match.operations = [pick(ops)];
    const rule: any = { id: `r${j}`, effect, match };
    if (rnd() < 0.3) rule.description = "Rule description";
    if (effect === "require_approval" && rnd() < 0.5) rule.approval = { required_role: pick(["admin", "owner"]), ttl_seconds: 600 };
    rules.push(rule);
  }
  const doc: any = { schema_version: 1, rules };
  if (rnd() < 0.3) doc.classifications = [{ resources: ["data/restricted/**"], level: "restricted" }, { resources: ["data/public/**"], level: "public" }, { resources: ["docs/**"], level: "internal" }];
  if (rnd() < 0.3) doc.budget = { max_allowed_actions: 3, window_seconds: 60 };
  const parsed = policyDocumentSchema.safeParse(doc);
  if (parsed.success) generated.push(parsed.data);
}
const policies = [...POLICY_EXAMPLES.map((e) => e.document), ...generated];

const cases: unknown[] = [];
for (const policy of policies) {
  for (let k = 0; k < 120; k++) {
    const action: any = { tool: pick(tools), operation: pick(ops), resource: pick(resources) };
    const d = pick(destinations);
    if (d !== undefined) action.destination = d;
    const c = pick(classes);
    if (c !== undefined) action.data_classification = c;
    const ctx = { allowedInWindow: pick([0, 2, 3, 10]), hasValidApproval: rnd() < 0.2 };
    cases.push({ policy, action, ctx, expected: evaluate(policy, action, ctx) });
  }
}
const digests = [
  { tool: "documents", operation: "read", resource: "docs/a.txt" },
  { tool: "transfer", operation: "external_transfer", resource: "r", destination: "https://x.example.com", data_classification: "internal", args: { z: 1, a: [1, 2.5, "ü", null, true], n: { y: -0.000001, x: 1e21, w: 123456789.125, v: 1e-7 } } },
  { tool: "email", operation: "create", resource: "mail/1", args: { body: "line1\nline2\t\"quoted\" \\ \u0001 \u2028", nested: { b: { c: [] }, a: {} } } },
].map((a) => ({ action: a, digest: actionDigest(a as any) }));
process.stdout.write(JSON.stringify({ policies: policies.length, cases, digests }));
