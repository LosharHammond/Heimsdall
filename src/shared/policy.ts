import { z } from "zod";

export const OPERATIONS = ["read", "create", "update", "delete", "external_transfer", "command_execution"] as const;
export type Operation = (typeof OPERATIONS)[number];
export const CLASSIFICATIONS = ["public", "internal", "confidential", "restricted"] as const;
export type Classification = (typeof CLASSIFICATIONS)[number];
export const EFFECTS = ["allow", "deny", "require_approval"] as const;
export type Effect = (typeof EFFECTS)[number];

const toolPattern = z.string().regex(/^(\*|[a-z0-9][a-z0-9_.-]{0,63})$/, "tool must be '*' or a lowercase name like 'documents'");
const resourcePattern = z
  .string()
  .min(1)
  .max(200)
  .refine((p) => !p.startsWith("/") && !p.split("/").some((s) => s === ".." || s === "."), "resource patterns must be relative namespaces without '.' or '..' segments");
const PRIVATE_HOST = /^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.lan)$/i;
const domainPattern = z
  .string()
  .min(3)
  .max(253)
  .transform((s) => s.toLowerCase())
  .refine((s) => /^(\*\.)?([a-z0-9-]+\.)+[a-z]{2,}$/.test(s), "use a domain like 'example.com' or '*.example.com'")
  .refine((s) => !PRIVATE_HOST.test(s.replace(/^\*\./, "")), "private or infrastructure hostnames cannot be approved destinations");

export const ruleSchema = z
  .object({
    id: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/i, "rule id: letters, digits, '-' or '_'"),
    description: z.string().max(300).optional(),
    effect: z.enum(EFFECTS),
    match: z
      .object({
        tools: z.array(toolPattern).min(1).max(50).optional(),
        operations: z.array(z.enum(OPERATIONS)).min(1).max(6).optional(),
        resources: z.array(resourcePattern).min(1).max(50).optional(),
        destination_domains: z.array(domainPattern).min(1).max(50).optional(),
        data_classifications: z.array(z.enum(CLASSIFICATIONS)).min(1).max(4).optional(),
      })
      .strict(),
    approval: z
      .object({
        required_role: z.enum(["admin", "owner"]).default("admin"),
        ttl_seconds: z.number().int().min(60).max(86400).default(900),
      })
      .strict()
      .optional(),
  })
  .strict()
  .superRefine((rule, ctx) => {
    if (rule.approval && rule.effect !== "require_approval") {
      ctx.addIssue({ code: "custom", message: "'approval' settings are only valid on require_approval rules", path: ["approval"] });
    }
    if (rule.effect === "allow") {
      if (!rule.match.tools || !rule.match.operations) {
        ctx.addIssue({ code: "custom", message: "allow rules must list 'tools' and 'operations' explicitly", path: ["match"] });
      }
      if (rule.match.operations?.includes("external_transfer") && !rule.match.destination_domains) {
        ctx.addIssue({ code: "custom", message: "allowing external_transfer requires 'destination_domains'", path: ["match", "destination_domains"] });
      }
    }
  });

/** Trusted classification: established by the policy owner, never by the agent. */
export const classificationRuleSchema = z.object({ resources: z.array(resourcePattern).min(1).max(50), level: z.enum(CLASSIFICATIONS) }).strict();

export const policyDocumentSchema = z
  .object({
    schema_version: z.literal(1),
    description: z.string().max(500).optional(),
    classifications: z.array(classificationRuleSchema).max(100).optional(),
    budget: z
      .object({
        max_allowed_actions: z.number().int().min(1).max(1_000_000),
        window_seconds: z.number().int().min(10).max(7 * 86400),
      })
      .strict()
      .optional(),
    rules: z.array(ruleSchema).max(200),
  })
  .strict()
  .superRefine((doc, ctx) => {
    const seen = new Set<string>();
    doc.rules.forEach((r, i) => {
      if (seen.has(r.id.toLowerCase())) ctx.addIssue({ code: "custom", message: `duplicate rule id '${r.id}'`, path: ["rules", i, "id"] });
      seen.add(r.id.toLowerCase());
    });
  });

export type PolicyDocument = z.infer<typeof policyDocumentSchema>;
export type PolicyRule = z.infer<typeof ruleSchema>;

export type ReasonCode =
  | "EXPLICIT_DENY"
  | "APPROVAL_REQUIRED"
  | "APPROVAL_GRANTED"
  | "ALLOWED_BY_RULE"
  | "NO_MATCHING_RULE"
  | "DESTINATION_NOT_APPROVED"
  | "INVALID_RESOURCE"
  | "INVALID_DESTINATION"
  | "BUDGET_EXCEEDED"
  | "NO_POLICY_ASSIGNED"
  | "AGENT_REVOKED"
  | "CREDENTIAL_REVOKED"
  | "CREDENTIAL_INVALID"
  | "MONITOR_ONLY";

export interface Decision {
  decision: Effect;
  reason_code: ReasonCode;
  explanation: string;
  matched_rule_id: string | null;
  /** How the data classification was established. Agent-declared values are untrusted. */
  classification?: { level: Classification | "unclassified"; source: "policy" | "policy_raised_by_agent" | "declared" | "none" };
  approval?: { required_role: "admin" | "owner"; ttl_seconds: number };
}

export interface EvaluableAction {
  tool: string;
  operation: Operation;
  resource: string;
  destination?: string | null;
  data_classification?: Classification | null;
}

export interface EvalContext {
  /** Allowed actions already counted inside the policy's budget window (excluding this request). */
  allowedInWindow: number;
  /** True only when a valid, unconsumed, in-date, action-bound approval exists. Determined by the caller. */
  hasValidApproval: boolean;
}

// ---------- normalization ----------

const WIN_RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)/i;

export function normalizeResource(raw: string): { ok: true; value: string } | { ok: false } {
  if (/[\u0000-\u001f]/.test(raw) || /%2e|%2f|%5c|%00|%25/i.test(raw)) return { ok: false };
  // Alternate Unicode encodings (fullwidth dots/slashes, ligatures...) must equal their normalized form.
  if (raw.normalize("NFKC") !== raw) return { ok: false };
  if (/[<>"|?*]/.test(raw)) return { ok: false };
  let v = raw.replace(/\\/g, "/").replace(/\/{2,}/g, "/");
  while (v.startsWith("./")) v = v.slice(2);
  if (!v || v.startsWith("/")) return { ok: false };
  for (const seg of v.split("/")) {
    if (seg === ".." || seg === ".") return { ok: false };
    // Windows quirks: alternate data streams / drive letters (':'), a trailing dot or space (silently stripped by the OS),
    // reserved device names, and 8.3 short names that alias a different path.
    if (seg.includes(":") || /[. ]$/.test(seg) || WIN_RESERVED.test(seg) || /~[0-9]/.test(seg) || seg.length > 255) return { ok: false };
  }
  return { ok: true, value: v };
}

export type NormalizedDestination = { ok: true; host: string; isIp: boolean } | { ok: false };

/** Executors MUST connect only to the host returned here; never re-parse the raw string with a different parser. */
export function normalizeDestination(raw: string): NormalizedDestination {
  const s = raw.trim();
  if (!s || /[\u0000-\u001f\s]/.test(s)) return { ok: false };
  let url: URL;
  try {
    url = new URL(s.includes("://") ? s : `https://${s}`);
  } catch {
    return { ok: false };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return { ok: false };
  if (url.username || url.password) return { ok: false };
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!host) return { ok: false };
  const isIp = host.startsWith("[") || /^[0-9.]+$/.test(host);
  return { ok: true, host, isIp };
}

// Compiled patterns are cached: a policy has a few hundred patterns at most, and recompiling them on every decision
// was the single largest cost of an evaluation. Bounded so a hostile stream of distinct patterns cannot grow it forever.
const GLOB_CACHE = new Map<string, RegExp>();
const GLOB_CACHE_MAX = 4096;

function globToRegex(glob: string): RegExp {
  const hit = GLOB_CACHE.get(glob);
  if (hit) return hit;
  const compiled = compileGlob(glob);
  if (GLOB_CACHE.size >= GLOB_CACHE_MAX) GLOB_CACHE.delete(GLOB_CACHE.keys().next().value as string);
  GLOB_CACHE.set(glob, compiled);
  return compiled;
}

function compileGlob(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        re += ".*";
        i++;
      } else re += "[^/]*";
    } else re += c.replace(/[.+^${}()|[\]\\?]/g, "\\$&");
  }
  // Files: Windows and macOS ignore letter case, so ".SSH" must match a ".ssh" rule.
  return new RegExp(`^${re}$`, glob.startsWith("files/") ? "i" : "");
}

export function resourceMatches(pattern: string, resource: string): boolean {
  return globToRegex(pattern).test(resource);
}

export function domainMatches(pattern: string, host: string): boolean {
  if (pattern.startsWith("*.")) return host.endsWith(pattern.slice(1)) && host.length > pattern.length - 1;
  return host === pattern;
}

// ---------- evaluation ----------

interface Prepared {
  a: EvaluableAction;
  cls: Classification | "unclassified";
  resource: string;
  host: string | null;
  hostIsIp: boolean;
}

const LEVEL_RANK: Record<Classification, number> = { public: 0, internal: 1, confidential: 2, restricted: 3 };

/**
 * Classification comes from trusted policy metadata when the policy defines `classifications`; the agent's own claim is then
 * never lowers it (an agent must never be able to relabel data as public); a HIGHER claim is honoured because it only tightens. Resources the policy does not classify are "unclassified",
 * which is handled conservatively: deny and approval rules that name a class still match them, allow rules that require a class do not.
 * Policies without a `classifications` map fall back to the declared value, which is untrusted and flagged as such.
 */
export function effectiveClassification(policy: PolicyDocument, resource: string, declared?: Classification | null): NonNullable<Decision["classification"]> {
  if (policy.classifications && policy.classifications.length > 0) {
    let best: Classification | null = null;
    for (const c of policy.classifications) {
      if (c.resources.some((r) => resourceMatches(r, resource)) && (best === null || LEVEL_RANK[c.level] > LEVEL_RANK[best])) best = c.level;
    }
    if (!best) return { level: "unclassified", source: "policy" };
    // An agent may only make its own data MORE sensitive (which can only tighten rules); it can never lower the trusted level.
    if (declared && LEVEL_RANK[declared] > LEVEL_RANK[best]) return { level: declared, source: "policy_raised_by_agent" };
    return { level: best, source: "policy" };
  }
  return declared ? { level: declared, source: "declared" } : { level: "unclassified", source: "none" };
}

function ruleMatches(rule: PolicyRule, p: Prepared): boolean {
  const m = rule.match;
  if (m.tools && !m.tools.some((t) => t === "*" || t === p.a.tool)) return false;
  if (m.operations && !m.operations.includes(p.a.operation)) return false;
  if (m.resources && !m.resources.some((r) => resourceMatches(r, p.resource))) return false;
  if (m.destination_domains) {
    if (!p.host || p.hostIsIp) return false;
    if (!m.destination_domains.some((d) => domainMatches(d, p.host!))) return false;
  }
  if (m.data_classifications) {
    const c = p.cls;
    if (c === "unclassified") {
      // Fail closed: an unknown classification must not let a caller slip past a deny/approval rule.
      if (rule.effect === "allow") return false;
    } else if (!m.data_classifications.includes(c)) return false;
  }
  return true;
}

/**
 * Deterministic policy evaluation. Precedence:
 * 2. explicit deny, 3. approval rules, 4. explicit allow, 5. default deny.
 * (1. identity/revocation is enforced by the caller before evaluation.)
 * Budget is the one cross-cutting exception: it can turn an allow (or approved action) into a deny.
 */
export function evaluate(policy: PolicyDocument, action: EvaluableAction, ctx: EvalContext): Decision {
  const norm = normalizeResource(action.resource);
  const cls = effectiveClassification(policy, norm.ok ? norm.value : action.resource, action.data_classification);
  return { ...evaluateInner(policy, action, ctx, cls), classification: cls };
}

function evaluateInner(policy: PolicyDocument, action: EvaluableAction, ctx: EvalContext, cls: NonNullable<Decision["classification"]>): Decision {
  const res = normalizeResource(action.resource);
  if (!res.ok) {
    return deny("INVALID_RESOURCE", "The resource path is not a valid namespace path (absolute paths, '..' and encoded separators are refused).");
  }
  let host: string | null = null;
  let hostIsIp = false;
  if (action.destination) {
    const d = normalizeDestination(action.destination);
    if (!d.ok) return deny("INVALID_DESTINATION", "The destination is not a valid http(s) host (credentials in URLs and other schemes are refused).");
    host = d.host;
    hostIsIp = d.isIp;
  } else if (action.operation === "external_transfer") {
    return deny("INVALID_DESTINATION", "External transfers must declare a destination.");
  }
  const p: Prepared = { a: action, cls: cls.level, resource: res.value, host, hostIsIp };

  const denyRule = policy.rules.find((r) => r.effect === "deny" && ruleMatches(r, p));
  if (denyRule) {
    return {
      decision: "deny",
      reason_code: "EXPLICIT_DENY",
      explanation: `Denied by rule '${denyRule.id}'${denyRule.description ? `: ${denyRule.description}` : "."}`,
      matched_rule_id: denyRule.id,
    };
  }

  const budgetExceeded = policy.budget && ctx.allowedInWindow >= policy.budget.max_allowed_actions;
  const budgetDeny = () =>
    deny("BUDGET_EXCEEDED", `The action budget (${policy.budget!.max_allowed_actions} allowed actions per ${policy.budget!.window_seconds}s) is used up.`);

  const approvalRule = policy.rules.find((r) => r.effect === "require_approval" && ruleMatches(r, p));
  if (approvalRule) {
    if (ctx.hasValidApproval) {
      if (budgetExceeded) return budgetDeny();
      return {
        decision: "allow",
        reason_code: "APPROVAL_GRANTED",
        explanation: `Rule '${approvalRule.id}' requires approval and a valid one-time approval for exactly this action was presented.`,
        matched_rule_id: approvalRule.id,
      };
    }
    return {
      decision: "require_approval",
      reason_code: "APPROVAL_REQUIRED",
      explanation: `Rule '${approvalRule.id}' requires a human ${approvalRule.approval?.required_role ?? "admin"} to approve this exact action.`,
      matched_rule_id: approvalRule.id,
      approval: { required_role: approvalRule.approval?.required_role ?? "admin", ttl_seconds: approvalRule.approval?.ttl_seconds ?? 900 },
    };
  }

  const allowRule = policy.rules.find((r) => r.effect === "allow" && ruleMatches(r, p));
  if (allowRule) {
    if (budgetExceeded) return budgetDeny();
    return {
      decision: "allow",
      reason_code: "ALLOWED_BY_RULE",
      explanation: `Allowed by rule '${allowRule.id}'${allowRule.description ? `: ${allowRule.description}` : "."}`,
      matched_rule_id: allowRule.id,
    };
  }

  // Default deny. If a rule matched everything except the destination, say so: it is the common surprise.
  if (host) {
    const near = policy.rules.find(
      (r) => r.effect !== "deny" && r.match.destination_domains && ruleMatches({ ...r, match: { ...r.match, destination_domains: undefined } }, p),
    );
    if (near) {
      return {
        decision: "deny",
        reason_code: "DESTINATION_NOT_APPROVED",
        explanation: `The destination '${host}' is not on the approved destination list of rule '${near.id}'.`,
        matched_rule_id: near.id,
      };
    }
  }
  return deny("NO_MATCHING_RULE", "No rule permits this action; the default is to deny.");
}

function deny(reason_code: ReasonCode, explanation: string): Decision {
  return { decision: "deny", reason_code, explanation, matched_rule_id: null };
}

// ---------- example policies ----------

export interface PolicyExample {
  key: string;
  title: string;
  summary: string;
  document: PolicyDocument;
}

export const POLICY_EXAMPLES: PolicyExample[] = [
  {
    key: "read-only-assistant",
    title: "Read-only document assistant",
    summary: "May read approved documents. Everything else is denied by default.",
    document: {
      schema_version: 1,
      description: "Read-only access to the docs/ namespace.",
      rules: [
        { id: "read-docs", effect: "allow", description: "Read approved documents", match: { tools: ["documents"], operations: ["read"], resources: ["docs/**"] } },
      ],
    },
  },
  {
    key: "summarizer",
    title: "Summarizer that cannot delete sources",
    summary: "Reads docs/, writes only to summaries/, and can never delete anything.",
    document: {
      schema_version: 1,
      description: "Create summaries; never delete source files.",
      rules: [
        { id: "never-delete", effect: "deny", description: "Deletion is never permitted", match: { operations: ["delete"] } },
        { id: "read-docs", effect: "allow", match: { tools: ["documents"], operations: ["read"], resources: ["docs/**"] } },
        { id: "write-summaries", effect: "allow", match: { tools: ["documents"], operations: ["create"], resources: ["summaries/**"] } },
      ],
    },
  },
  {
    key: "approved-destinations",
    title: "External transfer to approved destinations only",
    summary: "Data may be sent only to the listed domains; restricted data is never sent.",
    document: {
      schema_version: 1,
      description: "Outbound transfer allow-list.",
      rules: [
        { id: "no-restricted-data", effect: "deny", description: "Restricted data never leaves", match: { operations: ["external_transfer"], data_classifications: ["restricted"] } },
        {
          id: "send-to-partner",
          effect: "allow",
          match: { tools: ["transfer"], operations: ["external_transfer"], destination_domains: ["partner.example.com", "*.files.example.com"] },
        },
      ],
    },
  },
  {
    key: "destructive-needs-approval",
    title: "Destructive operations need administrator approval",
    summary: "Reads and updates are allowed; deleting requires a human administrator to approve that exact action.",
    document: {
      schema_version: 1,
      description: "Deletes wait for human approval.",
      rules: [
        { id: "delete-needs-admin", effect: "require_approval", match: { tools: ["*"], operations: ["delete"] }, approval: { required_role: "admin", ttl_seconds: 900 } },
        { id: "read-docs", effect: "allow", match: { tools: ["documents"], operations: ["read"], resources: ["docs/**"] } },
        { id: "update-docs", effect: "allow", match: { tools: ["documents"], operations: ["update"], resources: ["docs/**"] } },
      ],
    },
  },
  {
    key: "no-commands",
    title: "Arbitrary command execution denied",
    summary: "Explicitly denies command execution regardless of any other rule, with a small action budget.",
    document: {
      schema_version: 1,
      description: "No command execution, ever.",
      budget: { max_allowed_actions: 200, window_seconds: 3600 },
      rules: [
        { id: "no-commands", effect: "deny", description: "Command execution is never permitted", match: { operations: ["command_execution"] } },
        { id: "read-docs", effect: "allow", match: { tools: ["documents"], operations: ["read"], resources: ["docs/**"] } },
      ],
    },
  },
  {
    key: "demo-workspace",
    title: "Demo workspace (used by the runnable demo)",
    summary: "Reads docs/, creates summaries/, deletes need approval, one approved destination, commands denied.",
    document: {
      schema_version: 1,
      description: "Policy used by `npm run demo`.",
      classifications: [
        { resources: ["docs/**", "summaries/**"], level: "internal" },
        { resources: ["reports/**"], level: "confidential" },
        { resources: ["docs/finance/**"], level: "restricted" },
      ],
      rules: [
        { id: "no-commands", effect: "deny", match: { operations: ["command_execution"] } },
        { id: "no-restricted-transfer", effect: "deny", match: { operations: ["external_transfer"], data_classifications: ["restricted"] } },
        { id: "delete-needs-admin", effect: "require_approval", match: { tools: ["documents"], operations: ["delete"], resources: ["docs/**"] }, approval: { required_role: "admin", ttl_seconds: 900 } },
        { id: "read-docs", effect: "allow", match: { tools: ["documents"], operations: ["read"], resources: ["docs/**"] } },
        { id: "write-summaries", effect: "allow", match: { tools: ["documents"], operations: ["create"], resources: ["summaries/**"] } },
        { id: "send-to-partner", effect: "allow", match: { tools: ["transfer"], operations: ["external_transfer"], destination_domains: ["partner.example.com"] } },
      ],
    },
  },
];
