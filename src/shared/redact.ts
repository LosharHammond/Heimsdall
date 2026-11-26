/**
 * Redaction applied BEFORE anything is persisted or logged.
 * Default posture: record action metadata, not content. Content-like fields are replaced by their length.
 */
const SENSITIVE_KEY = /(passw(or)?d|passphrase|^pass$|secret|token|api[-_]?key|authorization|^auth$|cookie|credential|private[-_]?key|ssn|(^|[_-])card([_-]|$)|card_?number|cvv|(^|_)signature$|session)/i;
const CONTENT_KEY = /^(content|contents|body|text|prompt|completion|message|messages|document|data|payload|html|summary_text)$/i;
const VALUE_PATTERNS: Array<[RegExp, string]> = [
  [/asg_[A-Za-z0-9]{6,}_[A-Za-z0-9_-]{16,}/g, "[REDACTED:integration-key]"],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer [REDACTED]"],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "[REDACTED:jwt]"],
  [/\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, "[REDACTED:aws-key]"],
  [/\b(sk|pk|rk)[-_](live|test)?[-_]?[A-Za-z0-9]{16,}\b/g, "[REDACTED:api-key]"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[REDACTED:private-key]"],
  [/\b(?:\d[ -]?){13,19}\b/g, "[REDACTED:number]"],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[REDACTED:email]"],
  [/\b[A-Za-z0-9+/_-]{40,}={0,2}\b/g, "[REDACTED:long-token]"],
];

const MAX_STRING = 200;

export function redactString(s: string): string {
  let out = s;
  for (const [re, rep] of VALUE_PATTERNS) out = out.replace(re, rep);
  if (out.length > MAX_STRING) out = `${out.slice(0, MAX_STRING)}…[truncated ${out.length - MAX_STRING} chars]`;
  return out;
}

export function redact(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value ?? null;
  if (typeof value === "string") return redactString(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (depth > 5) return "[truncated: too deep]";
  if (Array.isArray(value)) {
    const items = value.slice(0, 20).map((v) => redact(v, depth + 1));
    if (value.length > 20) items.push(`[${value.length - 20} more items omitted]`);
    return items;
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    const entries = Object.entries(value as Record<string, unknown>);
    for (const [k, v] of entries.slice(0, 40)) {
      if (SENSITIVE_KEY.test(k)) out[k] = "[REDACTED]";
      else if (CONTENT_KEY.test(k)) out[k] = typeof v === "string" ? `[OMITTED ${v.length} chars]` : "[OMITTED]";
      else out[k] = redact(v, depth + 1);
    }
    if (entries.length > 40) out["…"] = `${entries.length - 40} more keys omitted`;
    return out;
  }
  return "[unsupported]";
}

export function redactedJsonString(value: unknown, maxBytes = 2048): string {
  const s = JSON.stringify(redact(value));
  return s.length > maxBytes ? JSON.stringify({ truncated: true, preview: s.slice(0, maxBytes - 40) }) : s;
}
