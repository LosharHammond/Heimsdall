/* Heimdall browser guard: finds secrets and personal data in text, on this computer. Nothing here leaves the browser:
 * only the kinds found ("API key", "card number") are sent to Heimdall for a decision. */
(function (root) {
  "use strict";
  const R = (label, level, re, check) => ({ label, level, re, check });
  const luhn = (s) => {
    const d = s.replace(/\D/g, "");
    if (d.length < 13 || d.length > 19 || /^(\d)\1+$/.test(d)) return false;
    let sum = 0;
    for (let i = 0; i < d.length; i++) {
      let n = +d[d.length - 1 - i];
      if (i % 2) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
    }
    return sum % 10 === 0 && /^[3-6]/.test(d);
  };
  const RULES = [
    R("private key", "restricted", /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g),
    R("Anthropic API key", "restricted", /\bsk-ant-[A-Za-z0-9_-]{20,}/g),
    R("OpenAI API key", "restricted", /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g),
    R("AWS access key", "restricted", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g),
    R("GitHub token", "restricted", /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g),
    R("Google API key", "restricted", /\bAIza[0-9A-Za-z_-]{35}\b/g),
    R("Slack token", "restricted", /\bxox[abprs]-[A-Za-z0-9-]{10,}/g),
    R("Stripe secret key", "restricted", /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g),
    R("access token (JWT)", "restricted", /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g),
    R("password in a connection string", "restricted", /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@]{1,64}:[^\s@/]{3,128}@[^\s"'<>]+/gi),
    R("password or secret", "restricted", /\b(?:password|passwd|pwd|pass|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*["']?[^\s"',;]{6,}/gi),
    R("payment card number", "restricted", /\b(?:\d[ -]?){12,18}\d\b/g, luhn),
    R("bank account number (IBAN)", "confidential", /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b/g),
    R("document marked confidential", "confidential", /\b(?:CONFIDENTIAL|PROPRIETARY)\b/g),
    R("document marked confidential", "confidential", /\b(?:strictly confidential|internal use only|for internal use|do not distribute|not for distribution|attorney[- ]client privileged)\b/gi),
  ];
  const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  const PHONE = /(?:\+|\b)\d[\d ()-]{7,}\d\b/g;
  const RANK = { public: 0, internal: 1, confidential: 2, restricted: 3 };

  function scan(text) {
    const findings = [];
    const spans = [];
    if (!text || typeof text !== "string") return { level: "internal", findings, spans };
    const sample = text.length > 200000 ? text.slice(0, 200000) : text;
    for (const r of RULES) {
      r.re.lastIndex = 0;
      let m, n = 0;
      while ((m = r.re.exec(sample)) && n < 50) {
        if (r.check && !r.check(m[0])) continue;
        if (spans.some((s) => m.index < s.end && m.index + m[0].length > s.start)) continue;   // already covered by a stronger rule
        spans.push({ start: m.index, end: m.index + m[0].length, label: r.label, level: r.level });
        n++;
      }
      if (n) findings.push({ label: r.label, level: r.level, count: n });
    }
    const emails = new Set(sample.match(EMAIL) || []);
    const phones = new Set((sample.match(PHONE) || []).map((p) => p.replace(/\D/g, "")).filter((p) => p.length >= 9 && p.length <= 15));
    if (emails.size >= 5) findings.push({ label: `list of ${emails.size} email addresses`, level: "confidential", count: emails.size });
    if (phones.size >= 5) findings.push({ label: `list of ${phones.size} phone numbers`, level: "confidential", count: phones.size });
    let level = "internal";
    for (const f of findings) if (RANK[f.level] > RANK[level]) level = f.level;
    spans.sort((a, b) => a.start - b.start);
    return { level, findings, spans };
  }

  /** The same text with every secret replaced by a short marker. Lists of contacts are left alone (they are not single values). */
  function redact(text, spans) {
    let out = "", at = 0;
    for (const s of spans || scan(text).spans) {
      if (s.level !== "restricted") continue;
      out += text.slice(at, s.start) + `[removed by Heimdall: ${s.label}]`;
      at = s.end;
    }
    return out + text.slice(at);
  }

  /** File names that are almost always secrets. */
  function scanFileName(name) {
    const n = String(name || "").toLowerCase();
    if (/(^|[\\/])\.env(\.|$)|id_(rsa|ed25519|ecdsa|dsa)(\.|$)|\.(pem|key|pfx|p12|kdbx|ppk|keystore|jks)$|credentials\.json$|service-account.*\.json$|\.npmrc$|\.pypirc$|wallet\.dat$/.test(n))
      return { label: `secret file (${name})`, level: "restricted", count: 1 };
    return null;
  }

  const api = { scan, redact, scanFileName, luhn };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.HeimdallDetect = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
