/**
 * Exports for auditors and SIEM tools. docs/ALERTS.md#exports.
 *  - audit:    who changed what (sign-ins, policies, keys, members, approvals...).
 *  - activity: every agent action with its decision and outcome.
 * CSV is for spreadsheets. JSON Lines ends with a manifest line: row count, period, the SHA-256 of every line before it and an
 * Ed25519 signature by the service's signing key, so anyone can check later that the file is complete and unchanged
 * (scripts/verify-export.ts). Each export is itself recorded in the audit log.
 */
import { createHash } from "node:crypto";
import { z } from "zod";
import { HttpError } from "../errors.js";
import { canonicalJson } from "../../shared/action.js";
import { requirePermission } from "./admin.js";
import { audit, type Ctx } from "./core.js";

export const exportQuery = z
  .object({
    kind: z.enum(["audit", "activity"]),
    format: z.enum(["csv", "jsonl"]).default("csv"),
    from: z.iso.datetime({ offset: true }).optional(),
    to: z.iso.datetime({ offset: true }).optional(),
  })
  .strict();
const MAX_ROWS = 100_000;

export async function exportData(ctx: Ctx, userId: string, orgId: string, q: z.infer<typeof exportQuery>) {
  await requirePermission(ctx.db, userId, orgId, "audit.read");
  const to = q.to ? new Date(q.to) : new Date();
  const from = q.from ? new Date(q.from) : new Date(to.getTime() - 30 * 86400_000);
  if (from > to) throw new HttpError(400, "BAD_RANGE", "The start must be before the end.");
  const rows =
    q.kind === "audit"
      ? await ctx.db.query<any>(
          `SELECT e.created_at AS time, e.actor_type, e.actor_id, u.email AS actor_email, e.action, e.target_type, e.target_id, e.metadata, e.id
             FROM audit_entries e LEFT JOIN users u ON e.actor_type = 'user' AND u.id::text = e.actor_id
            WHERE e.org_id = $1 AND e.created_at >= $2 AND e.created_at < $3 ORDER BY e.created_at, e.id LIMIT ${MAX_ROWS + 1}`,
          [orgId, from, to],
        )
      : await ctx.db.query<any>(
          `SELECT a.created_at AS time, ag.name AS agent, a.request_id, a.tool, a.operation, a.resource, a.destination, a.data_classification,
                  a.source, d.decision, d.policy_decision, d.reason_code, d.matched_rule_id, d.policy_version, d.enforcement_mode,
                  o.status AS outcome, o.enforcement_confirmed, o.error_code, a.action_digest, a.is_demo
             FROM action_requests a JOIN agents ag ON ag.id = a.agent_id
             LEFT JOIN authorization_decisions d ON d.action_request_id = a.id
             LEFT JOIN execution_outcomes o ON o.action_request_id = a.id
            WHERE a.org_id = $1 AND a.created_at >= $2 AND a.created_at < $3 ORDER BY a.created_at, a.id LIMIT ${MAX_ROWS + 1}`,
          [orgId, from, to],
        );
  if (rows.length > MAX_ROWS) throw new HttpError(413, "EXPORT_TOO_LARGE", `More than ${MAX_ROWS.toLocaleString("en-US")} rows in that period. Choose a shorter period.`);
  const norm = rows.map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, v instanceof Date ? v.toISOString() : v])));
  const stamp = `${from.toISOString().slice(0, 10)}_${to.toISOString().slice(0, 10)}`;
  await audit(ctx.db, { orgId, actorType: "user", actorId: userId, action: "export.downloaded", metadata: { kind: q.kind, format: q.format, rows: rows.length, from: from.toISOString(), to: to.toISOString() } });

  if (q.format === "csv") {
    const cols = norm.length ? Object.keys(norm[0]) : q.kind === "audit" ? ["time", "actor_type", "actor_id", "actor_email", "action", "target_type", "target_id", "metadata", "id"] : ["time", "agent", "request_id", "tool", "operation", "resource", "decision", "reason_code", "outcome"];
    const body = "﻿" + [cols.join(","), ...norm.map((r) => cols.map((c) => csvCell(r[c])).join(","))].join("\r\n") + "\r\n";
    return { filename: `heimdall-${q.kind}-${stamp}.csv`, contentType: "text/csv; charset=utf-8", body };
  }
  const lines = norm.map((r) => canonicalJson(r));
  const sha256 = createHash("sha256").update(lines.map((l) => `${l}\n`).join("")).digest("hex");
  const manifest: Record<string, unknown> = {
    _manifest: true, kind: q.kind, org_id: orgId, from: from.toISOString(), to: to.toISOString(), rows: lines.length, sha256,
    exported_at: new Date().toISOString(), exported_by: userId,
  };
  if (ctx.signer) {
    manifest.key_id = ctx.signer.keyId;
    manifest.signature = ctx.signer.sign(canonicalJson(manifest));
  }
  return { filename: `heimdall-${q.kind}-${stamp}.jsonl`, contentType: "application/x-ndjson; charset=utf-8", body: [...lines, canonicalJson(manifest)].map((l) => `${l}\n`).join("") };
}

/** Spreadsheet-safe: quotes, and a leading ' on values that a spreadsheet would run as a formula. */
function csvCell(v: unknown): string {
  if (v === null || v === undefined) return "";
  let s = typeof v === "object" ? JSON.stringify(v) : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) || s !== s.trim() ? `"${s.replace(/"/g, '""')}"` : s;
}
