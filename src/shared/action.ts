import { createHash } from "node:crypto";
import { z } from "zod";
import { CLASSIFICATIONS, OPERATIONS } from "./policy.js";

export const MAX_ARGS_BYTES = 16 * 1024;

function depthOk(v: unknown, depth = 0): boolean {
  if (depth > 6) return false;
  if (Array.isArray(v)) return v.length <= 200 && v.every((x) => depthOk(x, depth + 1));
  if (v && typeof v === "object") {
    const e = Object.entries(v as Record<string, unknown>);
    return e.length <= 100 && e.every(([, x]) => depthOk(x, depth + 1));
  }
  return true;
}

export const actionRequestSchema = z
  .object({
    request_id: z.string().regex(/^[A-Za-z0-9_.:-]{8,128}$/, "request_id must be 8-128 characters of letters, digits, '_', '.', ':' or '-'"),
    tool: z.string().regex(/^[a-z0-9][a-z0-9_.-]{0,63}$/, "tool must be a lowercase name such as 'documents'"),
    operation: z.enum(OPERATIONS),
    resource: z.string().min(1).max(512),
    destination: z.string().min(1).max(2048).optional(),
    data_classification: z.enum(CLASSIFICATIONS).optional(),
    args: z
      .record(z.string().max(100), z.unknown())
      .refine((a) => depthOk(a), "args are too deeply nested or too large")
      .refine((a) => JSON.stringify(a).length <= MAX_ARGS_BYTES, `args must be at most ${MAX_ARGS_BYTES} bytes as JSON`)
      .optional(),
    requested_at: z.string().datetime().optional(),
    demo: z.boolean().optional(),
    adapter: z.object({ name: z.string().max(64), version: z.string().max(32) }).strict().optional(),
  })
  .strict();

export type ActionRequestInput = z.infer<typeof actionRequestSchema>;

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    if (value === undefined) return "null";
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const o = value as Record<string, unknown>;
  const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(",")}}`;
}

/**
 * The action binding. Covers everything that defines what will be executed.
 * It deliberately excludes request_id and timestamps (those identify the request, not the action).
 * Org and agent binding are enforced server-side on the approval row, not inside the digest.
 */
export function actionDigest(a: Pick<ActionRequestInput, "tool" | "operation" | "resource" | "destination" | "data_classification" | "args">): string {
  return createHash("sha256")
    .update(
      canonicalJson({
        tool: a.tool,
        operation: a.operation,
        resource: a.resource,
        destination: a.destination ?? null,
        data_classification: a.data_classification ?? null,
        args: a.args ?? {},
      }),
    )
    .digest("hex");
}
