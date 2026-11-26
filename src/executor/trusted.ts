/**
 * The trusted executor's tool set. Everything that can touch a protected resource lives here:
 *  - `documents`: read / create / update / delete inside ONE protected folder (ProtectedFs);
 *  - `transfer` : send a protected file to an approved destination (ProtectedEgress).
 * There is deliberately NO subprocess capability: this package never imports child_process, so a `command_execution`
 * request has nothing to run even if a policy were misconfigured to allow it.
 */
import { ExecutorRefusal, type ProtectedAction, type ToolDefinition } from "../sdk/index.js";
import { ProtectedEgress, EgressRefusal, type EgressOptions } from "./egress.js";
import { PathRefusal, ProtectedFs, type Mode } from "./fs-guard.js";

export interface TrustedOptions {
  root: string;
  maxReadBytes?: number;
  egress?: EgressOptions;
  caseInsensitive?: boolean;
  /** Default true. When false the executor refuses every external transfer (egress disabled on this machine). */
  egressEnabled?: boolean;
}

interface Binding {
  identity: string | null;
  mode: Mode;
  refusal?: { code: string; message: string };
}

const modeFor = (op: string): Mode => (op === "create" ? "create" : "existing");

function wrap<T>(fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof PathRefusal || e instanceof EgressRefusal) throw new ExecutorRefusal(e.code, e.message);
    throw e;
  }
}

export function createTrustedTools(opts: TrustedOptions) {
  const fs = new ProtectedFs(opts.root, { maxReadBytes: opts.maxReadBytes, caseInsensitive: opts.caseInsensitive });
  const egress = new ProtectedEgress(opts.egress);

  /** Canonicalize (real case, validated path) BEFORE authorization so policy and approvals bind to the real resource. */
  const prepareFs = (action: Readonly<ProtectedAction>): { action: ProtectedAction; binding: Binding } => {
    const mode = modeFor(action.operation);
    try {
      const r = fs.resolve(action.resource, mode);
      return { action: { ...action, resource: r.rel }, binding: { identity: r.identity, mode } };
    } catch (e) {
      if (e instanceof PathRefusal) return { action: { ...action }, binding: { identity: null, mode, refusal: { code: e.code, message: e.message } } };
      throw e;
    }
  };
  const assertBinding = (b: unknown): Binding => {
    const x = b as Binding | undefined;
    if (!x) throw new ExecutorRefusal("NO_BINDING", "Missing authorization binding");
    if (x.refusal) throw new ExecutorRefusal(x.refusal.code, x.refusal.message);
    return x;
  };

  const documents: ToolDefinition = {
    prepare: prepareFs,
    verify(action, ctx) {
      const b = assertBinding(ctx.binding);
      wrap(() => fs.verify(action.resource, b.mode, b.identity));
    },
    async execute(action, ctx) {
      const b = assertBinding(ctx.binding);
      return wrap(() => {
        switch (action.operation) {
          case "read": {
            const r = fs.read(action.resource, b.identity);
            return { bytes: r.bytes, content: r.text };
          }
          case "create":
            return fs.create(action.resource, String(action.args?.text ?? ""));
          case "update":
            return fs.update(action.resource, String(action.args?.text ?? ""), b.identity);
          case "delete":
            return fs.delete(action.resource, b.identity);
          default:
            throw new ExecutorRefusal("UNSUPPORTED_OPERATION", `documents does not support '${action.operation}'`);
        }
      });
    },
  };

  const transfer: ToolDefinition = {
    prepare(action) {
      const p = prepareFs({ ...action, operation: "read" }); // the source file must exist: resolve it as an existing file
      return { action: { ...action, resource: p.action.resource }, binding: p.binding };
    },
    async verify(action, ctx) {
      if (action.operation !== "external_transfer") throw new ExecutorRefusal("UNSUPPORTED_OPERATION", "transfer only supports external_transfer");
      if (opts.egressEnabled === false) throw new ExecutorRefusal("EGRESS_DISABLED", "External transfers are disabled on this executor");
      const b = assertBinding(ctx.binding);
      wrap(() => fs.verify(action.resource, "existing", b.identity));
      if (!action.destination || !ctx.destinationHost) throw new ExecutorRefusal("DESTINATION_INVALID", "No authorized destination");
      try {
        await egress.plan(action.destination, ctx.destinationHost);
      } catch (e) {
        if (e instanceof EgressRefusal) throw new ExecutorRefusal(e.code, e.message);
        throw e;
      }
    },
    async execute(action, ctx) {
      if (action.operation !== "external_transfer") throw new ExecutorRefusal("UNSUPPORTED_OPERATION", "transfer only supports external_transfer");
      if (opts.egressEnabled === false) throw new ExecutorRefusal("EGRESS_DISABLED", "External transfers are disabled on this executor");
      const b = assertBinding(ctx.binding);
      if (!action.destination || !ctx.destinationHost) throw new ExecutorRefusal("DESTINATION_INVALID", "No authorized destination");
      const file = wrap(() => fs.read(action.resource, b.identity));
      let r;
      try {
        r = await egress.send({ destination: action.destination, approvedHost: ctx.destinationHost, body: Buffer.from(file.text, "utf8"), contentType: "text/plain" });
      } catch (e) {
        if (e instanceof EgressRefusal) throw new ExecutorRefusal(e.code, e.message);
        throw e;
      }
      if (r.status < 200 || r.status >= 300) throw new Error(`destination answered HTTP ${r.status}`);
      return { sent_to: r.host, bytes: r.bytes, status: r.status };
    },
  };

  return { tools: { documents, transfer } as Record<string, ToolDefinition>, fs, egress };
}
