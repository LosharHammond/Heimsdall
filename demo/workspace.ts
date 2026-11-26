/**
 * Disposable demo fixtures + the controlled tool executor.
 *
 * The "agent" in the demo never receives `fs`, a path, or any other route to these resources. It can only ask the
 * ProtectedExecutor to run a named tool; the handlers below hold the only access to the fixture directory.
 * Nothing here touches the network and nothing here executes shell commands.
 */
import { lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import type { ToolHandler } from "../src/sdk/index.js";

export interface Workspace {
  root: string;
  handlers: Record<string, ToolHandler>;
  files(): string[];
  exists(rel: string): boolean;
  read(rel: string): string;
  cleanup(): void;
}

export function createWorkspace(root?: string): Workspace {
  const base = resolve(root ?? mkdtempSync(join(tmpdir(), "asg-demo-")));
  const seed: Record<string, string> = {
    "docs/handbook.txt": "DEMO FIXTURE. Employee handbook. Remote work is allowed on Fridays. Expenses are reimbursed within 30 days.",
    "docs/old-notes.txt": "DEMO FIXTURE. Superseded meeting notes that are safe to delete once a human approves.",
    "docs/q3-draft.txt": "DEMO FIXTURE. Draft quarterly numbers. Revenue up, costs flat.",
    "reports/q3-final.txt": "DEMO FIXTURE. Final report. This sits outside the namespace the agent is allowed to touch.",
  };
  for (const [rel, text] of Object.entries(seed)) {
    mkdirSync(dirname(join(base, rel)), { recursive: true });
    writeFileSync(join(base, rel), text);
  }
  mkdirSync(join(base, "summaries"), { recursive: true });
  mkdirSync(join(base, "outbox"), { recursive: true });

  const safe = (rel: string): string => {
    const full = resolve(base, rel);
    if (full !== base && !full.startsWith(base + sep)) throw new Error("path escapes the workspace");
    try {
      if (lstatSync(full).isSymbolicLink()) throw new Error("symbolic links are not followed");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
    return full;
  };

  const documents: ToolHandler = async (a) => {
    const p = safe(a.resource);
    switch (a.operation) {
      case "read":
        return { bytes: readFileSync(p).length, preview: readFileSync(p, "utf8").slice(0, 60) };
      case "create":
        mkdirSync(dirname(p), { recursive: true });
        writeFileSync(p, String(a.args?.text ?? ""), { flag: "wx" }); // exclusive: never overwrites
        return { created: a.resource };
      case "update":
        writeFileSync(p, String(a.args?.text ?? ""), { flag: "r+" });
        return { updated: a.resource };
      case "delete":
        rmSync(p);
        return { deleted: a.resource };
      default:
        throw new Error(`unsupported documents operation '${a.operation}'`);
    }
  };

  // SIMULATED external transfer: copies into a local outbox folder named after the server-normalized host.
  const transfer: ToolHandler = async (a, ctx) => {
    if (!ctx.destinationHost) throw new Error("no validated destination");
    const source = safe(String(a.args?.source ?? ""));
    const out = join(base, "outbox", ctx.destinationHost);
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, basename(source)), `SIMULATED TRANSFER - no network used\n${readFileSync(source, "utf8")}`);
    return { simulated_delivery_to: ctx.destinationHost };
  };

  const shell: ToolHandler = async () => {
    throw new Error("The demo executor does not implement command execution.");
  };

  const files = () => {
    const out: string[] = [];
    const walk = (d: string) => {
      for (const e of readdirSync(d, { withFileTypes: true })) {
        const p = join(d, e.name);
        if (e.isDirectory()) walk(p);
        else out.push(p.slice(base.length + 1).split(sep).join("/"));
      }
    };
    walk(base);
    return out.sort();
  };

  return {
    root: base,
    handlers: { documents, transfer, shell },
    files,
    exists: (rel) => files().includes(rel),
    read: (rel) => readFileSync(join(base, rel), "utf8"),
    cleanup: () => rmSync(base, { recursive: true, force: true }),
  };
}
