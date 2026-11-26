/**
 * Finds AI tools, agents and automations on this computer. Local only: what leaves the computer is the product name, a short
 * detail (a script's file NAME, never its path or contents) and whether Heimdall protects it.
 */
import { createHash } from "node:crypto";
import { join } from "node:path";

export type Kind = "mcp_client" | "coding_agent" | "ai_app" | "local_model" | "agent_script" | "automation";
export type Protection = "protected" | "restart_needed" | "unprotected" | "not_possible" | "off";

export interface Found {
  key: string; kind: Kind; product: string; detail: string; protectable: boolean; protection: Protection; running: boolean;
  /** For MCP clients: the config file and where its servers live. Never reported. */
  config?: { path: string; serversKey: "mcpServers" | "servers" };
  /** Claude Code: its user settings file. Never reported. */
  settingsPath?: string;
}

export interface Proc { name: string; cmd: string }
export interface ScanDeps {
  platform: NodeJS.Platform;
  home: string;
  appData: string;       // Windows %APPDATA% (Roaming)
  readFile(path: string, maxBytes?: number): string | null;
  exists(path: string): boolean;
  processes(): Proc[];
}

const MCP_CLIENTS: Array<{ id: string; product: string; proc: RegExp; paths: (d: ScanDeps) => string[]; serversKey: "mcpServers" | "servers" }> = [
  { id: "claude-desktop", product: "Claude Desktop", proc: /^claude(\.exe)?$/i, serversKey: "mcpServers",
    paths: (d) => [join(d.appData, "Claude", "claude_desktop_config.json"), join(d.home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), join(d.home, ".config", "Claude", "claude_desktop_config.json")] },
  { id: "cursor", product: "Cursor", proc: /^cursor(\.exe)?$/i, serversKey: "mcpServers", paths: (d) => [join(d.home, ".cursor", "mcp.json")] },
  { id: "windsurf", product: "Windsurf", proc: /^windsurf(\.exe)?$/i, serversKey: "mcpServers", paths: (d) => [join(d.home, ".codeium", "windsurf", "mcp_config.json")] },
  { id: "vscode", product: "VS Code (AI tools)", proc: /^code(\.exe)?$/i, serversKey: "servers",
    paths: (d) => [join(d.appData, "Code", "User", "mcp.json"), join(d.home, "Library", "Application Support", "Code", "User", "mcp.json"), join(d.home, ".config", "Code", "User", "mcp.json")] },
];

const APPS: Array<{ re: RegExp; key: string; kind: Kind; product: string }> = [
  { re: /^chatgpt(\.exe)?$/i, key: "app:chatgpt", kind: "ai_app", product: "ChatGPT desktop" },
  { re: /^(ollama|ollama app)(\.exe)?$/i, key: "model:ollama", kind: "local_model", product: "Ollama (local AI models)" },
  { re: /^lm ?studio(\.exe)?$/i, key: "model:lmstudio", kind: "local_model", product: "LM Studio (local AI models)" },
  { re: /^(pad\.console\.host|pad\.robot)(\.exe)?$/i, key: "auto:power-automate", kind: "automation", product: "Power Automate Desktop" },
  { re: /^uipath\.(executor|assistant|robot)(\.exe)?$/i, key: "auto:uipath", kind: "automation", product: "UiPath Robot" },
];

/** Agent frameworks, by what a script imports. Order matters: the most specific first. */
const FRAMEWORKS: Array<[RegExp, string]> = [
  [/\b(from|import)\s+heimdall\b|kenuxa-heimdall/, "HEIMDALL"],
  [/\b(from|import)\s+(langgraph|langchain)\b|["']@?langchain\//, "LangChain"],
  [/\b(from|import)\s+crewai\b/, "CrewAI"],
  [/\b(from|import)\s+(autogen|autogen_agentchat|ag2)\b/, "AutoGen"],
  [/\bfrom\s+agents\s+import\b|["']@openai\/agents["']/, "OpenAI Agents SDK"],
  [/\b(from|import)\s+(llama_index|llama-index)\b|["']llamaindex["']/, "LlamaIndex"],
  [/\b(from|import)\s+(smolagents|pydantic_ai|semantic_kernel)\b/, "AI agent framework"],
  [/["']@anthropic-ai\/sdk["']|\b(from|import)\s+anthropic\b/, "Anthropic API"],
  [/["']openai["']|\b(from|import)\s+openai\b/, "OpenAI API"],
  [/["']ai["']\s*;|from ["']ai["']|@ai-sdk\//, "Vercel AI SDK"],
];

const short = (s: string) => createHash("sha256").update(s.toLowerCase()).digest("hex").slice(0, 12);
const base = (p: string) => p.replace(/^.*[\\/]/, "");

function parseJson(text: string | null): any {
  if (!text) return null;
  try { return JSON.parse(text.replace(/^﻿/, "")); } catch { return null; }
}

/** The script a python/node process runs, from its command line. */
export function scriptOf(cmd: string): string | null {
  const parts = cmd.match(/"[^"]*"|\S+/g)?.map((p) => p.replace(/^"|"$/g, "")) ?? [];
  if (!parts.length || !/(^|[\\/])(python[0-9.]*|pythonw|py|node|bun|deno|tsx|ts-node|uv|poetry)(\.exe)?$/i.test(parts[0])) return null;
  for (const p of parts.slice(1)) {
    if (p.startsWith("-")) continue;
    if (/\.(py|js|mjs|cjs|ts|mts)$/i.test(p)) return p;
  }
  return null;
}

export const isWrapped = (entry: any) => Array.isArray(entry?.args) && entry.args.includes("mcp-proxy") && entry.args.includes("--key");

export function scan(d: ScanDeps): Found[] {
  const procs = d.processes();
  const out: Found[] = [];
  for (const c of MCP_CLIENTS) {
    const path = c.paths(d).find((p) => d.exists(p));
    if (!path) continue;
    const cfg = parseJson(d.readFile(path)) ?? {};
    const servers = (cfg[c.serversKey] ?? {}) as Record<string, any>;
    const names = Object.keys(servers);
    const local = names.filter((n) => typeof servers[n]?.command === "string");
    const remote = names.length - local.length;
    const wrapped = local.filter((n) => isWrapped(servers[n])).length;
    out.push({
      key: `mcp:${c.id}`, kind: "mcp_client", product: c.product, running: procs.some((p) => c.proc.test(p.name)),
      protectable: local.length > 0,
      protection: local.length === 0 ? "not_possible" : wrapped === local.length ? "protected" : "unprotected",
      detail: local.length === 0 ? (remote ? `${remote} remote tool server(s): not covered` : "no tool servers set up")
        : `${local.length} tool server(s)${remote ? `, ${remote} remote not covered` : ""}${c.id === "claude-desktop" ? "" : "; built-in edits and terminal not covered"}`,
      config: { path, serversKey: c.serversKey },
    });
  }
  // Claude Code: its hook sees every command, file change and tool call it makes.
  const ccSettings = join(d.home, ".claude", "settings.json");
  if (d.exists(join(d.home, ".claude")) || d.exists(join(d.home, ".claude.json"))) {
    const s = parseJson(d.readFile(ccSettings)) ?? {};
    const hooked = JSON.stringify(s?.hooks?.PreToolUse ?? []).includes("hook claude-code");
    out.push({
      key: "claude-code", kind: "coding_agent", product: "Claude Code", protectable: true, protection: hooked ? "protected" : "unprotected",
      running: procs.some((p) => /(^|[\\/ ])claude(\.exe|\.cmd)?(\s|$)/i.test(p.cmd) || /@anthropic-ai[\\/]claude-code/i.test(p.cmd)),
      detail: "commands, file edits and tool calls", settingsPath: ccSettings,
    });
  }
  const seen = new Set<string>();
  for (const p of procs) {
    const app = APPS.find((a) => a.re.test(p.name));
    if (app && !seen.has(app.key)) {
      seen.add(app.key);
      out.push({ key: app.key, kind: app.kind, product: app.product, detail: "", protectable: false, protection: "not_possible", running: true });
      continue;
    }
    if (/\bn8n\b/i.test(p.cmd) && /node/i.test(p.name) && !seen.has("auto:n8n")) {
      seen.add("auto:n8n");
      out.push({ key: "auto:n8n", kind: "automation", product: "n8n workflows", detail: "", protectable: false, protection: "not_possible", running: true });
      continue;
    }
    const script = scriptOf(p.cmd);
    if (!script) continue;
    const key = `script:${short(script)}`;
    if (seen.has(key)) continue;
    const text = d.readFile(script, 256 * 1024) ?? "";
    const fw = FRAMEWORKS.find(([re]) => re.test(text))?.[1];
    if (!fw) continue;
    seen.add(key);
    const viaSdk = FRAMEWORKS[0][0].test(text);
    const framework = viaSdk ? (FRAMEWORKS.slice(1).find(([re]) => re.test(text))?.[1] ?? "AI") : fw;
    out.push({
      key, kind: "agent_script", product: `${framework} agent`, detail: `${base(script)}${viaSdk ? " (uses the Heimdall SDK)" : ""}`,
      protectable: false, protection: viaSdk ? "protected" : "not_possible", running: true,
    });
  }
  return out;
}
