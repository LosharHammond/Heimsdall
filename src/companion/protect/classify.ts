/**
 * Turns what an AI tool is about to do into a Heimdall action (tool, operation, resource, destination). Conservative: anything
 * that looks destructive is a delete, anything that sends data elsewhere is an external transfer, so the automatic policy can
 * pause exactly those and let everything else run at once.
 */
import type { ProtectedAction } from "../../sdk/index.js";
import { normalizeResource } from "../../shared/policy.js";

const DESTRUCTIVE_CMD = /(^|[\s;&|(])(rm|rmdir|del|erase|rd|shred|unlink|Remove-Item|ri|Clear-Content|format|mkfs|diskpart|dd)(\s|$)|git\s+(clean\b|reset\s+--hard|push\s+[^\n]*(--force|-f)\b|branch\s+-D)|\bdrop\s+(table|database|schema)\b|\btruncate\s+table\b|\bdelete\s+from\b|>\s*\/dev\/sd|\bkubectl\s+delete\b|\bterraform\s+destroy\b|\bdocker\s+(rm|rmi|system\s+prune)\b/i;
const SENDING_CMD = /(^|[\s;&|(])(curl|wget|scp|sftp|rsync|ftp|ssh|nc|ncat|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|Send-MailMessage)(\s|$)|git\s+push\b|npm\s+publish\b|twine\s+upload\b|docker\s+push\b|gh\s+(release\s+upload|gist\s+create)\b|aws\s+s3\s+(cp|sync|mv)\b|gsutil\s+cp\b|az\s+storage\b/i;
const URL_RE = /\bhttps?:\/\/[^\s'"<>`|)]+/i;

const DELETE_NAME = /(^|[_\-.])(delete|remove|rm|drop|destroy|purge|erase|unlink|trash|wipe|truncate)/i;
const SEND_NAME = /(^|[_\-.])(send|email|mail|post|upload|publish|share|tweet|message|notify|webhook|http|request|fetch_url|push|transfer|export|invite|slack|sms)/i;
const EXEC_NAME = /(^|[_\-.])(exec|execute|run|shell|command|terminal|bash|powershell|cmd|eval|spawn|script)/i;
const CREATE_NAME = /(^|[_\-.])(create|new|add|insert|make|mkdir|write_new)/i;
const UPDATE_NAME = /(^|[_\-.])(write|edit|update|modify|set|patch|put|move|rename|replace|save|append|commit|merge|apply)/i;
const READ_NAME = /(^|[_\-.])(read|get|list|search|find|query|view|show|open|fetch|load|describe|lookup|browse|cat|grep|glob|ls|stat|info|status)/i;

const lower = (s: string) => s.toLowerCase().replace(/[^a-z0-9_.-]+/g, "-").replace(/^[^a-z0-9]+/, "").slice(0, 64) || "tool";

/** A path anywhere on the computer as a Heimdall resource: "files/C/Users/ama/report.docx", "files/home/ama/x". */
export function fileResource(path: string): string {
  let p = path.replace(/\\/g, "/").trim();
  p = p.replace(/^([A-Za-z]):\//, (_, d: string) => `${d.toUpperCase()}/`).replace(/^\/+/, "");
  const r = normalizeResource(`files/${p}`);
  return r.ok ? r.value : "files/unrecognized-path";
}

function hostOf(text: string): string | undefined {
  const m = URL_RE.exec(text);
  if (!m) return undefined;
  try {
    return new URL(m[0]).toString();
  } catch {
    return undefined;
  }
}

// ---- commands, looked at the way the computer will run them ----

const ENCODED_PS = /(^|\s)-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[A-Za-z0-9+/=]{12,}/i;
const DOWNLOAD_RUN = /(\b(iwr|irm|curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b|DownloadString|DownloadFile|Net\.WebClient)[\s\S]*(\|\s*(iex|Invoke-Expression|sh|bash|zsh|python3?|pwsh|powershell|node|cmd)\b|;\s*(iex|Invoke-Expression)\b)|\bInvoke-Expression\b|\biex\s*[(\[$]|\bcertutil\b[\s\S]*-urlcache|\bbitsadmin\b[\s\S]*\/transfer|\bmshta(\.exe)?\s+["']?(https?|javascript|vbscript):|\bregsvr32\b[\s\S]*\/i:https?:/i;
const DISABLE_PROTECTION = /Set-MpPreference[\s\S]*-Disable|DisableRealtimeMonitoring|DisableAntiSpyware|\b(sc|sc\.exe)\s+(stop|config|delete)\s+(WinDefend|wscsvc|MpsSvc)|Stop-Service[\s\S]*\b(WinDefend|MpsSvc)|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off|Set-NetFirewallProfile[\s\S]*-Enabled\s+(False|\$false)|Uninstall-WindowsFeature\s+Windows-Defender/i;
const ELEVATE = /Start-Process\b[\s\S]*-Verb\s+["']?RunAs/i;
const WRITE_CMD = /(^|[\s;&|(])(>|>>|tee|Set-Content|sc|Add-Content|ac|Out-File|cp|copy|Copy-Item|mv|move|Move-Item|ren|Rename-Item|New-Item|ni|touch|mkdir|md|echo|sed\s+-i|notepad|code|nano|vim?|Set-ItemProperty)(\s|$)|[^-]>{1,2}\s*\S/i;
const SENSITIVE_HINT = /\.ssh|\.aws|\.azure|\.gnupg|\.kube|\.docker[\\/]config|\.git-credentials|[\\/_]\.?netrc|\.env\b|\.env\.|id_rsa|id_ed25519|id_ecdsa|\.pem\b|\.key\b|\.pfx\b|\.p12\b|\.kdbx|Login Data|Local State|Cookies|wallet\.dat|keystore|credentials(\.json)?|\.npmrc|\.pypirc|claude_desktop_config|\.claude[\\/]settings|mcp(_config)?\.json|KenuxaHeimdall|heimdall-backup|User Data|Credentials|Protect[\\/]|Vault|System32[\\/]config|Start Menu|\\Windows\\|\/Windows\/|Program Files|\/etc\/|AppData/i;

/** The command inside `powershell -c "..."`, `cmd /c ...`, `bash -c '...'`, `wsl ...` (one level, then once more). */
export function innerCommand(command: string): string {
  let c = command.trim().replace(/^&\s*/, "");
  for (let i = 0; i < 3; i++) {
    const ps = /^["']?(?:[^\s"']*[\\/])?(powershell|pwsh)(\.exe)?["']?\s+([\s\S]*)$/i.exec(c);
    const cmd = /^["']?(?:[^\s"']*[\\/])?cmd(\.exe)?["']?\s+\/[ck]\s+([\s\S]*)$/i.exec(c);
    const sh = /^(?:[^\s"']*\/)?(bash|sh|zsh|dash)\s+(?:-[a-z]*c[a-z]*)\s+([\s\S]*)$/i.exec(c);
    const wsl = /^wsl(\.exe)?\s+(?:-e\s+|--\s+)?([\s\S]*)$/i.exec(c);
    let next: string | null = null;
    if (ps) {
      const rest = ps[3];
      const m = /(?:^|\s)-(?:c|command)\s+([\s\S]*)$/i.exec(rest);
      next = m ? m[1] : rest.replace(/(^|\s)-(NoProfile|NonInteractive|NoLogo|WindowStyle\s+\w+|ExecutionPolicy\s+\w+|nop|noni|w\s+\w+|ep\s+\w+)\b/gi, " ");
    } else if (cmd) next = cmd[2];
    else if (sh) next = sh[2];
    else if (wsl) next = wsl[2];
    if (next === null) break;
    c = next.trim().replace(/^(["'])([\s\S]*)\1$/, "$2").replace(/^&\s*/, "").trim();
  }
  return c;
}

/** Turns path words in a command into absolute paths (~, %USERPROFILE%, $env:APPDATA, $HOME, relative to cwd). */
function pathsIn(command: string, cwd?: string): string[] {
  const home = (process.env.USERPROFILE ?? process.env.HOME ?? "").replace(/\\/g, "/");
  const tokens = command.match(/"[^"]*"|'[^']*'|[^\s;|&()]+/g) ?? [];
  const out: string[] = [];
  for (let t of tokens) {
    t = t.replace(/^["']|["']$/g, "").replace(/^-{1,2}[A-Za-z-]+[:=]/, "").replace(/^[\w.-]+=/, "").replace(/^[<>@]+/, "").replace(/^["']|["']$/g, "");
    if (!SENSITIVE_HINT.test(t) || /^(HK(LM|CU|CR|U|CC|EY_[A-Z_]+)\b|Registry::)/i.test(t) || /^https?:/i.test(t)) continue;
    let p = t.replace(/\\/g, "/");
    p = p.replace(/^~(?=\/|$)/, home)
      .replace(/^(%USERPROFILE%|\$env:USERPROFILE|\$HOME|\$\{HOME\}|\$env:HOME)/i, home)
      .replace(/^(%APPDATA%|\$env:APPDATA)/i, `${home}/AppData/Roaming`)
      .replace(/^(%LOCALAPPDATA%|\$env:LOCALAPPDATA)/i, `${home}/AppData/Local`)
      .replace(/^(%SYSTEMROOT%|%WINDIR%|\$env:SystemRoot|\$env:windir)/i, "C:/Windows")
      .replace(/^(%PROGRAMFILES%|\$env:ProgramFiles)/i, "C:/Program Files");
    if (!/^([A-Za-z]:\/|\/)/.test(p) && cwd) p = `${cwd.replace(/\\/g, "/").replace(/\/$/, "")}/${p.replace(/^\.\//, "")}`;
    // collapse "a/b/../c" so a relative path cannot hide where it really points
    const parts: string[] = [];
    for (const seg of p.split("/")) { if (seg === "..") parts.pop(); else if (seg !== ".") parts.push(seg); }
    out.push(parts.join("/"));
  }
  return out;
}

const shellResource = (word: string) => {
  const r = normalizeResource(`shell/${word.replace(/^.*[\\/]/, "").toLowerCase().replace(/[^a-z0-9_.-]/g, "") || "command"}`);
  return r.ok ? r.value : "shell/command";
};

/** A shell command. */
export function classifyCommand(tool: string, command: string, cwd?: string): ProtectedAction {
  const inner = innerCommand(command);
  const first = (inner.trim().split(/\s+/)[0] ?? "command").replace(/^["']|["']$/g, "");
  const base = { tool: lower(tool), args: { command: command.slice(0, 4000), ...(cwd ? { cwd } : {}) } };
  const all = `${command}\n${inner}`;
  // Things that are never acceptable, whatever program carries them.
  if (ENCODED_PS.test(command) || ENCODED_PS.test(inner)) return { ...base, operation: "command_execution", resource: "shell/encoded-command" };
  if (DISABLE_PROTECTION.test(all)) return { ...base, operation: "command_execution", resource: "shell/disable-protection" };
  if (DOWNLOAD_RUN.test(all)) return { ...base, operation: "command_execution", resource: "shell/download-and-run" };
  const destructive = DESTRUCTIVE_CMD.test(inner) || DESTRUCTIVE_CMD.test(command);
  const sending = SENDING_CMD.test(inner) || SENDING_CMD.test(command);
  const dest = sending ? hostOf(all) : undefined;
  // A command that touches a key file, saved passwords, Heimdall's settings or a system folder is checked as that file.
  for (const p of pathsIn(inner, cwd)) {
    const res = fileResource(p);
    if (res === "files/unrecognized-path") continue;
    const operation: ProtectedAction["operation"] = destructive ? "delete" : sending && dest ? "external_transfer" : WRITE_CMD.test(inner) ? "update" : "read";
    return { ...base, operation, resource: res, ...(operation === "external_transfer" && dest ? { destination: dest } : {}) };
  }
  const resource = ELEVATE.test(all) ? "shell/start-process-elevated" : shellResource(first);
  if (destructive) return { ...base, operation: "delete", resource };
  // Sending somewhere with no web address to check (git push, npm publish, scp to a host): a person decides.
  if (sending) return dest ? { ...base, operation: "external_transfer", resource, destination: dest } : { ...base, operation: "command_execution", resource: "shell/sends-data" };
  return { ...base, operation: "command_execution", resource };
}

/** Pulls the most meaningful target out of a tool's arguments. */
function targetOf(args: Record<string, unknown>): { resource?: string; destination?: string } {
  const str = (k: string) => (typeof args[k] === "string" ? (args[k] as string) : undefined);
  const path = str("path") ?? str("file_path") ?? str("filePath") ?? str("file") ?? str("filename") ?? str("target") ?? str("source") ?? str("directory") ?? str("dir") ?? str("notebook_path");
  const url = str("url") ?? str("uri") ?? str("endpoint") ?? str("webhook") ?? str("href");
  const to = str("to") ?? str("recipient") ?? str("email") ?? str("channel");
  return {
    ...(path ? { resource: fileResource(path) } : {}),
    ...(url && /^https?:\/\//i.test(url) ? { destination: url } : to && /@/.test(to) ? { destination: `https://${to.split("@").pop()}` } : {}),
  };
}

/** A tool call from an MCP server or an agent framework: classified from the tool's name and arguments. */
export function classifyToolCall(server: string, toolName: string, args: Record<string, unknown> = {}): ProtectedAction {
  const t = targetOf(args);
  const cmd = typeof args.command === "string" ? args.command : typeof args.cmd === "string" ? args.cmd : typeof args.script === "string" ? args.script : undefined;
  if (cmd && EXEC_NAME.test(toolName)) return { ...classifyCommand(server, cmd), args: { tool: toolName, command: cmd.slice(0, 4000) } };
  const op: ProtectedAction["operation"] = DELETE_NAME.test(toolName) ? "delete"
    : SEND_NAME.test(toolName) ? "external_transfer"
    : EXEC_NAME.test(toolName) ? "command_execution"
    : CREATE_NAME.test(toolName) ? "create"
    : UPDATE_NAME.test(toolName) ? "update"
    : READ_NAME.test(toolName) ? "read"
    : "update"; // unknown verbs are treated as changes, never as harmless reads
  const res = t.resource ?? (() => { const r = normalizeResource(`mcp/${lower(server)}/${lower(toolName)}`); return r.ok ? r.value : "mcp/tool"; })();
  return {
    tool: lower(server), operation: op, resource: res,
    ...(op === "external_transfer" && t.destination ? { destination: t.destination } : {}),
    args: { tool: toolName, ...summarizeArgs(args) },
  };
}

/** Argument summary for the record: short strings and numbers only (the server redacts secrets again). */
function summarizeArgs(a: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(a).slice(0, 20)) {
    if (typeof v === "string") out[k.slice(0, 60)] = v.length > 300 ? `${v.slice(0, 300)}…` : v;
    else if (typeof v === "number" || typeof v === "boolean") out[k.slice(0, 60)] = v;
  }
  return out;
}

/** Claude Code's built-in tools (PreToolUse hook input). Returns null for tools that are not checked. */
export function classifyClaudeCode(toolName: string, input: Record<string, unknown>, cwd?: string): ProtectedAction | null {
  const s = (k: string) => (typeof input[k] === "string" ? (input[k] as string) : "");
  switch (toolName) {
    case "Bash": case "PowerShell": return classifyCommand("claude-code", s("command"), cwd);
    case "Write": return { tool: "claude-code", operation: "update", resource: fileResource(s("file_path")), args: { tool: "Write", bytes: s("content").length } };
    case "Edit": case "MultiEdit": return { tool: "claude-code", operation: "update", resource: fileResource(s("file_path")), args: { tool: toolName } };
    case "NotebookEdit": return { tool: "claude-code", operation: input.edit_mode === "delete" ? "delete" : "update", resource: fileResource(s("notebook_path")), args: { tool: toolName } };
    case "Read": return { tool: "claude-code", operation: "read", resource: fileResource(s("file_path")), args: { tool: "Read" } };
    case "Grep": case "Glob": return s("path") ? { tool: "claude-code", operation: "read", resource: fileResource(s("path")), args: { tool: toolName, pattern: s("pattern").slice(0, 200) } } : null;
    case "WebFetch": return { tool: "claude-code", operation: "read", resource: "web/fetch", args: { tool: "WebFetch", url: s("url").slice(0, 500) } };
    default: {
      const m = /^mcp__(.+?)__(.+)$/.exec(toolName);
      return m ? classifyToolCall(m[1], m[2], input) : null;
    }
  }
}
