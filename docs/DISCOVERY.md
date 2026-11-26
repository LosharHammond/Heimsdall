# Automatic discovery and protection

Once a computer is added (Protection Center → **Protect this computer**), the Heimdall app looks for AI tools on it every
5 minutes and protects what it can, with nobody registering anything.

## What it finds

| Found | How | Protected? |
| --- | --- | --- |
| **Claude Desktop, Cursor, Windsurf, VS Code** (MCP tool servers) | their MCP settings files | **Yes.** Each local tool server is started through Heimdall's proxy, which asks Heimdall before every tool call. Remote (URL) tool servers and these apps' own built-in edits/terminal are listed as not covered. |
| **Claude Code** | `~/.claude` | **Yes.** A PreToolUse hook asks Heimdall before every command, file change, web fetch and MCP tool call. Reads and searches are not checked, so they stay instant. |
| **Python / Node agents** (LangChain, LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, LlamaIndex, smolagents, Pydantic AI, Semantic Kernel, Vercel AI SDK, plain OpenAI/Anthropic API scripts) | running processes; the script's imports are read on the computer | **Listed and alerted.** Heimdall cannot stand in front of a script from outside it. One “Unprotected AI agent” alert per script. Scripts that already use the Heimdall SDK show as protected. |
| **ChatGPT desktop, Ollama, LM Studio** | running processes | Listed. |
| **Power Automate Desktop, UiPath, n8n** | running processes | Listed and alerted. |

Only the product name, a short detail (a script's **file name**, never its path or contents) and the protection status leave
the computer.

## What “protected” does

Every protected tool becomes an agent in Heimdall named like *Claude Code on AMA-LAPTOP*, with the policy **Recommended for AI
tools (automatic)** (created on first use; edit it like any policy):

- reads, edits, creating files and ordinary commands (`git status`, `npm test`) run at once;
- **deleting** (including `rm -rf`, `Remove-Item`, `git push --force`, `DROP TABLE`, `terraform destroy`) and **sending data out**
  (`curl` uploads, `git push`, sending email or messages) wait for a person to approve.

Decisions come from the signed policy held in memory by the app on the computer (the fast path), so routine actions are not
slowed by the network. Each check of a Claude Code action takes about 0.1 s (starting the hook); MCP tool calls are checked
inside the already-running proxy. Waiting for approval: Claude Code waits up to 9 minutes; MCP apps wait about 50 seconds,
then the AI is told to try again after approval (approved actions then go straight through).

If the Heimdall app is not running, routine work continues and only deleting and sending data out are refused, so AI tools
never stop working because of Heimdall.

## Settings edits, and undoing them

- MCP apps: each local server entry becomes `HeimdallCompanion.exe mcp-proxy --key … --server … -- <original command>`. The
  original command is kept inside the entry, and the first edit keeps a copy of the file (`<file>.heimdall-backup`). Apps that
  were open need to be restarted once (Heimdall shows a notification and “Restart it once” in the dashboard).
- Claude Code: one hook entry is added to `~/.claude/settings.json`; your other hooks and settings are untouched. New Claude
  Code sessions use it.
- **Undo:** an administrator turns off **Protection Center → Protect found AI tools automatically**, and every computer
  restores the original settings within 5 minutes. On one computer: `HeimdallCompanion.exe unprotect`. Uninstalling the app
  restores them too, and so does removing the computer in the dashboard.

## Limits

- A browser alone cannot look at a computer; discovery starts once the app is installed.
- Scripts started with a relative path (`python bot.py` in a terminal) can only be recognized when their folder is known;
  on Windows the app cannot read another process's working folder, so such scripts may be missed. Scripts started with a full
  path, by schedulers, services and IDEs (the common case) are found.
- Agents that call AI services directly from their own code can be found and flagged but not blocked from outside; adding the
  SDK (`pip install kenuxa-heimdall`, two lines) protects them fully.
- Web AI used in a browser tab (ChatGPT in Chrome) is not detected.

Commands: `HeimdallCompanion.exe discover` (what would be reported), `unprotect`. API: `POST /v1/device/discovery`
(computers), `GET /api/orgs/:org/discovered`, `PUT /api/orgs/:org/auto-protect`. Tests: `tests/discovery.test.ts`.
