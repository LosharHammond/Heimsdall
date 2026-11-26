# MCP integration (supported agent integration)

Tools exposed: `read_document`, `write_summary`, `delete_document`, `send_document`, `run_command` (always refused; it exists so the attempt is authorized, recorded and alerted).
Results are honest strings: `EXECUTED`, `REFUSED (CODE)`, `WAITING FOR HUMAN APPROVAL` (with a `request_id` to resume the same action), `FAILED after being permitted`, `NOT EXECUTED (CODE)` (authorization could not be established; nothing ran).

## Run it

```bash
# register an agent in the dashboard (SDK integration), assign a policy, copy its key, then:
HEIMDALL_URL=https://heimdall.example.com HEIMDALL_KEY=asg_... HEIMDALL_ROOT="C:\Users\you\HeimdallProtected" npm run mcp
```

| Variable | Meaning |
| --- | --- |
| `HEIMDALL_URL`, `HEIMDALL_KEY` | service and the agent's integration key (the key never reaches the agent) |
| `HEIMDALL_ROOT` | the ONE protected folder |
| `HEIMDALL_EGRESS=1` | enable external transfers (default **off**: every transfer is refused) |
| `HEIMDALL_APPROVAL_WAIT_MS` | how long a tool call waits for an approval before answering "waiting" (default 0) |
| `HEIMDALL_STATE_DIR` | status file + signed-policy cache (default `%LOCALAPPDATA%\KenuxaHeimdall`) |
| `HEIMDALL_POLICY_PUBKEY` | pin the signing key explicitly (otherwise pinned on first contact) |
| `HEIMDALL_OFFLINE=0` | disable the offline policy cache (fail closed when the service is unreachable) |

### Claude Desktop (`claude_desktop_config.json`)

```json
{ "mcpServers": { "heimdall": {
  "command": "node",
  "args": ["C:\\path\\to\\Kenuxa Heimdall\\dist\\integrations\\mcp\\server.js"],
  "env": { "HEIMDALL_URL": "https://heimdall.example.com", "HEIMDALL_KEY": "asg_...", "HEIMDALL_ROOT": "C:\\Users\\you\\HeimdallProtected" }
} } }
```
(Build first with `npm run build`; the compiled server is `dist/integrations/mcp/server.js`. Configuration format per your MCP client's documentation.)

**Register only this server for file access.** Any additional file/shell tool in the same client is outside Heimdall.

## Live demonstration

`scripts/live-mcp.ts` drives the real server through a real stdio MCP client against a running Heimdall (read allowed, summary written, delete waits, traversal/transfer/command refused) and observes the folder from its own process:

```bash
HEIMDALL_URL=http://localhost:8787 HEIMDALL_KEY=asg_... npx tsx scripts/live-mcp.ts "%USERPROFILE%\HeimdallProtected" 25
```

## Verified by tests

`tests/mcp.test.ts` (real stdio, real HTTP, real disk): tool list; allowed read/summary; refusals with no side effect; `run_command` refused while a **preload trap proves no subprocess was started**; approval waits then executes exactly once; replay, expiry, revocation, policy change; service down fails closed; service outage mid-session falls back to the signed cache and refuses approvals.
