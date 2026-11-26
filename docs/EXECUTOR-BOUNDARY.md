# Trusted executor: what it enforces and where the boundary is

The supported integration is the **Heimdall MCP server** (`src/integrations/mcp/server.ts`, `npm run mcp`). An MCP client (Claude Desktop, Claude Code, any MCP-capable agent) launches it over stdio. The agent sees five tools; **the agent never receives a path, a file handle, a credential or a network route**. Every call goes:

```
agent -> MCP tool -> ProtectedExecutor.prepare -> POST /v1/authorize -> (approval?) -> verify -> POST /claim -> execute -> POST /outcome
                      canonical resource        decision bound to       human      pre-claim   one-time    trusted code   reported
                      + file identity           SHA-256 action digest              checks      permit      only here
```

All protected-resource access lives in two modules, which are the only code that may touch the folder or the network:

| Module | Controls |
| --- | --- |
| `src/executor/fs-guard.ts` | one protected root; every path component checked with `lstat` + `realpath` (symlinks, junctions, mount points refused); hard links (`nlink > 1`) refused; real-case canonicalization **before** authorization; `dev:ino` identity bound at authorization and re-checked on the opened handle at use; exclusive create (never overwrites); read size cap |
| `src/executor/egress.ts` | destination re-normalized and compared with the host the service approved; https + port 443 only; IP literals, URL credentials refused; DNS resolved **in the executor** and refused if ANY answer is private, loopback, link-local, multicast, CGNAT, documentation or mapped-private; connection pinned to the vetted IP (no second lookup); redirects never followed; size/time bounds |
| `src/executor/trusted.ts` | the `documents` and `transfer` tool definitions; **no subprocess capability** (the code imports no `child_process`; a test asserts it and a preload trap proves no process starts when `run_command` is called) |

## What is bypass-resistant under this architecture (and tested)

- An agent that can only talk to the MCP server cannot read, change, delete or upload anything the policy does not allow. Denied calls leave the disk and the network untouched; tests assert this from the **test process** by reading the fixtures and by counting requests at a local receiver, not by trusting a "blocked" message.
- Argument changes after authorization, replay, duplicate/concurrent execution, expired/rejected approvals, policy changes after approval, revoked credentials and an unreachable service all fail closed (see `tests/mcp.test.ts`, `tests/enforcement.test.ts`, `tests/executor.test.ts`).
- Path attacks: traversal, absolute paths, percent-encoding, Unicode look-alikes (full-width dots/slashes), NTFS alternate data streams, trailing dots/spaces, reserved device names, 8.3 short names, case variants, junctions, symbolic links, hard links, and a file swapped between authorization and use.
- Destination attacks: look-alike domains, `user@host` credentials, IP literals (decimal/hex/IPv6), private/link-local answers, mixed public/private DNS answers, redirects, host/port mismatch.

## What is NOT controlled (be explicit with customers)

- **A process with direct access.** If the agent (or anything else on the machine) can open the files, use the network or read the credentials directly, it can bypass the executor. The executor is not an operating-system sandbox, a minifilter driver or a firewall. Keep the agent without a filesystem/shell/network tool of its own; register only this MCP server for file access.
- **Other tools in the same client.** A second MCP server, a shell tool or a browser tool is outside Heimdall.
- **Windows race window.** Windows has no `O_NOFOLLOW`; after the last `lstat/realpath/fstat` checks a very small window remains before the system call. The checks make exploitation require a local process already able to write the folder.
- **Local administrators and the executor's own user.** Anyone who can run code as the same user can edit the cache directory or the executor.
- **Self-declared metadata.** The service trusts the executor's description of the action (tool, resource, destination). The digest binds the action *as described*.
- **Content.** The executor moves bytes; it does not inspect them (no DLP, no malware scanning).

## Data classification

Classification must not be decided by the agent. Policies may carry a `classifications` map (resource patterns -> `public|internal|confidential|restricted`), which is **trusted policy metadata**:

- the highest matching level wins; an agent's claim can never lower it, and a *higher* claim is honoured because it only tightens rules;
- a resource the map does not cover is `unclassified`, handled conservatively: deny and approval rules that name a class still match it, allow rules that require a class do not;
- policies without a map fall back to the agent's declaration, which is shown as **untrusted** in the dashboard.

The UI shows the level, its source (`set by your policy`, `raised by the agent`, `declared by the agent (untrusted)`) and how unknown classification is treated. A supported inspection mechanism (content scanning) does not exist yet.
