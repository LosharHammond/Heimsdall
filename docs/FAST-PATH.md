# Fast path: protection that does not slow agents down

Routine agent actions are decided **in the agent's own process** from the signed policy, in microseconds, with no network call
and no disk access. The audit trail is sent to the service in the background. Only actions the policy marks
`require_approval` wait, because they wait for a person.

## Measured overhead (25 Nov 2026, this repository, `npx tsx bench/fast-path.bench.ts`)

No-op tool, so only Heimdall's own cost is measured. Linux container, Node 22.

| Path | p50 | p99 |
| --- | ---: | ---: |
| Policy engine alone (`evaluate`) | 1.4 µs | 4.5 µs |
| **Fast path**: `executor.run()` with a local decision | **8.8 µs** | **37 µs** |
| Online path: `executor.run()` against an in-process server, no network | 153.6 µs | 23.66 ms |

The online figure is a floor: over a real network the online path adds three round trips (authorize, claim, outcome). The fast
path does not change with the network. 52,000 fast-path records were sent in background batches during the run, with 0
mismatches on server re-evaluation.

## How it works

1. **Signed bundle in memory.** The executor fetches the agent's policy bundle (`GET /v1/policy-bundle`), checks the Ed25519
   signature against the pinned service key, the agent binding, the expiry and that it is not older than one already
   accepted (no rollback). Checked once, then held in memory.
2. **Local decision.** Every action is evaluated by the same deterministic engine the server uses (`src/shared/policy.ts`),
   in-process. Compiled path patterns are cached.
   - `allow`: the trusted executor's own checks run (`verify`), a one-time permit is taken for the request id, the tool runs.
   - `deny`: refused at once, nothing runs.
   - `require_approval`: **not decided locally.** The action goes to the service and waits for a person, exactly as before.
     After approval it runs through the online one-time claim.
3. **Background audit.** Each decision and its outcome are queued in memory and sent every 250 ms in batches of up to 500
   (`POST /v1/offline-sync`, `source: "local_fast"`). The server stores them, **re-evaluates each against the policy version it
   was decided with**, and raises a high-severity `offline_decision_mismatch` alert on any disagreement, so a tampered executor
   is caught. The dashboard labels these actions "Fast path".
4. **Staying current.** Every 2 s the executor asks `GET /v1/policy-state` (a few bytes) for the agent's policy version and
   mode. A change triggers an immediate bundle refresh. A revoked key or agent gets a 401/403, which drops the bundle at once;
   the executor then uses the online path, which refuses. A full refresh every 30 s renews the bundle's expiry.
5. **Never blocks on the network.** If no valid bundle is loaded (first start, expired, revoked), the executor uses the
   normal online path: correct, only slower.

## Using it

```ts
import { GuardianClient, ProtectedExecutor } from "kenuxa-heimdall/sdk";             // src/sdk/index.ts in this repo
import { FastPathAuthority } from "kenuxa-heimdall/executor/fast-path";            // src/executor/fast-path.ts
import { verifySignature } from "kenuxa-heimdall/server/signing";                  // src/server/signing.ts

const client = new GuardianClient({ baseUrl: process.env.HEIMDALL_URL!, apiKey: process.env.HEIMDALL_KEY! });
const fastPath = new FastPathAuthority({ client, verify: verifySignature, publicKeyPem: process.env.HEIMDALL_POLICY_PUBKEY });
await fastPath.start();                       // never throws; until a bundle loads, calls use the online path
const executor = new ProtectedExecutor(client, handlers, { fastPath });
process.on("SIGTERM", () => fastPath.stop()); // sends whatever is still queued
```

The MCP integration (`npm run mcp`) turns it on by default.

| Variable | Default | Meaning |
| --- | --- | --- |
| `HEIMDALL_FAST_PATH` | on | `0` = every call asks the service (strict online mode) |
| `HEIMDALL_FAST_PATH_CHECK_MS` | 2000 | How often to check the policy version. Bounds how long a policy change or revocation takes to apply |
| `HEIMDALL_FAST_PATH_REFRESH_MS` | 30000 | Full bundle refresh (renews expiry) |

`fastPath.stats()` returns state, policy version, decisions, queued, sent, mismatches and refusals for a status page.

## Trade-offs, stated plainly

| Online path | Fast path |
| --- | --- |
| A revoked key or a policy change applies on the very next call | Applies within `checkMs` (default 2 s); the bundle's expiry is a hard stop |
| Budgets counted across all executors of the agent | Budgets counted per process |
| One-time claim enforced by the server across processes | Per-process permit; request ids are random, and the server flags duplicates on sync |
| Outcome stored before `run()` returns | Stored within `flushMs` (250 ms). Up to that much is lost if the process is killed without `stop()` |
| Network outage: falls back to the offline cache | Keeps deciding from memory; the audit queue holds up to 50,000 records, then **refuses** actions rather than run them unrecorded |

Choose strict online mode (`HEIMDALL_FAST_PATH=0`) for an agent where a revocation must stop the very next call.
Approvals behave identically in both modes. The enforcement boundary is unchanged: only tools executed through the executor are
protected ([EXECUTOR-BOUNDARY.md](EXECUTOR-BOUNDARY.md)).
