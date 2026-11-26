# Threat model

Scope: the hosted Heimdall service (API + dashboard + PostgreSQL) and the TypeScript adapter. Not in scope: endpoint software, network interception (neither exists).

## Assets

| Asset | Why it matters |
| --- | --- |
| Integration keys | Whoever holds one can request decisions and claim execution for one agent |
| Policies | Define what agents may do; tampering changes enforcement |
| Approvals | A human's authority to let one risky action run |
| Action/decision/outcome history and audit log | Evidence for investigations; may reveal resource names and metadata |
| User sessions and password hashes | Give control of an organization |
| Availability of the authorization service | Agents fail closed when it is down |

## Trust boundaries

1. **Browser <-> API** (`/api`, cookie session, CSRF header + Origin check).
2. **Customer application/adapter <-> API** (`/v1`, bearer key over HTTPS). The adapter and handlers run in the *customer's* environment and are trusted only to the extent the customer keeps the agent from bypassing them.
3. **API <-> PostgreSQL** (parameterized queries; composite foreign keys enforce organization boundaries inside the database).
4. **The agent (untrusted/steerable) <-> the controlled executor.** The agent is assumed to be manipulable by prompt injection. It must have no route to protected resources except via the executor.

## Attackers considered

| Attacker | Goal |
| --- | --- |
| A. Prompt-injected or misbehaving agent | Perform delete/exfiltrate/command actions outside its policy |
| B. Malicious member of another organization | Read or alter another tenant's data |
| C. Viewer/admin acting beyond their role | Change enforcement or approve own requests |
| D. Network attacker / stolen key holder | Replay or forge authorizations |
| E. Cross-site attacker | Trigger dashboard actions via a victim's browser |
| F. Operator error | Leak secrets in logs or the database |

## Controls (and where they are tested)

| Threat | Control | Test |
| --- | --- | --- |
| A: action outside policy | Deterministic engine, default deny, explicit deny precedence, approval rules before allow | `policy-engine.test.ts` |
| A: path traversal / URL tricks / SSRF-shaped destinations | Resource and destination normalization; IP literals and private hosts never match; userinfo URLs refused; policy cannot allow private hosts | `policy-engine.test.ts` |
| A: change arguments after authorization | SHA-256 action digest over tool/operation/resource/destination/classification/args; claim must present the same digest; adapter runs a frozen snapshot | `enforcement.test.ts` (action binding) |
| A/D: double execution via retry or race | One-time claim (unique row per action, row-locked); approval consumed atomically; outcome idempotent; claim never retried | concurrent-claim tests |
| A: stale permission | Immediate allows expire in 5 min; policy and agent status rechecked at claim; approvals void on policy change/expiry/revocation | approval and claim tests |
| A: protected resource access | Demo handlers hold the only access to fixtures; denied actions verified to leave the filesystem unchanged | `Denied operations cause no protected side effect` |
| B: tenant isolation | Org derived from membership or key, never from the client; non-members get 404; composite FKs reject cross-org references at the database; unknown request fields rejected | `access.test.ts` (organization isolation) |
| C: roles | Server-side role checks on every operation; owner/admin/viewer matrix; owner-level approval rules; last-owner protection; keys have no route to `/api` | `access.test.ts` (roles), self-approval test |
| D: key theft/replay | Keys are 256-bit random, stored as SHA-256 hash, shown once, revocable, replaceable, scope- and agent-limited, rate-limited; revoked use raises an alert | credential tests |
| D: tampering with decisions in transit | HTTPS (deployment requirement); adapter checks the returned digest equals its own | `lying server` test |
| E: CSRF | HttpOnly SameSite=Lax cookie, required `x-asg-csrf` header, Origin check | CSRF test |
| Brute force | scrypt password hashing, per-email and per-IP limits, uniform failure message and timing equalisation | rate-limit test |
| F: secret leakage | Redaction before persistence and logging (keys, tokens, JWTs, card-like numbers, emails; content-like fields omitted); logs never include request bodies or headers | `secrets never leak` test |
| Injection/abuse | Parameterized SQL, strict zod schemas, body/arg size limits, no URL-fetch or command endpoint exists | tests, code review |
| Availability failures | Any 5xx/timeout/malformed response = not authorized; adapter never executes on error; readiness reflects DB | `failure handling` tests |

## Residual risks and limitations (be honest with customers)

- **Bypass.** Heimdall cannot protect against a fully compromised application, or an agent that can reach resources or credentials directly. Enforcement exists only for tools routed through the adapter.
- **Self-declared data classification and tool names.** The service trusts the adapter's description of the action. A compromised adapter can lie about what it will do; the digest only binds *what was described* to what was authorized.
- **Redaction is heuristic.** Unknown secret formats can slip through; content-like keys are omitted but other keys are kept (truncated to 200 chars).
- **Observability of intent only.** For external transfers the platform validates the destination string; the demo executor simulates delivery locally and no network access is performed. A real executor must connect only to `destination_host`, must not follow redirects to other hosts, and must block private/link-local addresses after DNS resolution.
- **Audit log is application-append-only** (a trigger blocks UPDATE). Anyone with database privileges, or the retention job, can delete rows. It is not tamper-proof.
- **Single-instance rate limits** (in memory). Horizontal scaling needs a shared limiter.
- **Authentication** is custom and minimal: no MFA, email verification, password reset, session listing or SSO. Account existence is revealed at sign-up (409).
- **Availability** depends on one application and one database. A Heimdall outage stops authorized actions (fail closed) by design.
- **Timing.** An allowed action can run up to 5 minutes after its decision; a human approval grants a 5-minute one-time window.
- **No independent security assessment** has been performed.

---

# Addendum: trusted executor, devices, notifications, offline operation

New assets: protected folder contents, the executor's signed-policy cache and outbox, device keys, the policy signing key, notification delivery records.
New trust boundaries: **agent <-> MCP server** (stdio; the agent is untrusted and steerable), **executor <-> OS** (files, DNS, network), **companion <-> Windows** (toast API, registry, DPAPI), **companion/executor <-> service** (device keys `hdv_`, agent keys `asg_`).

| Threat | Control | Test |
| --- | --- | --- |
| Agent bypasses policy via path tricks (traversal, encodings, ADS, 8.3, case, junction/symlink, hard link) | shared normalizer + `fs-guard` (lstat/realpath per component, nlink, real-case canonicalization before authorization) | `executor.test.ts` |
| File swapped between authorization and use | file identity (`dev:ino`) bound at authorization, re-checked on the opened handle; refusal reported as a failure | `executor.test.ts` (swap) |
| Data exfiltration to look-alike/private/redirecting destinations | executor-side normalization, host equality with the authorized host, DNS vetting of every answer, IP pinning, no redirects, https/443 only | `executor.test.ts` (egress) |
| Arbitrary command execution | policy deny + executor has no subprocess capability; preload trap | `mcp.test.ts`, `executor.test.ts` |
| Agent mislabels sensitive data as public | classification from trusted policy map; claims can only raise | `policy-engine.test.ts`, `executor.test.ts` |
| Forged/edited offline policy; extended expiry; other agent's bundle; rollback | Ed25519 signature over the whole bundle, pinned key, agent binding, expiry, monotonic version marker | `offline.test.ts` |
| Offline approval bypass | approval-required actions are refused offline | `offline.test.ts`, `mcp.test.ts` |
| Offline executor lies about what it did | server re-evaluates every offline record against the claimed policy version; mismatch alert | `devices.test.ts` |
| Notification storm / duplicate toasts | one delivery row per alert+device, cooldown, 3 + summary | `devices.test.ts`, `companion.test.ts` |
| Another org receives alerts/devices/policies | org derived from device/agent credential; foreign alert ids ignored; 404 for non-members | `devices.test.ts` |
| Device key theft | DPAPI (current user), hash-only server storage, single-use enrollment token, revocation, uninstall revokes | `devices.test.ts`, real DPAPI test |
| Privacy creep via telemetry | consent flags on the device; server drops optional fields without same-message consent; process **names only**, flagged weak | `devices.test.ts`, `companion.test.ts` |

Residual risks: see EXECUTOR-BOUNDARY.md (direct access bypass, Windows race window, same-user attacker, self-declared metadata, no content inspection), OFFLINE.md (revocation lag bounded by bundle TTL; cache directory is only as private as its ACL), COMPANION.md (starts after sign-in only; PowerShell-driven toast path; Focus assist undetectable). A local administrator or malware running as the user can stop the companion, edit its files or bypass the executor: this product reports that state (stale heartbeat) but cannot prevent it.
