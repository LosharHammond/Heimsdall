# Kenuxa Heimdall

An **AI agent permission and behaviour firewall**, built as one deployable Node.js application with PostgreSQL.

Organizations register their AI agents, write a policy for each, and route the agents' tool calls through a small
adapter. For every proposed action the platform issues a deterministic decision (`allow`, `deny` or
`require_approval`), lets a human approve risky actions, records what the executor actually did, and shows it all in a
dashboard.

> This folder is self-contained and lives next to (and does not touch) the unrelated One Workspace app in the parent directory.

## The one idea you must not skip: observation vs authorization vs enforcement

| Term | Meaning | Where you see it |
| --- | --- | --- |
| **Observation** | An event was *reported* by an integration. Says nothing about prevention. | `POST /v1/events`, "Reporting events only" agents |
| **Authorization** | The policy engine issued a decision. | Decision badge: Allowed / Denied / Needs approval |
| **Enforcement** | An integrated executor *confirmed* it did or did not run the action. | Result badge: **Blocked** only when the adapter confirmed non-execution |

A denial that the executor never confirmed is shown as **"Denied (not confirmed)"**, never "blocked". "Allowed" is not
"executed": the dashboard shows *Authorized, no run reported* until the executor reports an outcome.

An AI-model API proxy can only inspect traffic routed through it; it cannot stop a separate application from running a
tool outside it. That is why enforcement here is done by an **adapter / controlled executor**
([`src/sdk/index.ts`](src/sdk/index.ts)) that checks authorization *before* touching a protected resource.
Heimdall does **not** protect against a fully compromised application that can bypass the adapter or reach the
underlying credentials directly. It also cannot discover agents on its own: visibility requires an authorized
integration (an agent registered here and connected with a key).

## Protecting the AI tools on your computer (start here)

Double-click **`START-HEIMDALL.bat`**. It starts the server and dashboard, opens the dashboard, and starts the Heimdall app
that protects this computer. The first time, a code appears in the dashboard: click **Add**. Then restart Claude Desktop /
Cursor once. From then on AI tools on this computer follow [Standard protection](docs/STANDARD-PROTECTION.md): keys,
saved passwords, Heimdall's own settings, system folders, dangerous and hidden commands are refused; deleting, sending data
out and system changes wait for your approval; ordinary work runs at once. The Overview page tells you if nothing is being
protected.

Sign in with **Google** (set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`) or **Kenuxa Account** (on by default; register
Heimdall once with `KENUXA ACCOUNTS/supabase/migrations/0004_heimdall_sourcebook.sql`). The nine-dot menu next to the logo
opens the other Kenuxa apps.

## Quick start (local, no external services)

Requirements: Node.js 22+. In development the app uses an embedded PostgreSQL (PGlite) stored in `.data/`, so you do
not need to install a database.

```bash
npm install
npm run dev          # API on :8787, dashboard on http://localhost:5173
```

In another terminal, run the demonstration (it creates a demo organization, agent, policy and key through the real
API, then drives the controlled executor against disposable fixture files):

```bash
npm run demo
```

It prints PASS/FAIL for 14 checks and a demo login so you can inspect the results in the dashboard. Demo activity
carries a "Demonstration" badge and is filterable ("Demonstration only / Real only").

Or build and run the production bundle:

```bash
npm run build
npm start            # serves API + built dashboard on :8787
```

## Scripts

| Command | What it does |
| --- | --- |
| `npm run dev` | API (tsx watch) + Vite dev server with proxy |
| `npm run build` / `npm start` | Production bundle (`dist/web`, `dist/server`) / run it |
| `npm run migrate` | Apply SQL migrations in `migrations/` |
| `npm run retention` | Delete data older than each organization's retention settings |
| `npm run seed` | Dev only: fill a fresh `.data/` with a showcase organization (agents, a week of labelled demonstration traffic, approvals, alerts). Stop the server first |
| `npm run connect` | Link this computer to a registered agent (see below) |
| `npm run demo` | Runnable demonstration against a running server (`BASE_URL`, default `http://localhost:8787`) |
| `npm test` | automated tests on embedded PostgreSQL (PGlite), incl. real MCP stdio and real Windows API tests |
| `npm run mcp` / `npm run companion` / `npm run worker` | MCP server / Windows companion / background worker |
| `npx tsx scripts/live-mcp.ts` | live MCP demonstration against a running server |
| `npm run test:pg` | The same suite against a **real PostgreSQL server** (embedded-postgres binaries) |
| `npm run smoke:prod` | Build, then boot the production bundle on real PostgreSQL, migrate, run the demo over HTTP |
| `npm run typecheck` | Type-check web, server, SDK, tests |

## Linking a computer (laptop test connector)

1. In the dashboard: **Agents -> Register agent**. The key is issued immediately and a dialog shows the exact command and a live indicator that flips to *Connected* when the agent authenticates.
2. On the computer you want to link, in this project folder, run the command shown, for example:

```bash
npm run connect -- --url http://localhost:8787 --key asg_xxxxxxxx_...
```

The connector authenticates, sends a heartbeat every 30 s (this is what makes the agent show *online*), and opens a `heimdall>` prompt (`read`, `create`, `update`, `delete`, `send`, `exec`). Every command goes through authorization, approval and the one-time claim, and executes only on the disposable `laptop-sandbox/` folder. It does not read your real files, use the network or run shell commands. Connection states: *Registered, not connected* -> *Connected, no enforcement confirmed yet* -> *Enforcing through adapter* (after the adapter confirms a claim or refusal); *online/idle* reflects the last 15 minutes.

## Using the adapter

```ts
import { GuardianClient, ProtectedExecutor } from "kenuxa-heimdall/sdk"; // src/sdk/index.ts in this repo

const client = new GuardianClient({ baseUrl: "https://guardian.example.com", apiKey: process.env.HEIMDALL_KEY! });

// The handlers are the ONLY code that touches your files / databases / APIs.
const executor = new ProtectedExecutor(client, {
  documents: async (action) => { /* read / create / delete, using action.resource */ },
});

const r = await executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });
// r.status: "executed" | "denied" | "pending_approval" | "execution_failed" | "not_authorized"
```

What the executor guarantees (all covered by tests):

1. Sends the proposed action and gets a decision bound to a **SHA-256 action digest**.
2. Executes only on `allow`, or on `require_approval` after a human approved *that exact action*.
3. Takes a **one-time execution claim** (digest-bound, rechecks agent status, policy version and approval) before running.
4. Runs a deep-frozen snapshot of the action, so arguments cannot change between authorization and execution.
5. Reports the outcome (`succeeded` / `failed` / `refused`). Reports are idempotent and safe to retry; the claim is never retried.
6. **Fails closed**: timeouts, malformed responses, 5xx, an unreachable service or a lost claim response all produce `not_authorized` and the tool does not run.

**Fast path (does not slow agents down).** Pass `{ fastPath }` to the executor and routine actions are decided in-process from the
signed policy: about 9 µs per call at the median, no network on the agent's path. Only `require_approval` actions wait, for a
person. Decisions are synced in the background and re-checked by the service. On by default in the MCP integration. Measurements,
how it stays current, and the trade-offs against strict online mode: [docs/FAST-PATH.md](docs/FAST-PATH.md).

## Executor, companion and Protection Center

- **Supported integration: MCP.** `npm run mcp` starts a Model Context Protocol server whose tools (read, write summary, delete, send, run command) are authorized by the service and executed only by the **trusted executor** against one protected folder. The agent never gets a path, handle, credential or network route. See [docs/MCP-INTEGRATION.md](docs/MCP-INTEGRATION.md) and the boundary in [docs/EXECUTOR-BOUNDARY.md](docs/EXECUTOR-BOUNDARY.md).
- **Automatic device setup.** The dashboard asks “Add this device?”; one click adds the browser, turns on push notifications and it works from then on. The Heimdall app pairs itself: it shows a code, an administrator clicks Add, and it starts protecting and starts at sign-in. No tokens to copy. [docs/DEVICES.md](docs/DEVICES.md).
- **Automatic discovery and protection.** Added computers find Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, agent scripts (LangChain, CrewAI, AutoGen, OpenAI Agents SDK…), local models and automations every 5 minutes, and protect the ones Heimdall can sit in front of with no manual registration. One click in the browser installs the app. [docs/DISCOVERY.md](docs/DISCOVERY.md).
- **Python SDK.** `pip install ./sdk/python[all]`: the same protection for Python agents, with LangChain and OpenAI Agents SDK integrations and the in-process fast path. [sdk/python/README.md](sdk/python/README.md).
- **Slack and email alerts, audit export.** Per-channel severity, retries, signed JSON Lines and CSV exports. [docs/ALERTS.md](docs/ALERTS.md).
- **Windows companion.** `npm run companion` links a computer (one-click pairing, or `enroll` with a token): DPAPI-protected device key, health heartbeats, **native Windows notifications** for incidents (no browser needed), a safe protection test, optional consent-based telemetry, clean uninstall. [docs/COMPANION.md](docs/COMPANION.md).
- **Protection Center.** Six separate layers with status, evidence, last check and exact scope; no global “protected” badge. [docs/PROTECTION-CENTER.md](docs/PROTECTION-CENTER.md).
- **Enterprise sign-in.** Continue with Google, Continue with Kenuxa Account, per-organization OpenID Connect SSO (Okta, Entra ID, Workspace) with DNS-verified domains, authenticator-app two-step verification with recovery codes, organization rules (require MFA, require SSO), Approver and Auditor roles, session management. [docs/ENTERPRISE-AUTH.md](docs/ENTERPRISE-AUTH.md).
- **Fast path.** Routine decisions in-process from the signed policy, audit in the background, policy changes and revocation picked up within 2 s. [docs/FAST-PATH.md](docs/FAST-PATH.md).
- **Cloud outage.** Signed policy bundles let the executor keep enforcing explicitly protected resources from a cache (approvals refused, expiry, rollback protection, synchronized on reconnect). [docs/OFFLINE.md](docs/OFFLINE.md).
- **What was verified and what needs a manual check:** [docs/MANUAL-VERIFICATION.md](docs/MANUAL-VERIFICATION.md) and [docs/EVIDENCE.md](docs/EVIDENCE.md).

## Repository layout

```
src/shared/   policy schema + deterministic engine, action digest, redaction (used by server AND sdk)
src/server/   Hono API, services (auth, orgs, agents, credentials, policies, authz, approvals), retention
src/sdk/      GuardianClient + ProtectedExecutor (prepare/verify/execute, offline fallback)
src/executor/ trusted executor: fs-guard, egress, fast path, offline cache, status, local test authority
src/integrations/mcp/  the MCP server
src/companion/        Windows companion (notifications, health, selftest, startup)
src/web/      React dashboard (Vite)
migrations/   plain SQL migrations (schema_migrations table)
demo/         disposable fixtures, controlled executor, runnable demo
tests/        policy engine, access control, enforcement, fast path, end-to-end, real-PostgreSQL runners
bench/        overhead benchmark (fast path vs online path)
examples/     example policy documents (JSON)
docs/         API, policies, threat model, deployment, limitations, roadmap
```

## Documentation

- [API reference](docs/API.md)
- [Fast path: protection without slowing agents](docs/FAST-PATH.md)
- [Enterprise sign-in: Google, Kenuxa Accounts, organization SSO, two-step verification, roles](docs/ENTERPRISE-AUTH.md)
- [Python SDK, LangChain and OpenAI Agents SDK](sdk/python/README.md)
- [Adding devices automatically](docs/DEVICES.md)
- [Automatic discovery and protection of AI tools](docs/DISCOVERY.md)
- [Alerts to Slack and email, audit export](docs/ALERTS.md)
- [Policy format, precedence and examples](docs/POLICIES.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Deployment, environment variables, backups, costs](docs/DEPLOYMENT.md)
- [Known limitations](docs/KNOWN-LIMITATIONS.md)
- [Roadmap](docs/ROADMAP.md)

## Technology choices (and why)

- **TypeScript, Hono, React + Vite, PostgreSQL** (`pg`; PGlite for zero-install development/tests). One process serves API and dashboard.
- **Plain SQL migrations + parameterized queries** instead of an ORM: the schema uses composite foreign keys so the *database* refuses cross-organization references.
- **Authentication is implemented in-house** (scrypt password hashing, server-side sessions stored as SHA-256 hashes, HttpOnly SameSite cookies, CSRF header + Origin check). This is a deliberate deviation from "use a maintained auth library": it keeps the dependency surface and cost at zero, and the behaviour is covered by tests. It has no email verification, password reset, MFA or SSO. Before real customers, consider moving to a maintained solution (for example Better Auth) or an identity provider.
- **Zod** validates every API input and the policy document format.
- No paid services are required. The core works without any AI-model API.
