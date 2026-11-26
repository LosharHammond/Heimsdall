# API reference

All bodies are JSON. Errors have the shape `{"error": {"code", "message", "details?"}}`. Validation errors (`400`,
`VALIDATION_ERROR`) list `{path, message}` items. Unknown fields are rejected everywhere (strict schemas), including any
client-supplied organization id: **organization scope always comes from the session's membership or the integration key.**

## Two separate surfaces

| Surface | Auth | Purpose |
| --- | --- | --- |
| `/api/*` | Session cookie `asg_session` (HttpOnly, SameSite=Lax, Secure in production) + header `x-asg-csrf: 1` on non-GET + Origin check | The dashboard and administration |
| `/v1/*` | `Authorization: Bearer asg_<prefix>_<secret>` | Integrations (adapter). **Cannot** reach `/api/*`; sessions cannot reach `/v1/*` |

Integration keys carry scopes: `actions` (decisions, claims, outcomes) and `events` (observation reports). Event-only
agents can hold only `events`. A key is bound to one agent in one organization.

Health: `GET /healthz` (process alive), `GET /readyz` (database reachable and migrated; `503` otherwise).

Rate limits (in-memory, per instance): sign-in 8 failures / 15 min per email and 30 / 15 min per IP; sign-up 10 / hour per IP;
`/v1` 600 / min per key and 1200 / min per IP; `/api` 600 / min per user. `429` with `Retry-After`.
Request bodies: `/v1` max 64 KB, `/api` max 256 KB; `args` max 16 KB and bounded depth.

## Integration API (`/v1`)

### `GET /v1/whoami`
Authenticates the key and marks the agent as *seen*. Returns `agent_id, agent_name, scopes, enforcement_mode, policy_assigned`.

### `POST /v1/authorize`  (scope `actions`)
```json
{
  "request_id": "req_0123456789",          // 8-128 chars [A-Za-z0-9_.:-], unique per agent; idempotency key
  "tool": "documents",                      // lowercase name
  "operation": "read",                      // read|create|update|delete|external_transfer|command_execution
  "resource": "docs/handbook.txt",          // logical namespace path; '..', absolute paths, encoded separators are refused
  "destination": "https://partner.example.com/inbox",   // required for external_transfer
  "data_classification": "internal",        // optional, self-declared: public|internal|confidential|restricted
  "args": { "page": 1 },                    // optional structured arguments (stored redacted; digest covers the full value)
  "requested_at": "2026-10-19T12:00:00Z",   // optional
  "demo": true,                             // optional: labels the record a demonstration
  "adapter": { "name": "heimdall-sdk-ts", "version": "0.1.0" }
}
```
Response `200`:
```json
{
  "request_id": "req_0123456789", "action_id": "uuid",
  "decision": "allow",                       // allow | deny | require_approval  (effective decision)
  "policy_decision": "allow",                // what the policy decided (differs from decision only in monitor mode)
  "reason_code": "ALLOWED_BY_RULE", "explanation": "Allowed by rule 'read-docs'.",
  "policy_version": 1, "matched_rule_id": "read-docs",
  "enforcement_mode": "enforce",             // enforce | monitor (monitor = advisory; decision is always allow with reason MONITOR_ONLY)
  "action_digest": "sha256 hex",             // binding for claim; the SDK verifies it equals its own digest
  "decision_expires_at": "...",              // an immediate allow can be claimed for 5 minutes
  "destination_host": "partner.example.com", // server-normalized host; executors must connect only to this host
  "approval": null | { "id", "status": "pending|approved|rejected|expired|used", "expires_at", "grant_expires_at", "required_role" },
  "execution": null | { "status": "claimed|succeeded|failed|refused", "enforcement_confirmed": true },
  "idempotent_replay": false
}
```
- Repeating the same `request_id` with the same action returns the stored decision (`idempotent_replay: true`). With a *different*
  action it returns `409 REQUEST_ID_CONFLICT`. Retrying this call is always safe.
- Credential problems return `401` with `{decision:"deny", reason_code:"CREDENTIAL_INVALID" | "CREDENTIAL_REVOKED"}`; a revoked agent returns `403 AGENT_REVOKED`.
- Any `5xx` means "not authorized": nothing was executed and the adapter must not execute.

### `GET /v1/actions/:requestId`  (scope `actions`)
Same view as above; used to poll an approval.

### `POST /v1/actions/:requestId/claim`  (scope `actions`)
Body `{"action_digest": "<sha256 of the action about to run>"}`. This is the **one-time execution permit**. In a single
transaction it rechecks: agent active, no earlier claim, digest equals the authorized digest, decision not expired,
policy still permits (or: approval approved, unexpired, unused, same policy version and agent assignment), budget.
For approvals it consumes the approval atomically.

`200 {"permitted": true}` or a refusal `403/409` with `reason_code`: `NOT_AUTHORIZED, ALREADY_CLAIMED, DIGEST_MISMATCH,
AUTHORIZATION_EXPIRED, APPROVAL_PENDING, APPROVAL_REJECTED, APPROVAL_EXPIRED, APPROVAL_ALREADY_USED, APPROVAL_POLICY_CHANGED,
AGENT_REVOKED`, or any policy reason code (policy changed since authorization). **Never retry a claim**: a retry returns
`ALREADY_CLAIMED`, and an uncertain claim must fail closed.

### `POST /v1/actions/:requestId/outcome`  (scope `actions`)
Body `{"status": "succeeded|failed|refused", "error_code?": "...", "detail?": {}}`.
`succeeded`/`failed` require an existing claim; `refused` means the executor did **not** run the action (this is what turns a denial
into "Blocked (confirmed)"). Idempotent for the same status, `409 OUTCOME_CONFLICT` otherwise. Safe to retry.

### `POST /v1/events`  (scope `events`)
Observation only: `{"event_id?", "event_type", "tool?", "operation?", "resource?", "summary?", "occurred_at?", "demo?"}`.
`event_id` makes retries idempotent. Never creates a decision and is never displayed as "blocked".

## Dashboard API (`/api/*`) summary

Roles: **viewer** read-only; **admin** agents, policies, credentials, approvals, alerts, audit; **owner** also organization settings and members.
`:orgId` in the path only *selects* an organization the session user is a member of; a non-member always gets `404`.

| Method & path | Role | Notes |
| --- | --- | --- |
| `POST /api/auth/register`, `/login`, `/logout`; `GET /api/auth/me` | - | password >= 12 chars |
| `POST /api/orgs`, `GET /api/orgs/:orgId`, `PATCH /api/orgs/:orgId` | any / viewer / owner | timezone (default `Africa/Accra`), retention |
| `GET /overview?hours=` | viewer | every figure counted from stored rows |
| `GET/POST /members`, `PATCH/DELETE /members/:userId` | viewer / owner | last owner protected |
| `GET/POST /agents`, `GET/PATCH /agents/:id`, `POST /agents/:id/revoke` | viewer / admin | filters: `q, environment, status, connection, page, limit` |
| `GET/POST /credentials`, `POST /credentials/:id/revoke`, `POST /credentials/:id/replace` | viewer / admin | the secret is returned once in the create/replace response |
| `GET/POST /policies`, `GET/PUT /policies/:id`, `POST /policies/simulate` | viewer / admin | PUT creates a new version only if the document changed; simulate is a dry run |
| `GET /actions`, `GET /actions/:id`, `GET /observations` | viewer | filters: `q, agent_id, decision, operation, state, demo, page, limit` |
| `GET /approvals?status=`, `POST /approvals/:id/approve`, `/reject` | viewer / admin (or owner if the rule requires it) | |
| `GET /alerts`, `POST /alerts/:id/acknowledge`, `/resolve` | viewer / admin | |
| `GET /audit?q=` | admin | |
| `GET /api/policy-examples` | signed in | |

Action `state` values: `blocked_confirmed, executed, execution_failed, claimed, claimed_no_outcome, denied_unconfirmed,
awaiting_approval, approved_unused, approval_rejected, approval_expired, authorized_not_executed`.

## Sign-in, two-step verification, sessions and organization security

Listed in [ENTERPRISE-AUTH.md](ENTERPRISE-AUTH.md#endpoints). `POST /api/auth/login` now answers `{mfa_required: true}` (and sets a
short-lived pending cookie instead of a session) when the account has two-step verification. Organization routes can answer
`403 MFA_REQUIRED` or `403 SSO_REQUIRED` when the organization's sign-in rules are not met by the current session.
Roles: `owner`, `admin`, `approver`, `auditor`, `viewer`.

## Additional endpoints (executor, offline, devices)

Agent key (`actions` scope):
- `GET /v1/policy-bundle` -> `{bundle, signature}` signed policy bundle (503 if the server has no `POLICY_SIGNING_KEY`).
- `POST /v1/executor/report` `{roots:[{label,prefix}], egress_enabled, mode, cache_expires_at?, queued_events}` — the executor's self-report (evidence only).
- `GET /v1/policy-state` -> `{policy_id, policy_version, enforcement_mode}`. A few bytes; fast-path executors poll it (default every 2 s) to pick up policy changes. 401/403 for a revoked key or agent.
- `POST /v1/offline-sync` `{records:[{request_id, action, action_digest, decision, reason_code, policy_version, decided_at, outcome, source?}]}` — up to 500 records and 4 MiB per request; idempotent by `request_id`. `source` is `offline_cache` (default: decided while the service was unreachable) or `local_fast` (decided in-process by the fast path). Every record is re-evaluated against the policy version it names; a disagreement raises a high-severity `offline_decision_mismatch` alert. A local `BUDGET_EXCEEDED` denial is accepted (budgets are counted where the decision is made).
Public: `GET /v1/signing-key` -> `{key_id, public_key_pem}`.

Device key (`hdv_…`, separate namespace; cannot call agent endpoints):
- `POST /v1/device/enroll` (enrollment token, single use) -> `{device_id, device_key, policy_signing_key}`.
- `POST /v1/device/heartbeat` (companion version, executor state, notification state, cloud/cache state, consent flags, optional consented telemetry) -> `{commands:[…]}`.
- `GET /v1/device/notifications` -> `{total, show:[≤3], coalesce_ids:[…]}`; `POST /v1/device/notifications/ack` `{items:[{alert_id,state}]}`.
- `POST /v1/device/commands/:id/result`; `POST /v1/device/unenroll`.

Dashboard (session): `GET /protection`, `GET|POST /devices`, `GET /devices/:id`, `POST /devices/:id/revoke`, `POST /devices/:id/commands`, `GET /incidents?since=`. Roles: viewers read; administrators change.
