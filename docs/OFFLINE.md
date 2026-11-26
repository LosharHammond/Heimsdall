# Cloud outage and offline operation

Three components are kept separate: the **cloud control plane** (this service), **local enforcement** (the executor in front of the protected folder) and **user-facing notifications** (the Windows companion). An outage of one must not silently disable or over-block the others.

## Policy cache strategy (executor)

| Situation | Behaviour |
| --- | --- |
| Service reachable | Every decision is made online. The executor refreshes an **Ed25519-signed policy bundle** in the background (on start, then every ~5 minutes) and flushes any queued offline records. |
| Service **unreachable** (network error, timeout, 5xx) | The executor decides from the cached bundle with the **same deterministic engine**. Explicit deny, default deny and allow rules behave exactly as online. |
| Action needs a human approval | **Refused** (`APPROVAL_REQUIRED`, recorded as a policy `require_approval` decision). A pending approval never becomes an allow. |
| Service answers 401/403/409/400 | That is a *decision* (revoked key, wrong scope...), **not** an outage: no offline fallback. |
| Bundle missing, bad signature, wrong agent/org, expired, or older than one already accepted | The executor refuses everything routed through it (`OFFLINE_NO_CACHE / BAD_SIGNATURE / WRONG_BINDING / EXPIRED / ROLLBACK`) and reports degraded protection. Unrelated computer activity is not affected: only calls through the executor are. |
| Offline record queue full | The executor refuses to act (it will not run what it cannot record). |

### Bundle
`GET /v1/policy-bundle` returns `{bundle, signature}`. The signature covers the canonical JSON of the whole bundle: `v, key_id, org_id, agent_id, policy_id, policy_version, document, enforcement_mode, issued_at, expires_at`. Validity is `POLICY_BUNDLE_TTL_MINUTES` (default 240).
- **Pinning:** the executor pins the signing key on first contact (TOFU) or from `HEIMDALL_POLICY_PUBKEY`; compare the key id printed at enrollment with the one in the dashboard.
- **Rollback:** the executor persists the highest `(policy_id, policy_version, issued_at)` it accepted and refuses lower versions, from the network or from a replayed cache file.
- **Atomicity:** cache files are replaced atomically; a one-time local permit (exclusive file create) per request id prevents a second offline execution.

### Reconnect
Offline decisions are stored in a bounded, redacted outbox and sent to `POST /v1/offline-sync` (idempotent by `request_id`). The server marks them `source = offline_cache` (the dashboard shows an **Offline** badge) and **re-evaluates each one against the policy version it claims to have used**; a disagreement raises a high-severity `offline_decision_mismatch` alert.

### Stated limits
- **Revocation cannot reach an offline executor.** A revoked agent keeps working offline until its bundle expires (≤ `POLICY_BUNDLE_TTL_MINUTES`). Choose a short TTL if that matters; online executors are refused immediately. (Tested and documented as a limit.)
- **Policy edits** reach offline executors only on their next refresh (or at the next bundle).
- **Budgets** are approximated offline from local records only.
- Someone who can write the cache directory can delete the rollback marker or the outbox. The directory must be private to the signed-in user; this is not a defence against a local administrator.

## Companion during an outage
After three failed heartbeats the companion shows **one** local notice ("Heimdall can't reach the cloud: protected tool calls continue from the signed policy cache; approvals can't be granted") and re-arms only after a successful heartbeat. When the executor reports an expired cache it shows one "policy cache expired" notice. Alerts queued in the cloud are delivered after reconnect with de-duplication (see COMPANION.md).

## Laptop off
No endpoint enforcement or immediate display is claimed. The Protection Center marks the device **Degraded** after 3 minutes without a heartbeat and **Not protected** after 15 ("No endpoint enforcement is claimed") and a `device_offline` alert is raised. Independently hosted integrations keep working; alerts wait in the cloud and are delivered when the companion returns.
