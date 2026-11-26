# Protection Center

Six separate layers, each with a status, evidence, last check, exact scope and "what this does not cover". **There is no global "Everything protected" badge**: the API response has no overall field (a test asserts this) and the page says so. The setup checklist is labelled *setup progress*, not protection.

Statuses: **Enforcing**, **Observing only**, **Setup required**, **Degraded**, **Unsupported**, **Not protected**.

| Layer | Evidence used | Enforcing when | Degraded / Not protected when |
| --- | --- | --- | --- |
| Connected AI tool enforcement | agent connection state, adapter-confirmed claim/refusal timestamps | an SDK agent in enforce mode had a claim/refusal confirmed and was seen in the last 15 min | previously enforcing but not seen for 15 min -> Degraded; only monitor/event-only/no claim yet -> Observing only; registered but never connected -> Setup required |
| Supported protected folders/resources | executor self-report (`/v1/executor/report`): protected roots, report age | a fresh report from an enforce-mode agent that has a policy | stale report, or no policy (everything denied) -> Degraded; monitor mode -> Observing only; none -> Setup required |
| Supported outbound destinations | executor egress attestation + approved domains in the agent's policy | a running executor with egress enabled (scope lists the approved domains) or egress disabled (all transfers refused) | no running executor -> Setup required. Always states that other programs' traffic is not controlled |
| Enrolled device health | companion heartbeat, executor status file | heartbeat < 3 min and executor `running` | executor missing/stale or heartbeat 3-15 min -> Degraded; > 15 min or revoked -> **Not protected** ("No endpoint enforcement is claimed") |
| Desktop notification delivery | `ToastNotifier.Setting` reported by the device, delivery records | Windows reports `enabled` on every active device | disabled/DND/stale -> Degraded with the reason; protection is stated to be unaffected |
| Operating-system security status | Windows Security status, **only with on-device consent** | never "Enforcing": healthy -> **Observing only** | real-time protection off or old signatures -> Degraded; not consented -> Setup required; non-Windows -> Unsupported |

Executor attestations are **evidence, not proof** (the executor reports on itself); that is why the UI also shows the adapter-confirmed enforcement timestamps and how recent each piece of evidence is.

Onboarding (computed from the above): select resources -> connect an agent -> verify its executor -> enroll a device -> enable notifications -> run the safe protection test (a queued device command whose result the companion posts back).

API: `GET /api/orgs/:orgId/protection`, `GET/POST /devices`, `POST /devices/:id/commands` (`selftest` | `test_notification`), `POST /devices/:id/revoke`, `GET /incidents` (dashboard notifications).
