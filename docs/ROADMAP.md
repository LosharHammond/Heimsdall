# Roadmap (prioritized; nothing below is implemented)

## Before the first paying customer (hardening of the first release)
1. Deploy once to a real host, run `npm run demo` against it, and perform a **backup restore drill**.
2. Authentication: email verification, password reset and invitation emails (needs an email provider); SAML and SCIM; passkeys. (MFA, Google, Kenuxa and OIDC SSO, session list/revoke: done.)
3. Reconcile "claimed, no outcome" actions. (Slack and email alerts, signed audit export, Python SDK with LangChain and OpenAI Agents SDK, one-click device setup with Web Push: done.) Next: Microsoft Teams and PagerDuty alerts, native mobile apps.
4. Shared rate limiter (Postgres or Redis) if running more than one instance; batch `last_seen` writes.
5. Independent review of the policy engine and claim transaction; load test the authorize/claim path.

## Done since the first release (see docs/)
- Real MCP integration with a trusted executor; Windows companion (notifications, health, safe test); signed offline policy cache; Protection Center.
- Enterprise sign-in (Nov 2026): Google, Kenuxa Accounts, per-organization OIDC SSO with DNS-verified domains, TOTP two-step verification with recovery codes, required-MFA / required-SSO organization rules, Approver and Auditor roles, session management. [ENTERPRISE-AUTH.md](ENTERPRISE-AUTH.md).
- Fast path (Nov 2026): in-process decisions from the signed policy (about 9 µs per call), background batched audit with server re-evaluation, 2 s policy-state check. [FAST-PATH.md](FAST-PATH.md).

## Next, in order
1. Rebuild the companion as a signed .NET app using AppNotificationManager (Windows App SDK) with an installer; keep the PowerShell path only as a fallback.
2. A real reboot/sign-in test, a Focus-assist-aware notification mode, (Web Push for browsers: done.)
3. Content-aware classification (a supported inspection mechanism) and DLP hooks in the executor.
4. OS-enforced containment (minifilter/AppContainer) for the protected folder, evaluated as a separate security project.

## Phase 2
- One real supported agent-framework integration (pick the framework your first customers use) built on the existing SDK.
- Optional AI-model gateway (inspects model traffic routed through it; still not enforcement for tools outside it).
- Destination controls: real egress executor that connects only to the validated host, no cross-host redirects, post-DNS private-address blocking.
- Configurable alert delivery (email, chat webhooks). Expanded organization administration (invitations, teams, API audit export).
- Optional AI-written *explanations* of decisions. They must never grant permissions or override a denial.

## Phase 3
- Optional Windows endpoint guard with **explicit enrollment**, per-device identity, secure updates and credential rotation.
- Carefully scoped process/activity telemetry; **detect and warn before any automatic blocking**.
- A process name alone is not reliable proof that software is an AI agent. The guard must report a *confidence level* and its visibility limits (it only sees what the enrolled device exposes; it cannot see other devices or the network).

## Phase 4
- Billing and plans. Linux and macOS support. Scale-out (shared limiter, read replicas, partitioned event tables). Additional integrations.
- Independent security assessment.
