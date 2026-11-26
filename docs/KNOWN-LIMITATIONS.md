# Known limitations

Product scope
- Protects only tools executed through the adapter/controlled executor. A compromised or non-integrated application is not protected.
- Only one integration exists: the TypeScript SDK (plus event-only reporting). No other agent frameworks, no AI-model gateway.
- No automatic discovery of AI agents, devices or networks. No endpoint software, antivirus, kernel drivers or packet inspection.
- External transfers are policy-evaluated; the demo executor *simulates* delivery into a local folder. No network I/O is performed by any shipped executor.
- Data classification, tool names and destinations are as declared by the adapter; the platform cannot verify them.
- Alerts go to the dashboard, Slack, email and added browsers ([ALERTS.md](ALERTS.md), [DEVICES.md](DEVICES.md)). No SMS, Teams or PagerDuty yet. Email needs your own SMTP server (`SMTP_URL`).
- No billing, plans or usage metering. No machine-learning detection or risk scores (all numbers are counts of recorded events).

Fast path ([FAST-PATH.md](FAST-PATH.md))
- Policy changes and revocation apply within the policy-state check interval (default 2 s), not on the very next call. Use `HEIMDALL_FAST_PATH=0` where that matters.
- Action budgets and one-time permits are per process. Duplicate request ids across processes are flagged when synced, not prevented.
- Audit records still queued when a process is killed without `stop()` (at most about 250 ms of activity) are lost.
- The in-memory bundle is as trustworthy as the process holding it: someone who controls the agent's process can bypass any in-process check. Server re-evaluation of every synced record detects a tampered decision after the fact; it does not prevent it.

Security and accounts
- Authentication: two-step verification (authenticator app), Google, Kenuxa Accounts and per-organization OIDC single sign-on, and session management are built ([ENTERPRISE-AUTH.md](ENTERPRISE-AUTH.md)). Not yet: SAML, SCIM, passkeys, email verification for password sign-ups, password reset and invitation emails (members must have an account first, or sign in once through organization SSO).
- Sign-up reveals whether an email is registered (409).
- Rate limiting is in memory (per process).
- The audit log is application-append-only (UPDATE blocked by a trigger); it is not tamper-proof against database administrators. Retention deletes old rows by design.
- Redaction is pattern-based and can miss unknown secret formats.
- Deleted-by-retention action history also removes the approvals/outcomes tied to it.
- No independent security assessment.

Operations
- Backup/restore procedure is documented but **not tested** here. Docker image and `render.yaml` are **not built/deployed/verified**.
- No metrics/tracing export; logs are structured JSON on stdout only.
- Credential "last used" and agent "last seen" update on each request (a write per call); at high volume this should be batched.
- Claims that are taken but never followed by an outcome show as "Outcome missing" after 10 minutes; there is no automatic reconciliation.
- The `repeated_denials` and budget alerts are simple threshold rules (10 denials in 5 minutes; policy budget), not behavioural analytics.
- Revoked-credential alerts are not labelled as demonstration activity (the credential carries no demo flag).
- Request-destination strings with an embedded `user@host` are shown redacted (`[REDACTED:email]`) in the dashboard, so the exact attempted string is not retained.
- The `connection` filter on the agent list is applied after pagination (page-local), because connection state is derived.
- Mobile layout was checked only through the in-app browser's emulation.

Executor, companion, offline (added)
- The executor is not an OS sandbox. A process with direct file/network access bypasses it; Windows has a tiny residual race window (no O_NOFOLLOW).
- Only one MCP integration exists. Other agent frameworks are not integrated.
- External transfers default to OFF in the MCP server (HEIMDALL_EGRESS=1 enables them); the egress guard was tested against local receivers with a mapped resolver, never against real internet destinations.
- The Windows companion drives ToastNotificationManager through PowerShell 5.1 with a registered AppUserModelID. Microsoft recommends AppNotificationManager (Windows App SDK) for unpackaged apps; no .NET SDK was available to build it. Focus assist / Do Not Disturb cannot be queried. Toasts are not visible on the lock screen or over some full-screen apps (they go to the Action Center).
- A visual capture of a toast pop-up was not obtained (screen locked or full-screen video during the runs). OS-level acceptance was verified through the Windows notification history for the app identity.
- Web Push reaches an added browser while that browser is running (it cannot wake a browser that is fully closed); production needs HTTPS. Delivery was tested with a fake push service and a headless browser; delivery through real Chrome/Firefox/Safari push services needs a manual check on a deployed HTTPS address. No native iOS/Android app yet (phones use the browser path).
- The Python SDK's fast path defers destinations that need IDN/IP normalization to the server (a network round-trip) rather than risk deciding differently from the service.
- The companion starts after the user signs in only (HKCU Run). A reboot was not performed in this environment.
- Revocation cannot reach an offline executor until its signed bundle expires (default 4 h). Offline budgets are approximate.
- Policy-signing key pinning is trust-on-first-use unless HEIMDALL_POLICY_PUBKEY is set.
- Optional OS-security status and process-name inventory are observation only, consent-based and weak evidence; Heimdall is not an antivirus replacement and has not been tested as one.
- Data classification inspection (content scanning) does not exist: classification comes from policy metadata or, in legacy policies, the untrusted agent declaration.

- Automatic discovery ([DISCOVERY.md](DISCOVERY.md)) protects MCP tool servers and Claude Code; other agents are found and flagged but cannot be blocked without the SDK. The packaged Windows app was built and exercised on Linux (same code path); a Windows build (`npm run build:installer`) and a run on a real Windows PC with Claude Desktop installed still need a manual check. The app is unsigned until you sign it with your own certificate.
