# Evidence (this machine, 19 Oct 2026)

Baseline reproduced first: typecheck clean, 76 tests passing, before any change in this increment.

## Automated results
| Run | Result |
| --- | --- |
| `npm run typecheck` | clean |
| `npm test` (embedded PostgreSQL / PGlite) | **138 / 138** passed in 10 files |
| `npm run test:pg` (real PostgreSQL 18 server, `pg` driver) | **138 / 138** passed |
| `npm run smoke:prod` (built bundle, production config validation, `npm run migrate`, `/readyz`, demo over HTTP, retention CLI, signing key served, device API auth) | PASSED |

New test files: `executor.test.ts` (17: file/path attacks incl. a **real NTFS junction**, hard link, file swap, egress against local receivers, command refusal, trusted classification), `mcp.test.ts` (4: **real stdio MCP client ↔ real server ↔ real HTTP**, disk observed from the test process, **spawn-trap preload** proving no subprocess), `offline.test.ts` (8), `devices.test.ts` (15: enrollment, notifications, Protection Center states, bundles, offline-sync), `companion.test.ts` (14, **4 against the real Windows APIs**), plus classification tests in `policy-engine.test.ts`.

## Side-effect assertions for blocked operations (observed, not reported)
- Unauthorized deletion: `snapshot(root)` before/after is identical; the outside file still exists (`executor.test.ts`).
- Unapproved upload: a local HTTP receiver counts **0 requests** for unapproved, look-alike (`partner.example.com.evil.test`, `evilpartner.example.com`), credentialed (`partner.example.com@evil…`, `user:pw@…`), IP-literal, private-DNS and redirecting destinations; the approved destination produces exactly 1 request with the file body (so the test is not vacuous).
- Redirect: the decoy receiver behind a `302` receives **0 requests**.
- Command execution: `run_command` is refused; with `NODE_OPTIONS=--require spawn-trap.cjs` in the executor process, the trap file is never created (no `spawn/exec/fork` call happened).
- Junction `docs/linked -> outside/`: read refused with `EXECUTOR_PATH_ESCAPES_ROOT|REDIRECTED`; the outside file is unchanged and its content never appears in any result.
- Swapped file between authorization and use: the executor refuses (`EXECUTOR_REFUSED_RESOURCE_CHANGED`) and the replacement file is **not** overwritten.

## Real Windows evidence
1. **Notification history (OS-level).** After the live run, Windows' own history for the companion's app identity listed the toasts it accepted:
   ```
   windows toast history (real AUMID): [ 'alert-640f107f', 'alert-5d4b9542', 'executor-missing', 'enrolled' ]
   setting: enabled
   ```
   (`ToastNotificationManager.History.GetHistory('Kenuxa.Heimdall.Companion')`.) Two `alert-…` toasts correspond to two real incidents (`run_command` denied, restricted transfer denied) created by the live MCP run.
2. **Not obtained: a visual capture of a toast pop-up.** Both attempts captured the screen while a full-screen video was playing and, later, the Windows lock screen; Windows does not pop toasts in those states (they go to the Action Center). Those screenshots were deleted (they contained unrelated personal content). Use MANUAL-VERIFICATION.md procedure A/B to capture one on an unlocked desktop.
3. **DPAPI**: the device key in `%LOCALAPPDATA%\KenuxaHeimdall\companion.json` is a DPAPI blob (`AQAAANCMnd8…`); the file contains no `hdv_` string.
4. **Run key round trip** (real HKCU): value added -> listed -> removed; the set of Run values before and after is identical.
5. **Windows Security status** was read on this machine (`RealTimeProtectionEnabled: True`, `AntivirusEnabled: True`, signatures 0 days) as observation only.

## Live run against the running server (PROCUS organization)
Real companion enrolled (`npm run companion -- enroll`), real MCP stdio server and client (`scripts/live-mcp.ts`):
```
OK             read_document          -> EXECUTED
OK             write_summary          -> EXECUTED
OK             delete_document        -> WAITING FOR HUMAN APPROVAL   (observed on disk: old-notes.txt still present = true, unchanged = true)
REFUSED/FAILED read_document ../secrets.txt -> REFUSED (INVALID_RESOURCE)
REFUSED/FAILED send_document (evil.example.net, restricted) -> REFUSED (EXPLICIT_DENY)
REFUSED/FAILED run_command            -> REFUSED (EXPLICIT_DENY)
```
Then the Protection Center (screenshots `docs/evidence/protection-center-*.jpg`) read: Connected AI tool enforcement **Enforcing**, Protected folders **Enforcing** (1 root, executor attested 11 s earlier), Outbound destinations **Enforcing** (external transfers disabled: all refused), Enrolled device health **Enforcing**, Desktop notification delivery **Enforcing** ("2 shown"), Operating-system security status **Setup required** (not consented). The safe protection test was queued **from the dashboard UI**, executed by the real companion, and returned all checks passing (6 of 6 setup steps verified). The in-app browser reported `Notification.permission = "denied"`, which the page showed as "Blocked in browser settings".

## Not verified here (see MANUAL-VERIFICATION.md)
Visual toast capture; a real reboot/sign-in; toggling real Windows notification settings or Focus assist; browser notification permission granted; a physically powered-off laptop; the real `uninstall` on the live enrollment; Docker image / `render.yaml` / backup restore (no Docker or pg_dump here).

## Official documentation consulted
- Windows notifications overview — https://learn.microsoft.com/en-us/windows/apps/develop/notifications/ : recommends `AppNotificationManager` (Windows App SDK) for unpackaged apps; `ToastNotificationManager` is the UWP/WinRT API that "may work in some desktop scenarios". **Deviation:** no .NET SDK was available, so the companion uses `ToastNotificationManager` via PowerShell 5.1 with a registered AppUserModelID (documented in COMPANION.md as the thing to replace).
- Windows push notifications — https://learn.microsoft.com/en-us/windows/apps/develop/notifications/push-notifications/ : WNS needs an Azure/Entra app registration and the Windows App SDK; app notifications can be push or local. **Not used** (local notifications from the companion; push is planned).
- PWA offline and background operation — https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/Guides/Offline_and_background_operation : service workers may run while the app is closed and be restarted by the browser, but push requires the Push API with VAPID, every push must show a notification, and the page does not promise execution after the whole browser exits. **Consequence:** the dashboard uses a service worker only to display notifications for a loaded page; closed-browser delivery is the companion's job.
- `ServiceWorkerRegistration.showNotification()` — https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerRegistration/showNotification : needs a secure context, granted permission and an active worker; `tag` replaces notifications with the same tag. **Used:** `tag = alert-<id>` so one alert never stacks twice.


## Fast path increment (25 Nov 2026, Linux container, Node 22.23)

| Run | Result |
| --- | --- |
| `npm run typecheck` (server config) and `tsc -p tsconfig.server.json` build | clean |
| `npm test` (embedded PostgreSQL / PGlite) | **148 passed, 4 skipped** (Windows-only) in 11 files |
| `npm run test:pg` | not run here: the container lacks `libicuuc.so.60` for embedded PostgreSQL. Run it on the Windows machine |
| `npx tsx bench/fast-path.bench.ts` | fast path 8.8 µs p50 / 37 µs p99 per `executor.run()`; online path 153.6 µs p50 / 23.66 ms p99 in-process (no network) |

New tests: `fast-path.test.ts` (13): zero network calls on the caller's path for allow and deny; one batched sync for four records,
stored as `local_fast` and re-evaluated with no mismatch; one-time execution per request id; keeps deciding with the service down and
sends the backlog after; refuses when the audit queue is full (the file is not written); approval-required actions go to the service,
wait, then run once after approval; a new policy version applies on refresh and on the policy-state check; a revoked key or agent drops
the bundle; an expired bundle is never used; tampered, foreign and rolled-back bundles are refused; a forged `local_fast` record raises a
high-severity alert; monitor mode; per-process budget accepted by the server. `mcp.test.ts` (+1): over real stdio and HTTP, with the
fast path on, a policy change and a key revocation take effect within the check interval and approvals still wait for a person.

Also fixed: on Linux a deleted file's inode number is reused at once, so a file swapped between authorization and use could match a
`device:inode` identity. The identity now includes the file's creation time (or change time where none is reported). The two
executor swap tests that failed on Linux now pass.

## Enterprise sign-in increment (25 Nov 2026, Linux container, Node 22.23)

| Run | Result |
| --- | --- |
| `npm run typecheck` (both configs) | clean |
| `npm test` (embedded PostgreSQL / PGlite) | **162 passed, 4 skipped** (Windows-only) in 12 files |
| `vite build` and server build | clean |
| Built server in a real browser (Chromium) | sign-in page with Google, Kenuxa and organization SSO buttons and an SSO error; Security page with authenticator QR code, sessions table and owner controls |

New tests: `enterprise-auth.test.ts` (14), through the real HTTP app with fake identity providers that sign real RSA tokens and check
PKCE: RFC 6238 test vectors; enrolment and sign-in with a code; a code accepted once; recovery codes accepted once; five wrong
codes end the pending sign-in; required MFA (owner must have it first, members blocked until they step up, cannot turn it off
while required); Approver and Auditor permissions; session list, sign-out of one device and of all others; Google first sign-in,
return by subject, linking a verified email to an existing account; Google refusals (unverified email, wrong nonce, wrong
audience, expired token, signature from another key, replayed state); authenticator still required after Google unless the ID
token reports MFA; Kenuxa sign-in through the code + PKCE exchange and Supabase verify, with the Supabase session signed out;
Kenuxa refusals (unconfirmed account, a code redeemed with another sign-in's PKCE secret); organization SSO needs a
DNS-verified domain, adds first-time users with the default role, refuses addresses outside its domains, a verified domain
cannot be claimed by another organization; required SSO refuses members' password sessions and keeps owners' break-glass access.

Found and fixed while testing: a wrong two-step code was counted inside a transaction that the error then rolled back, so the
five-attempt lockout never triggered. Failed attempts are now committed before the error is returned.

Not verified here: the live Google and Kenuxa projects (no credentials in this environment). Follow the checks in
ENTERPRISE-AUTH.md once with the real ones.
