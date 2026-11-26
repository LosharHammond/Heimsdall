# Acceptance conditions: what was verified here, and exact manual procedures

Legend: **V** verified by an automated test or a real run on this Windows 11 machine · **M** requires the manual procedure below (could not be performed in this environment) · **P** planned.

Environment of the automated/real runs: Windows 11 (10.0.26100), Node 24, real PostgreSQL 18 (embedded-postgres) and PGlite, real Windows PowerShell 5.1, real DPAPI/registry/toast APIs, an in-app Chromium for the dashboard. The development machine's screen was **locked / showing a full-screen video** when toasts were fired, so a *visual* capture of a toast pop-up was **not** obtained; Windows' own notification **history** for the app identity was used as OS-level evidence instead (see EVIDENCE.md).

| # | Condition | Status | How it was verified / what remains |
| --- | --- | --- | --- |
| 1 | Dashboard open: controlled denied action -> confirmed incident + one Windows notification | **V** (native path) / **M** (browser path) | A denied `run_command` raises a high-severity alert; the real companion showed one toast per incident (`alert-…` tags in Windows' history for the app identity; tests assert exactly one toast and no repeats). The in-dashboard browser notification is implemented (service worker `showNotification`) but the in-app browser reported permission `denied`, so it was **not** exercised: use procedure A. |
| 2 | Dashboard minimized | **M** | Same two paths; procedure A with the window minimized. |
| 3 | Dashboard tab closed | **V** (companion) | Companion delivery has no browser dependency (tests run with no browser at all; live run unaffected by the dashboard). Browser notifications are **not** delivered when the tab is closed (no Web Push): stated in the UI. |
| 4 | Browser fully exited | **V** (companion) / **M** live | As 3; for a live confirmation follow procedure B. |
| 5 | After reboot and sign-in | **M** | The per-user Run entry round trip is verified on the real registry (set, read, remove, other entries unchanged). A real reboot was not performed: procedure C. Before sign-in **nothing** runs (HKCU Run only). |
| 6 | Notifications denied / Do Not Disturb | **V** (logic, simulated Windows settings) / **M** (real toggle) | Suppression is recorded, explained, never bypassed; enforcement unaffected. Real Windows `Setting` was read (`enabled`). Toggling the user's real notification settings was not done: procedure D. Windows exposes no supported Focus-assist query. |
| 7 | Cloud offline | **V** | `tests/offline.test.ts`, MCP mid-session outage test, companion degraded-notice test. |
| 8 | Laptop off | **V** (server-side states) | Stale heartbeat -> Degraded -> Not protected; hosted agent authorization unaffected; no immediate display claimed. A physically powered-off laptop was not tested. |
| 9 | Reconnect: de-duplicated, no storm | **V** | 9-incident backlog -> 3 toasts + 1 summary, all acknowledged; cooldown re-announcement test. |
| 10 | Unauthorized deletion/upload/command: no side effect | **V** | Disk observed by the test process; local receiver counts requests; spawn-trap preload proves no subprocess. |
| 11 | Replay/tamper/expiry/revocation/duplicates | **V** | Concurrent claim tests, digest mismatch, approval expiry/replay, policy change, revoked key. |
| 12 | Cross-organization isolation (alerts, subscriptions, policies, approvals, devices) | **V** | `tests/access.test.ts`, `tests/devices.test.ts`. |
| 13 | Stopped companion / stale heartbeat / missing executor / unprotected resource | **V** | Protection Center state tests. |
| 14 | Uninstall / removal: revoke credentials, remove only app-owned config | **V** | Fake-Windows tests + real registry before/after listing; the real `uninstall` was not run on the live enrollment (it would remove it): procedure E. |

## Manual procedures

**A. Browser notification (dashboard open / minimized).** In a normal browser signed in as an administrator: Protection Center -> *Browser notifications* -> **Enable** -> allow the prompt (Windows: Settings > System > Notifications must allow your browser; Focus/Do Not Disturb off). Then trigger an incident: `npx tsx scripts/live-mcp.ts "%USERPROFILE%\HeimdallProtected"` (it calls `run_command`, which is denied). Within ~15 s one notification titled *Heimdall: high-risk incident* should appear. Repeat with the window minimized. Take a screenshot of the toast/Action Center and note the time.

**B. Companion with no browser.** Quit the browser completely (check Task Manager). Run `npm run companion -- run` (or rely on `--startup`). From another terminal run the same `live-mcp` script. Expect the toast. Confirm with `npm run companion -- status`, and in PowerShell: `[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null; [Windows.UI.Notifications.ToastNotificationManager]::History.GetHistory('Kenuxa.Heimdall.Companion') | % Tag`.

**C. Reboot.** `npm run companion -- install-startup`; confirm `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v KenuxaHeimdallCompanion`; reboot; do **not** sign in yet: from another machine the device must show *Heartbeat stale / not heard from* (nothing runs pre-sign-in); sign in; within ~30 s the device shows **Companion online**.

**D. Notifications denied / DND.** Windows Settings > System > Notifications > turn off *Kenuxa Heimdall*; trigger an incident; expect no toast, the Protection Center *Desktop notification delivery* = **Degraded** ("disabled for user") and the delivery recorded as suppressed. Turn it back on. With Focus on, expect a silent Action Center entry; the UI must not claim a pop-up.

**E. Uninstall.** Before: export `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. `npm run companion -- uninstall`. After: the Run listing is identical minus `KenuxaHeimdallCompanion`; `%LOCALAPPDATA%\KenuxaHeimdall\companion.json` is gone; the dashboard shows the device *Removed*; its key returns 401.

**F. Laptop off.** Power the laptop off; wait 20 minutes; the device must read **Not protected** with "No endpoint enforcement is claimed", a `device_offline` alert is raised, and a hosted agent's authorizations still succeed.
