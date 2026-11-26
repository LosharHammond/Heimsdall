# Windows companion

A small per-user background program (`src/companion`, run with `npm run companion` or the compiled `dist/companion/main.js`). It enrolls a Windows computer, reports health, shows **Windows notifications** for incident-class alerts and runs the **safe protection test**. It does **not** enforce anything itself and it is **not antivirus**.

## Install / enroll (explicit, by the person who uses the computer)
1. Dashboard -> Protection Center -> **Add a device** -> copy the one-time enrollment command (token valid 60 minutes, used once, only its hash is stored).
2. On the Windows computer, in the project folder (Node 22+):
   ```bash
   npm install && npm run build           # once
   npm run companion -- enroll --url https://heimdall.example.com --token hdv_... [--startup]
   npm run companion -- run               # or sign out/in if you used --startup
   ```
3. Enrollment exchanges the token for a **device key** stored with Windows **DPAPI (current user only)** in `%LOCALAPPDATA%\KenuxaHeimdall\companion.json`, registers the app notification identity and shows a confirmation toast.

Commands: `status`, `notify-test`, `selftest`, `consent --os-security on|off --process-inventory on|off`, `install-startup`, `remove-startup`, `uninstall`.

## What it creates (all app-owned, all removed by `uninstall`)
| Item | Location |
| --- | --- |
| Notification identity (AppUserModelID `Kenuxa.Heimdall.Companion`) | `HKCU\Software\Classes\AppUserModelId\...` |
| Start at sign-in (optional) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `KenuxaHeimdallCompanion` |
| Config, DPAPI device key, executor status, policy cache | `%LOCALAPPDATA%\KenuxaHeimdall\` |

It never changes Windows Firewall, Defender, group policy or any key it did not create. `uninstall` (or revocation from the dashboard) tells the service, removes only the items above (verified by a registry-listing before/after test) and leaves unrelated files in the folder alone. If the cloud is unreachable at uninstall time, local entries are still removed and an administrator must remove the device in the dashboard.

## Startup and reboot behaviour
`--startup` uses the per-user **Run** key, so the companion starts **after that user signs in**. **Nothing runs before sign-in**: not at the lock screen, not for other users, not as a service. A stopped companion, a locked/powered-off laptop or a missing executor shows up as Degraded / Not protected in the Protection Center; nothing claims otherwise.

## Notifications
- API: `Windows.UI.Notifications.ToastNotificationManager` driven from Windows PowerShell 5.1 with a registered AppUserModelID. Microsoft's *Windows notifications overview* recommends **`AppNotificationManager` (Windows App SDK)** for unpackaged desktop apps and describes `ToastNotificationManager` as the UWP/WinRT API that "may work in some desktop scenarios". This build machine has no .NET SDK, so the PowerShell route is used and works here; migrating to a small signed .NET companion with `AppNotificationManager` is the supported path and is planned.
- Windows push notifications (WNS) need an Azure/Entra app registration and a Windows App SDK app; they are not used.
- The companion reads `ToastNotifier.Setting` and **never bypasses** it. If Windows reports notifications disabled (for user, for the app, by group policy, by manifest) the toast is **not** attempted, the alert is recorded as `suppressed`, and the Protection Center says so ("Protection is unaffected; alerts stay in the dashboard"). Windows exposes no supported API to detect Focus assist / Do Not Disturb, so in that mode a toast may be accepted but delivered silently to the Action Center; delivery is reported as "shown" only when Windows accepted the toast. Windows reports a setting only after an identity's first toast, which enrollment triggers.
- **De-duplication:** one delivery record per alert per device; the same alert re-announces only after a 30-minute cooldown; after being offline a backlog becomes at most 3 individual toasts plus one summary ("N more incidents"), all acknowledged.
- Locked screen / full-screen apps: Windows decides; toasts are queued to the Action Center.

## Optional telemetry (off by default, decided on the device)
- `consent --os-security on`: reads Microsoft Defender status via `Get-MpComputerStatus` (real-time protection, antivirus enabled, signature age). **Observation only.** Heimdall does not scan, block or control Windows Security and is not tested as, nor marketed as, an antivirus replacement.
- `consent --process-inventory on`: reports **process names only**, matched against a short list (claude, ollama, ...), each flagged `confidence: weak`. A process name is not proof that software is an AI agent. No command lines, paths, window titles, browsing history, document contents, prompts, clipboard or keystrokes are ever collected. The server drops these fields unless the same heartbeat declares consent.

## Safe protection test
`selftest` (also triggered from the dashboard) runs the **real executor** against disposable temp fixtures with a built-in test policy and a local receiver: allowed read, summary write, unauthorized deletion leaves the file intact, traversal refused, junction escape refused, upload to an unapproved destination sends nothing (while the approved one proves the receiver works), command execution refused before any handler runs. It touches no real files, your organization's policies, the real network or any subprocess. It tests the mechanics, not your policies.
