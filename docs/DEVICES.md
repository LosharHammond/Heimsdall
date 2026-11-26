# Adding devices: automatic, one click

Nobody copies tokens or keys. A device is added by answering one question, and from then on it is active and working.

## Browsers (any member)

1. Open the dashboard. At the top it asks **“Add this device to <organization>?”** with the browser and system it detected
   (for example *Chrome on Windows*).
2. Choose **Yes, add it**. That single click:
   - adds the browser as an **active** device belonging to you (your signed-in session is the proof, so there is no extra step),
   - asks the browser for notification permission,
   - subscribes it to **Web Push** with the server's own keys (generated on first use and stored encrypted; nothing to configure).
3. From then on the browser is told about **incident alerts** (everyone) and **approval requests** (people allowed to approve
   them), even when no Heimdall tab is open, as long as the browser itself is running. Each item reaches each browser once.

*Not now* hides the question for 7 days on that browser. If notifications are blocked, the device is still added and the
dashboard alerts you while it is open; the Protection Center shows *notifications off*. Push subscriptions that a browser drops
(HTTP 404/410 from its push service) are removed automatically. People can remove their own browsers; administrators can
remove any device. Browsers are never reported as “offline” (being closed is normal for a browser).

Web Push needs HTTPS in production (localhost works for development). iPhone/iPad receive Web Push only when the dashboard
has been added to the Home Screen (an Apple rule).

## Computers: one click from the browser (recommended)

1. On the Windows computer, in the dashboard: **Protect this computer too** (offered right after “Yes, add it”, and in the
   Protection Center). The browser downloads `Heimdall-Setup-<code>.exe`.
2. The person opens the downloaded file. Browsers cannot run programs for you, so this one step is theirs.
3. The app reads the one-time code from its own file name, adds the computer (active, owned by that person's
   organization), copies itself to `%LOCALAPPDATA%\Kenuxa Heimdall` (no administrator rights), sets itself to start with
   Windows, starts in the background and closes the window. Nothing to type, no code to compare, no administrator click.

The code is good for one computer and 15 minutes, and only the person who clicked can download it. A used or expired file
falls back to the pairing below (an administrator confirms), so nobody is stuck. Organizations that want an administrator
to confirm every computer turn on **Protection Center → “Computers added from a download wait for an administrator”**.

**Building the app (once per server).** On a Windows machine with this project:
`npm run build:installer -- --url https://your-heimdall-address`. It packages Node.js and the app into one
`dist/installer/HeimdallSetup.exe` (about 80 MB; no Node.js needed on the computers that install it) and the dashboard
offers it from then on. To avoid Windows' “Windows protected your PC” warning, sign that file with your code-signing
certificate (`signtool sign …`). Downloads are the same file under another name, so the signature stays valid.

## Computers: start the app and confirm a code

1. On the computer, start the app: `npm run companion -- --url https://your-heimdall` (or just `npm run companion` when
   `HEIMDALL_URL` is set or a `heimdall-url.txt` sits next to the app).
2. The app shows a code such as `49J2-DX9A` and opens the dashboard at **/pair** in the browser.
3. An administrator signed in to the dashboard checks the code, picks the organization and clicks **Add this computer**.
   The page warns when the request came from a different network than the administrator's.
4. The app collects its device key (once; the server erases its copy), protects it with Windows DPAPI, sets itself to start
   at sign-in, shows a *“Kenuxa Heimdall is protecting this computer”* notification and starts working. Later starts skip
   straight to running.

Requests expire after 10 minutes. Starting pairing is rate-limited per network. The poll secret is held only by the app;
the code alone cannot collect the key. Refused or expired requests give the app nothing.

The manual alternative (`npm run companion -- enroll --url … --token …`) still works for scripted deployments.

## API

| Call | Who | Purpose |
| --- | --- | --- |
| `POST /api/orgs/:org/browser-devices` `{label, platform}` | any member | add this browser (active) and get the push key |
| `POST /api/orgs/:org/browser-devices/:id/push` `{subscription, permission}` | that person | save or clear the push subscription |
| `POST /api/orgs/:org/browser-devices/:id/heartbeat` | that person | “dashboard open”; returns whether still active |
| `POST /api/orgs/:org/browser-devices/:id/test` | that person | send a test notification |
| `GET /api/orgs/:org/push-key` | any member | the server's public push key |
| `GET /api/orgs/:org/installer` | any member | is the Windows app available; does the org require approval |
| `POST /api/orgs/:org/device-installs` | any member | one-time code + download address (15 min) |
| `GET /api/device-installs/:code/download` | the person who asked | the app, named `Heimdall-Setup-<code>.exe` |
| `POST /v1/device/install/claim` `{install_token, device_name, platform, companion_version}` | the app (rate-limited) | 200 device key, 202 approval needed (pairing), 410 used/expired |
| `PUT /api/orgs/:org/device-settings` `{device_approval_required}` | admin | require approval for downloaded installs |
| `POST /v1/device/pair/start` `{device_name, platform, companion_version}` | the app (no auth, rate-limited) | start pairing |
| `GET /api/device-pairings/:code` | signed in | what is asking, and the organizations you administer |
| `POST /api/device-pairings/decide` `{code, org_id, approve}` | organization admin | add or refuse |
| `POST /v1/device/pair/poll` `{pairing_id, poll_secret}` | the app | 202 waiting, 200 key (once), 410 refused/expired |

Tests: `tests/device-setup.test.ts` (one-click add, ownership, push to the right people once, dropped subscriptions,
removal, pairing end to end through the companion's own code, refusal, expiry).

## Mobile apps

There is no native iOS/Android app yet. Phones and tablets are added the same way as any browser (Android: Chrome, Edge,
Firefox, Samsung Internet; iPhone/iPad: from the Home Screen). Native apps would use the same pairing calls.
