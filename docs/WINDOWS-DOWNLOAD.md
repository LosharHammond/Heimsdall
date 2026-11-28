# Windows download on Vercel

Normal users open Protection Center, click Download for Windows, and open Heimdall-Setup.cmd from Downloads. No project folder, Node.js, npm, or copied credentials are needed.

The short setup downloads the immutable executable from our GitHub release, verifies its SHA-256 checksum against the deployed manifest, then starts it with a 15-minute, one-time installation code. The public GitHub request never receives that code. Account linking uses our HTTPS API and the device key is protected by the current Windows user's DPAPI. The app installs under LocalAppData and starts in the background at that user's Windows sign-in. If the organization requires administrator approval, the existing approval step remains.

Windows still requires a person to open and approve a downloaded program; the website cannot silently execute software. Restart already-open supported AI tools once after setup, then check their statuses in Protection Center and run the protection test. Detection, configured routing, and proven blocked actions are separate statuses. Browser registration enables notifications and approvals; it does not intercept browsing, web conversations, or arbitrary website actions.

The Windows companion release workflow type-checks, runs the full suite, builds the single executable and executes its fixture protection self-test before publishing. It records the immutable asset URL and checksum in deploy/windows-installer.json, which Vercel includes in its API function. The executable itself is hosted on GitHub Releases, avoiding Vercel response-size limits. Secret installation downloads are never cached.
