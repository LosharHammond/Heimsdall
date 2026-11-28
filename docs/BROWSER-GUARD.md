# Browser guard (Chrome, Edge, Brave, Opera)

The Heimdall extension stops passwords, API keys, tokens, private keys and payment card numbers from being pasted, typed
or uploaded into AI chat websites: ChatGPT, Claude, Gemini, Copilot, Perplexity, DeepSeek, Grok, Mistral, Meta AI, Poe,
Hugging Face, AI Studio and NotebookLM. Lists of personal details (5+ emails or phone numbers) and documents marked
CONFIDENTIAL wait for an administrator's approval.

**Privacy:** the text is checked on the computer (`browser-extension/detect.js`). Heimdall receives only what kind of thing
was found ("OpenAI API key"), the website and the decision. Never the text.

## For users
1. Overview or Protection Center → **AI chats in your browser** → *Download the browser extension* (or *Add to Chrome*
   once it is in the Chrome Web Store).
2. Click **Protect this browser**. The card turns green.
3. *Try it: copy a harmless test key* and paste it into ChatGPT. Heimdall stops it and offers to paste it with the key removed.

Even before step 2, the extension blocks secrets on its own. A small shield in the corner of each AI chat shows it is on.

## How decisions are made
Each browser gets its own agent ("Browser guard: Chrome on Windows (Ama)") with a key, held to the policy
**Browser guard (automatic)** (`src/shared/browser-policy.ts`), editable like any policy:

| Found | Classification | Rule | Result |
|---|---|---|---|
| keys, passwords, private keys, cards, secret files | restricted | `never-share-secrets` | blocked; offered with the secrets removed |
| contact lists, CONFIDENTIAL documents, IBANs | confidential | `ask-before-sharing-personal-data` | waits for approval (15 min) |
| anything else, on the listed AI sites | internal | `everyday-ai-chats` | at once |

Blocks are reported as refused outcomes, so they count as **Confirmed stopped**. If Heimdall can't be reached, secrets
are still blocked and personal-data lists ask the person to confirm.

## Publishing to the Chrome Web Store (one-click install)
`npm run build:extension` writes `src/web/public/downloads/heimdall-browser-guard.zip`. Upload that zip at
https://chrome.google.com/webstore/devconsole (one-time $5 developer registration), and to Microsoft Edge Add-ons for Edge.
Once listed, set `BROWSER_GUARD_WEBSTORE_URL` in Vercel to the listing address: the dashboard then shows **Add to Chrome**
instead of the manual steps. A self-hosted Heimdall: `npm run build:extension -- --url https://your-heimdall.example.com`.

## Limits
- Text already on a site, or typed into AI tools other than the listed sites, is not checked.
- Images and the contents of uploaded files are not read; uploads are blocked by file name (`.env`, `id_rsa`, `*.pem`, `*.key`...).
- Someone with administrator rights on the computer can remove the extension. For company computers, force-install it
  with Chrome/Edge enterprise policy (`ExtensionInstallForcelist`) after it is in the store.
