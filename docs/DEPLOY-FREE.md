# Running Heimdall online for free: Vercel + Supabase + GitHub Actions

| Part | Where | Free plan limit that matters |
|---|---|---|
| Dashboard and API | Vercel Hobby | each request may run up to 60 s here; scheduled jobs once a day |
| Database | Supabase (your existing Kenuxa project, its own `heimdall` schema) | 500 MB per project; paused after a week with no activity |
| 30-minute jobs | GitHub Actions | free on public repositories; about 1,500 of the 2,000 free minutes on a private one |
| Heimdall on each PC | the companion app (unchanged) | |

Heimdall's tables go in their own schema, `heimdall`, not in `public`: Supabase publishes the `public` schema through its
REST API with the browser key, so Heimdall's data must never sit there.

## 1. Database (Supabase)
1. Open the Kenuxa project in Supabase > **Connect** > **Session pooler**. Copy that connection string (port 5432 on
   `pooler.supabase.com`) and put the database password in it. Use the *session* pooler, not the transaction pooler (6543):
   Heimdall sets its schema once per connection.
2. Nothing to run by hand: the Vercel build creates the `heimdall` schema and its tables.

## 2. Vercel
1. Push this folder to a GitHub repository, then Vercel > **Add New > Project** > import it. Project name `kenuxa-heimdall`
   (the Kenuxa app menu points at `https://kenuxa-heimdall.vercel.app`; if you use another name, update `home_url` in `kenuxa_apps`).
   Framework preset: **Other**. Vercel reads the build settings from `vercel.json`.
2. Environment variables (Production):

| Name | Value |
|---|---|
| `NODE_ENV` | `production` |
| `APP_URL` | `https://kenuxa-heimdall.vercel.app` |
| `DATABASE_URL` | the session pooler string from step 1 |
| `DATABASE_SSL` | `require` |
| `DATABASE_SCHEMA` | `heimdall` |
| `AUTH_ENCRYPTION_KEY` | `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"` |
| `POLICY_SIGNING_KEY` | see `.env.example` (needed for offline protection on PCs) |
| `CRON_SECRET` | any long random text, e.g. the same command as `AUTH_ENCRYPTION_KEY` |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | optional: "Continue with Google". Redirect URI `https://kenuxa-heimdall.vercel.app/api/auth/sso/callback` |
| `SMTP_URL`, `EMAIL_FROM` | optional: email alerts |

3. Deploy. Check `https://kenuxa-heimdall.vercel.app/readyz` shows `"status":"ready"`.

Vercel Cron calls `/api/cron/tick` once a day by itself (it sends `CRON_SECRET`).

## 3. GitHub Actions (every 30 minutes)
In the GitHub repository: **Settings > Secrets and variables > Actions**
- Secrets: `HEIMDALL_CRON_SECRET` = the same value as `CRON_SECRET`.
- Variables: `HEIMDALL_URL` = `https://kenuxa-heimdall.vercel.app`.

Move `deploy/heimdall-tick.yml` into a folder `.github/workflows/` (create it) before you push; GitHub then runs it every 30 minutes. Run it once by hand from the **Actions** tab to check it.

## 4. PCs
In the dashboard, **Devices > Add device** gives each PC its setup link as before, now pointing at the Vercel address.

## What works differently on the free setup
- Alerts (Slack, email, browser) go out straight after the action that raised them; retries and the "PC went quiet" check
  run every 30 minutes instead of every 15 seconds and 5 minutes.
- The Windows installer download from the dashboard is not hosted on Vercel; use `START-HEIMDALL.bat` or `npm run build:installer` locally.
- Locally nothing changed: `START-HEIMDALL.bat` and `npm run dev` still use the built-in database and run every job in the background.


## Many users at once (thousands)
Use Supabase's **Transaction pooler** (port 6543) instead of the session pooler, and add `DATABASE_POOL_MODE=transaction`
to Vercel's environment variables. Heimdall then sets its schema inside every transaction, so a handful of database
connections serve every Vercel instance. Keep `DATABASE_POOL_MAX` at 3. Rate limits are per instance and per key.
Optional: `BROWSER_GUARD_WEBSTORE_URL` once the browser extension is in the Chrome Web Store (docs/BROWSER-GUARD.md).
