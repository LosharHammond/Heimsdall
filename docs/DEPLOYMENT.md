# Deployment

Heimdall is one container: a Node.js 22 process serving the API and the built dashboard, plus a PostgreSQL database.
It must run on a host independent of your computer. **No deployment has been performed**; the artifacts below are prepared
but the Docker image and `render.yaml` have not been built/deployed in this repository's development environment (no Docker was available).
What *was* verified is the production bundle on a real PostgreSQL server: `npm run smoke:prod`.

## Hosted topology (modest)

| Component | Purpose | Notes |
| --- | --- | --- |
| **web** (this container) | API + dashboard, `node dist/server/main.js` | HTTPS in front; health check `/readyz` |
| **worker** (same image, `node dist/server/worker.js`) | retention, silent-device alerts | tiny; can also run as the in-process timers of `web` for a single-instance start |
| **PostgreSQL** | all state | managed, backups on |
| Secrets | `DATABASE_URL`, **`POLICY_SIGNING_KEY`** | secret manager only |

The cloud control plane never needs to run on your computer. Local enforcement (executor) and notifications (companion) run on each enrolled Windows laptop and keep working in a documented, degraded way when the cloud is unreachable (OFFLINE.md). Nothing here has been deployed: preparing the artifacts does not create an account or incur cost; deploying requires your hosting account and your approval.

### Generate the policy signing key (once)
```bash
node -e "console.log(require('crypto').generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'der'}).toString('base64'))"
```
Store the output as `POLICY_SIGNING_KEY`. Rotating it invalidates cached bundles; executors refuse old-key bundles until they re-pin (documented limitation).

### Health monitoring
Point an external uptime monitor (your provider's, or any HTTP checker) at `https://<app>/readyz` (alert on non-200) and at `/healthz`. Inside the product, a silent enrolled device raises a `device_offline` alert after 15 minutes and the Protection Center shows stale heartbeats; those depend on the worker/timers running, so monitor the worker's process health too.

## What you need

1. A host that runs a container or Node.js (any PaaS/VPS) with **HTTPS** (TLS terminated by the platform or a reverse proxy).
2. A managed PostgreSQL (13+; tested on PostgreSQL 18) with automated backups.
3. Secrets stored in the platform's secret manager, never in the repository.

Managed options to compare (check each provider's *current* pricing and terms; do not assume a free tier supports commercial production):
Render, Fly.io, Railway, or a VPS with managed Postgres from the same cloud. Purpose: run the container and the database.
Alternatives: self-managed Postgres on a VPS (cheaper, but you own backups/patching). Cost drivers are listed below.

## Build and run

```bash
npm ci
npm run build            # dist/web (dashboard) + dist/server (API)
npm run migrate          # apply SQL migrations (needs DATABASE_URL)
npm start                # node dist/server/main.js
```

Container: `docker build -t kenuxa-heimdall .` then run with the environment variables below (`EXPOSE 8787`, built-in `HEALTHCHECK` on `/healthz`).
Example blueprint: [`render.yaml`](../render.yaml) (unverified).

## Environment variables

| Variable | Required | Notes |
| --- | --- | --- |
| `NODE_ENV` | yes | `production`. Enables Secure cookies, HSTS, and the startup checks below |
| `DATABASE_URL` | **yes in production** | PostgreSQL connection string. The embedded dev database is refused in production |
| `DATABASE_SSL` | recommended | `require` to verify the server certificate (most managed databases) |
| `APP_URL` | **yes in production** | Public `https://` base URL. Used for the Origin check. The process refuses to start with `http://` |
| `PORT` | no | default `8787` |
| `AUTO_MIGRATE` | no | default `1` (migrate on boot; fine for one instance). Set `0` and run `npm run migrate` as a release step when running several instances |
| `SESSION_TTL_HOURS` | no | default `168` |
| `RETENTION_INTERVAL_MINUTES` | no | default `1440`. `0` disables the in-process job; then schedule `npm run retention` (daily) |
| `TRUST_PROXY` | no | `1` only behind a proxy you control that sets `X-Forwarded-For` (the **last** entry is used) |
| `POLICY_SIGNING_KEY` | for offline bundles | base64 PKCS#8 Ed25519 private key. Unset in production => `/v1/policy-bundle` returns 503 and offline executors fail closed |
| `POLICY_BUNDLE_TTL_MINUTES` | no | default 240; how long a signed bundle is valid offline (= worst-case revocation lag for an offline executor) |
| `LOG_LEVEL` | no | `debug|info|warn|error` |
| `DATA_DIR` | dev only | location of the embedded PGlite database |

`.env.example` contains placeholders only. There are no other secrets: integration keys and sessions are generated at runtime.

## Health checks

- Liveness: `GET /healthz` -> `200 {"status":"ok"}`.
- Readiness: `GET /readyz` -> `200 {"status":"ready","database":"pg","migrations":N}` or `503` (database unreachable). Point the platform's health check at `/readyz`.

## HTTPS, headers and secrets

- Serve only over HTTPS. The app sends HSTS (production), a strict CSP, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, and `Cache-Control: no-store` on API responses.
- Integration keys travel in a bearer header: HTTPS is mandatory or they can be stolen on the wire.
- Put `DATABASE_URL` in the platform secret store; restrict database network access to the app.
- Rotate integration keys from **Credentials -> Replace**. Revocation is immediate.

## Backups and restore

- Enable the provider's automated backups and point-in-time recovery if offered; note the retention window.
- Logical backup (works anywhere with the PostgreSQL client tools): `pg_dump --format=custom --no-owner "$DATABASE_URL" > guardian-$(date +%F).dump`.
- Restore into an **empty** database: `pg_restore --no-owner --dbname "$RESTORE_URL" guardian-2026-01-01.dump`, then `npm run migrate` (a no-op if the dump is current), then check `/readyz`.
- Backups contain hashed credentials and activity metadata: encrypt them and store them away from the database host.
- **Restore has NOT been tested** in this repository (the development environment had no `pg_dump`/`pg_restore`). Do a restore drill into a scratch database before relying on it.

## Cost drivers (no prices quoted: verify with the provider)

- **Database storage and size**: each authorization writes a request, a decision (and often an outcome). Volume = agents x actions/day x retention days.
  Retention is configurable per organization (7-730 days; default 90); shorter retention is the main lever.
- **Compute**: one small always-on instance suffices for early use; rate limiting is per instance.
- **Bandwidth**: payloads are small (<= 64 KB per request); the dashboard bundle is ~100 KB gzipped.
- **Backups**: provider backup storage and retention.
- **Optional AI usage**: none today. The core never calls an AI model; if optional explanations are added later they must never grant permissions or override a denial.

## Release checklist

1. `npm test` and `npm run test:pg` pass (includes the real Windows API tests when run on Windows); `npm run typecheck` clean.
2. `npm run build`; `npm run smoke:prod` passes.
3. Set environment variables; confirm `APP_URL` is the real HTTPS URL.
4. Deploy; confirm `/readyz`; register, create an organization; run the adapter demo against the deployed URL with a throwaway organization.
5. Confirm backups are enabled and schedule the restore drill.
