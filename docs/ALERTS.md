# Alerts to Slack and email, and audit export

**Settings → Alerts to Slack and email** (administrators).

## Channels

- **Slack:** paste an incoming-webhook address (`https://hooks.slack.com/services/…`; Slack → Apps → Incoming Webhooks).
  Only Slack webhook addresses are accepted, so the server cannot be pointed at other hosts.
- **Email:** up to 20 addresses. Needs `SMTP_URL` (for example `smtps://user:pass@smtp.example.com:465`) and optionally
  `EMAIL_FROM`. Without `SMTP_URL`, email channels show a delivery error instead of silently dropping alerts.
- Each channel chooses *low and above*, *medium and above* or *high only*. Webhook addresses and recipient lists are stored
  encrypted; the dashboard shows only a hint (`hooks.slack.com/…klmnop`, `a…@procus.test`).
- **Send test** checks a channel right away.

## Delivery

New alerts are queued per channel (an outbox in the database) and sent every 15 s by the server or worker. Failures are
retried after 1, 5, 30, 120 and 360 minutes, then marked failed and shown on the channel. A repeat of the same alert only
raises its counter: no second message. Several servers can run at once; each delivery is taken by one of them
(`FOR UPDATE SKIP LOCKED`). Message text is escaped for Slack and HTML email.

## Export

**Settings → Export** (owners, administrators, auditors): audit log or agent activity, a date range, as

- **CSV** for spreadsheets. Cells that start like formulas (`=`, `+`, `-`, `@`) are neutralized.
- **JSON Lines** for SIEMs. The last line is a manifest with the row count, period and SHA-256 of the rows, signed with the
  server's Ed25519 policy key. Check a file with `npm run verify-export -- file.jsonl` (it fails if any line was changed,
  added or removed).

API: `GET /api/orgs/:org/export?kind=audit|activity&format=csv|jsonl&from=…&to=…` (up to 100 000 rows per file; default the
last 30 days). Channels: `GET/POST /api/orgs/:org/channels`, `PUT/DELETE /api/orgs/:org/channels/:id`,
`POST /api/orgs/:org/channels/:id/test`. Tests: `tests/alerts.test.ts`.
