import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createDb } from "./db.js";
import { log, setLogLevel } from "./log.js";
import { runMigrations } from "./migrate.js";
import { runRetention } from "./retention.js";
import { loadSigner } from "./signing.js";
import { sweepDevices } from "./services/devices.js";
import { dispatchAlerts } from "./services/notify.js";
import { dispatchPushes } from "./services/device-setup.js";
import { upgradeAllLegacyAutoPolicies } from "./services/discovery.js";

const config = loadConfig();
setLogLevel(config.LOG_LEVEL);
const where = config.DATABASE_URL ? "PostgreSQL (DATABASE_URL)" : `embedded PGlite in ${config.DATA_DIR}/pglite`;
log("info", "starting: opening database", { database: where });
const slow = setTimeout(() => log("warn", "database still opening after 30 s. If it never finishes: make sure no other Heimdall server is running (port 8787), then rename the data folder to start a fresh development database", { database: where }), 30_000);
const db = await createDb(config);
clearTimeout(slow);
log("info", "database open");
const signer = loadSigner(config);
if (!signer) log("warn", "no POLICY_SIGNING_KEY configured: signed offline policy bundles are disabled");
if (config.AUTO_MIGRATE === "1") await runMigrations(db);
try {
  const upgraded = await upgradeAllLegacyAutoPolicies(db);
  if (upgraded) log("info", "moved the automatic AI-tool policy to Standard protection", { organizations: upgraded });
} catch (e) {
  log("warn", "could not upgrade the automatic AI-tool policy", { error: (e as Error).message });
}
const app = createApp({ db, config, signer });

const server = serve({ fetch: app.fetch, port: config.PORT }, (info) => {
  log("info", "server listening", { port: info.port, database: db.kind, env: config.NODE_ENV });
});

let timer: NodeJS.Timeout | undefined;
if (config.RETENTION_INTERVAL_MINUTES > 0) {
  timer = setInterval(() => runRetention(db).catch((e) => log("error", "retention failed", { error: (e as Error).message })), config.RETENTION_INTERVAL_MINUTES * 60_000);
  timer.unref();
}

// Alert delivery (Slack, email) every 15 s. The worker runs it too; each delivery is leased before sending, so both can run.
const alerts = setInterval(() => {
  dispatchAlerts({ db, config, signer }).catch((e) => log("error", "alert delivery failed", { error: (e as Error).message }));
  dispatchPushes({ db, config, signer }).catch((e) => log("error", "browser push failed", { error: (e as Error).message }));
}, 15_000);
alerts.unref();

const sweeper = setInterval(() => sweepDevices(db).catch((e) => log("error", "device sweep failed", { error: (e as Error).message })), 5 * 60_000);
sweeper.unref();

const shutdown = (signal: string) => {
  log("info", "shutting down", { signal });
  if (timer) clearInterval(timer);
  server.close(() => db.close().finally(() => process.exit(0)));
  setTimeout(() => process.exit(1), 10_000).unref();
};
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
