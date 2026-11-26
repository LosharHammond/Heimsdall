/**
 * Background worker: retention cleanup, approval expiry and silent-device alerts. Runs separately from the web process so it can be
 * a second, tiny service (see render.yaml). Safe to run alongside the web process: every job is idempotent.
 *   npm run worker
 */
import { loadConfig } from "./config.js";
import { createDb } from "./db.js";
import { log, setLogLevel } from "./log.js";
import { runMigrations } from "./migrate.js";
import { runRetention } from "./retention.js";
import { sweepDevices } from "./services/devices.js";
import { dispatchAlerts } from "./services/notify.js";
import { dispatchPushes } from "./services/device-setup.js";

const config = loadConfig();
setLogLevel(config.LOG_LEVEL);
const db = await createDb(config);
if (config.AUTO_MIGRATE === "1") await runMigrations(db);

const guard = (name: string, fn: () => Promise<unknown>) => async () => {
  try {
    await fn();
  } catch (e) {
    log("error", `worker job failed: ${name}`, { error: (e as Error).message });
  }
};
const jobs = [
  { name: "alert-delivery", every: 15_000, run: guard("alert-delivery", () => dispatchAlerts({ db, config })) },
  { name: "browser-push", every: 15_000, run: guard("browser-push", () => dispatchPushes({ db, config })) },
  { name: "device-sweep", every: 5 * 60_000, run: guard("device-sweep", () => sweepDevices(db)) },
  { name: "retention", every: Math.max(1, config.RETENTION_INTERVAL_MINUTES || 1440) * 60_000, run: guard("retention", () => runRetention(db)) },
];
for (const j of jobs) {
  await j.run();
  setInterval(j.run, j.every);
}
log("info", "worker started", { jobs: jobs.map((j) => j.name) });
const stop = () => db.close().finally(() => process.exit(0));
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
