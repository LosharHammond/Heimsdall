/**
 * Vercel entry: the whole API as one function. The dashboard itself is served as static files by Vercel
 * (scripts/build-vercel.ts builds both into .vercel/output).
 *
 * There is no always-on process here, so:
 * - database migrations run during the build (npm run build:vercel), not at start-up;
 * - alert and browser-push delivery runs straight after any request that can raise an alert, once the response has been sent;
 * - everything else (device sweep, retention, retries) runs from /api/cron/tick, called by Vercel Cron and GitHub Actions.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { getRequestListener } from "@hono/node-server";
import { waitUntil } from "@vercel/functions";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createDb } from "./db.js";
import { deliver } from "./jobs.js";
import { log, setLogLevel } from "./log.js";
import { loadSigner } from "./signing.js";
import { upgradeAllLegacyAutoPolicies } from "./services/discovery.js";
import type { Ctx } from "./services/core.js";

let ready: Promise<{ ctx: Ctx; listener: (req: IncomingMessage, res: ServerResponse) => Promise<void> }> | undefined;

function boot() {
  ready ??= (async () => {
    const config = loadConfig({ DATABASE_POOL_MAX: "3", TRUST_PROXY: "1", ...process.env, AUTO_MIGRATE: "0" });
    setLogLevel(config.LOG_LEVEL);
    const db = await createDb(config);
    const signer = loadSigner(config);
    const ctx: Ctx = { db, config, signer, installerDir: process.cwd() + "/installer" };
    try {
      await upgradeAllLegacyAutoPolicies(db);
    } catch (e) {
      log("warn", "could not upgrade the automatic AI-tool policy", { error: (e as Error).message });
    }
    return { ctx, listener: getRequestListener(createApp(ctx).fetch) };
  })().catch((e) => {
    ready = undefined; // try again on the next request
    throw e;
  });
  return ready;
}

let lastDelivery = 0;
/** Requests that can raise an alert or an approval: agent calls and dashboard changes. */
const mayAlert = (method = "GET", path = "/") => method !== "GET" && (path.startsWith("/v1/") || path.startsWith("/api/"));

export default async function handler(req: IncomingMessage, res: ServerResponse) {
  let app;
  try {
    app = await boot();
  } catch (e) {
    log("error", "start-up failed", { error: (e as Error).message });
    res.statusCode = 503;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ error: { code: "UNAVAILABLE", message: "Heimdall could not reach its database. Nothing was executed." } }));
    return;
  }
  await app.listener(req, res);
  const path = (req.url ?? "/").split("?")[0];
  if (mayAlert(req.method, path) && !path.startsWith("/api/cron/") && Date.now() - lastDelivery > 5_000) {
    lastDelivery = Date.now();
    waitUntil(deliver(app.ctx).catch(() => undefined));
  }
}
