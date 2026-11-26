import { loadConfig } from "./config.js";
import { createDb } from "./db.js";
import { runMigrations } from "./migrate.js";
import { runRetention } from "./retention.js";

const db = await createDb(loadConfig());
await runMigrations(db);
console.log(JSON.stringify(await runRetention(db)));
await db.close();
