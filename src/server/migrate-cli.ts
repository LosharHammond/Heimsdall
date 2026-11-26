import { loadConfig } from "./config.js";
import { createDb } from "./db.js";
import { runMigrations } from "./migrate.js";

const config = loadConfig();
const db = await createDb(config);
const applied = await runMigrations(db);
console.log(applied.length ? `Applied: ${applied.join(", ")}` : "Database is up to date.");
await db.close();
