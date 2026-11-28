/**
 * Builds Heimdall for Vercel (Build Output API v3) into .vercel/output:
 *   static/              the dashboard (vite build)
 *   functions/api.func/  the API as one Node function, bundled with esbuild, plus the SQL migrations
 *   config.json          routes (API paths to the function, everything else to the dashboard) and the daily cron
 * Then, when DATABASE_URL is set (it is on Vercel), applies any new database migrations.
 *   npm run build:vercel
 */
import { execSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { build } from "esbuild";

const out = ".vercel/output";
rmSync(out, { recursive: true, force: true });
execSync("npx vite build", { stdio: "inherit" });

mkdirSync(`${out}/static`, { recursive: true });
cpSync("dist/web", `${out}/static`, { recursive: true });

const fn = `${out}/functions/api.func`;
mkdirSync(fn, { recursive: true });
await build({
  entryPoints: ["src/server/vercel.ts"],
  outfile: `${fn}/index.mjs`,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  sourcemap: false,
  // Development-only database and the optional native pg driver are never loaded on Vercel.
  external: ["@electric-sql/pglite", "pg-native", "embedded-postgres"],
  banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
  logLevel: "info",
});
cpSync("migrations", `${fn}/migrations`, { recursive: true });
if (existsSync("deploy/windows-installer.json")) {
  mkdirSync(`${fn}/installer`, { recursive: true });
  cpSync("deploy/windows-installer.json", `${fn}/installer/installer.json`);
}
writeFileSync(`${fn}/package.json`, JSON.stringify({ type: "module" }));
writeFileSync(
  `${fn}/.vc-config.json`,
  JSON.stringify({ runtime: "nodejs22.x", handler: "index.mjs", launcherType: "Nodejs", shouldAddHelpers: false, supportsResponseStreaming: true, maxDuration: 60 }, null, 2),
);

writeFileSync(
  `${out}/config.json`,
  JSON.stringify(
    {
      version: 3,
      routes: [
        { src: "^/sw\\.js$", headers: { "cache-control": "no-cache" }, continue: true },
        { src: "^/assets/(.*)$", headers: { "cache-control": "public, max-age=31536000, immutable" }, continue: true },
        { src: "^/(api|v1)(/.*)?$", dest: "/api" },
        { src: "^/(healthz|readyz)$", dest: "/api" },
        { handle: "filesystem" },
        { src: "^/(.*)$", dest: "/index.html" },
      ],
      crons: [{ path: "/api/cron/tick", schedule: "17 3 * * *" }],
    },
    null,
    2,
  ),
);
console.log(`Built ${out}`);

if (process.env.DATABASE_URL) {
  console.log("Applying database migrations...");
  execSync("npx tsx src/server/migrate-cli.ts", { stdio: "inherit", env: { ...process.env, NODE_ENV: "development", AUTO_MIGRATE: "1" } });
}
