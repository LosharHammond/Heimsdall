/**
 * Builds the Windows app people download from the dashboard ("Protect this computer").
 *
 *   npm run build:installer -- --url https://heimdall.example.com
 *
 * Run it on Windows for a Windows app (it packages the Node.js you are running into one .exe; no Node is needed on the
 * computers that install it). The address defaults to APP_URL. Output: dist/installer/HeimdallSetup.exe + installer.json,
 * which the server offers for download. To sign it, run signtool on dist/installer/HeimdallSetup.exe afterwards: downloads
 * are the same file under a different name, so the signature stays valid.
 */
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { build } from "esbuild";

const argv = process.argv.slice(2);
const flag = (n: string) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : undefined; };
const url = (flag("url") ?? process.env.APP_URL ?? "").replace(/\/$/, "");
if (!/^https?:\/\/[^\s"']+$/.test(url)) {
  console.error("Which address will computers use to reach Heimdall? npm run build:installer -- --url https://heimdall.example.com");
  process.exit(1);
}
if (url.startsWith("http://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(url)) console.warn("Warning: plain http is only safe for local testing.");
const [major] = process.versions.node.split(".").map(Number);
if (major < 20) throw new Error("Node.js 20 or newer is needed to build the app.");

const out = resolve("dist/installer");
mkdirSync(out, { recursive: true });
const bundle = join(out, "companion.cjs");
const version = (readFileSync("src/companion/companion.ts", "utf8").match(/COMPANION_VERSION = "([^"]+)"/) ?? [])[1] ?? "0.0.0";

console.log(`1/4 Bundling the companion ${version} for ${url}`);
await build({
  entryPoints: ["src/companion/main.ts"], bundle: true, platform: "node", format: "cjs", target: `node${major}`, outfile: bundle,
  define: { __HEIMDALL_URL__: JSON.stringify(url), "import.meta.url": "__importMetaUrl" },
  banner: { js: 'const __importMetaUrl = require("node:url").pathToFileURL(__filename).href;' },
  logLevel: "warning",
});

console.log("2/4 Preparing the single-file app");
const blob = join(out, "sea-prep.blob");
const seaConfig = join(out, "sea-config.json");
writeFileSync(seaConfig, JSON.stringify({ main: bundle, output: blob, disableExperimentalSEAWarning: true, useCodeCache: false }));
execFileSync(process.execPath, ["--experimental-sea-config", seaConfig], { stdio: "inherit" });

const exeName = process.platform === "win32" ? "HeimdallSetup.exe" : "heimdall-setup";
const exe = join(out, exeName);
console.log(`3/4 Copying Node.js ${process.version} to ${exeName}`);
rmSync(exe, { force: true });
copyFileSync(process.execPath, exe);
if (process.platform === "win32") {
  // Node's own signature no longer matches once the app is injected; remove it if signtool is installed (optional).
  try { execFileSync("signtool", ["remove", "/s", exe], { stdio: "ignore" }); } catch { /* signtool not installed: fine */ }
}

console.log("4/4 Injecting the app");
const postject = resolve("node_modules/postject/dist/cli.js");
execFileSync(process.execPath, [postject, exe, "NODE_SEA_BLOB", blob, "--sentinel-fuse", "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2", ...(process.platform === "darwin" ? ["--macho-segment-name", "NODE_SEA"] : [])], { stdio: "inherit" });

writeFileSync(join(out, "installer.json"), JSON.stringify({ file: exeName, version, url, platform: process.platform, built_at: new Date().toISOString() }, null, 2));
for (const f of [blob, seaConfig]) rmSync(f, { force: true });
console.log(`Done: ${exe}\nThe dashboard now offers it under Protection Center > Protect this computer. Restart the server if it is running.`);
