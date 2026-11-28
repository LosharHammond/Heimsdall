/**
 * Packs browser-extension/ into src/web/public/downloads/heimdall-browser-guard.zip (served by the dashboard), so the
 * extension download always matches this version. Plain "stored" zip, no extra dependencies.
 * Usage: tsx scripts/build-extension.ts [--url https://your-heimdall.example.com]
 */
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { crc32 } from "node:zlib";

const root = new URL("..", import.meta.url).pathname;
const src = join(root, "browser-extension");
const outDir = join(root, "src/web/public/downloads");
const urlArg = process.argv.indexOf("--url");
const url = (urlArg > 0 ? process.argv[urlArg + 1] : process.env.HEIMDALL_PUBLIC_URL || "").replace(/\/$/, "");

const files: Array<{ name: string; data: Buffer }> = [];
for (const name of readdirSync(src).sort()) {
  let data = readFileSync(join(src, name));
  if (url && /^https:\/\//.test(url) && url !== "https://kenuxa-heimdall.vercel.app") {
    // A self-hosted Heimdall: point the extension at it.
    if (name === "bg.js") data = Buffer.from(data.toString().replace('"https://kenuxa-heimdall.vercel.app"', JSON.stringify(url)));
    if (name === "manifest.json") data = Buffer.from(data.toString().replaceAll("https://kenuxa-heimdall.vercel.app/*", `${url}/*`));
  }
  files.push({ name, data });
}

const parts: Buffer[] = [];
const central: Buffer[] = [];
let offset = 0;
const dosTime = 0, dosDate = (2026 - 1980) << 9 | 1 << 5 | 1;
for (const f of files) {
  const name = Buffer.from(f.name);
  const crc = crc32(f.data) >>> 0;
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0, 6); local.writeUInt16LE(0, 8);
  local.writeUInt16LE(dosTime, 10); local.writeUInt16LE(dosDate, 12); local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(f.data.length, 18); local.writeUInt32LE(f.data.length, 22); local.writeUInt16LE(name.length, 26); local.writeUInt16LE(0, 28);
  parts.push(local, name, f.data);
  const c = Buffer.alloc(46);
  c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(20, 4); c.writeUInt16LE(20, 6); c.writeUInt16LE(0, 8); c.writeUInt16LE(0, 10);
  c.writeUInt16LE(dosTime, 12); c.writeUInt16LE(dosDate, 14); c.writeUInt32LE(crc, 16); c.writeUInt32LE(f.data.length, 20);
  c.writeUInt32LE(f.data.length, 24); c.writeUInt16LE(name.length, 28); c.writeUInt32LE(offset, 42);
  central.push(c, name);
  offset += 30 + name.length + f.data.length;
}
const cd = Buffer.concat(central);
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
mkdirSync(outDir, { recursive: true });
const zip = Buffer.concat([...parts, cd, end]);
writeFileSync(join(outDir, "heimdall-browser-guard.zip"), zip);
const version = JSON.parse(readFileSync(join(src, "manifest.json"), "utf8")).version;
writeFileSync(join(outDir, "heimdall-browser-guard.json"), JSON.stringify({ version, size: zip.length, built_at: new Date().toISOString() }));
console.log(`Browser guard ${version}: ${files.length} files, ${(zip.length / 1024).toFixed(0)} KB`);
