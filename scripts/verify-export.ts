/**
 * Checks a JSON Lines export from Heimdall: every line is present and unchanged, and the manifest was signed by the service.
 *   npx tsx scripts/verify-export.ts heimdall-audit-2026-11-01_2026-11-25.jsonl https://your-heimdall
 * The public key comes from <server>/v1/signing-key (or pass a PEM file path instead of the URL).
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { canonicalJson } from "../src/shared/action.js";
import { verifySignature } from "../src/server/signing.js";

const [file, keySource] = process.argv.slice(2);
if (!file || !keySource) {
  console.error("Usage: verify-export <file.jsonl> <server url | public key .pem>");
  process.exit(2);
}
const lines = readFileSync(file, "utf8").split("\n").filter((l) => l.length);
const manifest = JSON.parse(lines.pop()!);
if (!manifest._manifest) throw new Error("The last line is not a Heimdall manifest.");
const sha = createHash("sha256").update(lines.map((l) => `${l}\n`).join("")).digest("hex");
const pem = existsSync(keySource) ? readFileSync(keySource, "utf8") : ((await (await fetch(`${keySource.replace(/\/$/, "")}/v1/signing-key`)).json()) as any).public_key_pem;
const { signature, ...unsigned } = manifest;
const sigOk = !!signature && verifySignature(pem, canonicalJson(unsigned), signature);
const countOk = lines.length === manifest.rows;
const hashOk = sha === manifest.sha256;
console.log(`rows: ${lines.length} (manifest says ${manifest.rows}) ${countOk ? "OK" : "MISMATCH"}`);
console.log(`content hash: ${hashOk ? "OK" : "MISMATCH: the file was changed"}`);
console.log(`signature (key ${manifest.key_id}): ${sigOk ? "OK" : "INVALID"}`);
process.exit(countOk && hashOk && sigOk ? 0 : 1);
