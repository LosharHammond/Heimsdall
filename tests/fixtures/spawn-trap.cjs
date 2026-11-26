// Test-only preload: records (and blocks) any attempt to start a subprocess in the process it is loaded into.
const cp = require("node:child_process");
const fs = require("node:fs");
const marker = process.env.SPAWN_TRAP_FILE;
for (const name of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]) {
  const orig = cp[name];
  cp[name] = function trapped(...args) {
    try { fs.appendFileSync(marker, `${name} ${JSON.stringify(args[0])}\n`); } catch {}
    throw new Error(`subprocess blocked by spawn-trap: ${name}`);
  };
  void orig;
}
