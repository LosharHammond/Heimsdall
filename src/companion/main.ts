/**
 * Kenuxa Heimdall companion (Windows). Commands:
 *
 *   (no command) [--url <dashboard url>]                                    first start: pair this computer (a person confirms in the
 *                                                                          dashboard), start at sign-in, then run. Later: run.
 *   pair --url <dashboard url> [--no-startup]                              pair this computer without copying a token
 *   enroll --url <dashboard url> --token <enrollment token> [--startup]   link this computer with a token (manual alternative)
 *   run                                                                    heartbeat + notifications (foreground)
 *   status                                                                 local state, what runs at sign-in
 *   notify-test                                                            show a local Windows toast (no cloud needed)
 *   selftest                                                               safe protection test on disposable fixtures
 *   consent --os-security on|off --process-inventory on|off               optional telemetry, off by default
 *   install-startup | remove-startup                                       start at USER SIGN-IN (HKCU Run), nothing earlier
 *   uninstall                                                              unenroll + remove ONLY app-owned entries
 */
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { defaultStateDir, executorStatusPath, readExecutorStatus } from "../executor/status.js";
import { COMPANION_VERSION, Companion, configPath, loadConfig, saveConfig } from "./companion.js";
import { runSelfTest } from "./selftest.js";
import { installTokenFromPath, pairDevice } from "./pairing.js";
import { copyFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { spawn } from "node:child_process";

// Set when built as the Windows app (scripts/build-installer.ts); undefined when run from source.
declare const __HEIMDALL_URL__: string | undefined;
const BAKED_URL = typeof __HEIMDALL_URL__ !== "undefined" ? __HEIMDALL_URL__ : undefined;
/** True inside the packaged single-file app (Node single executable application). */
const IS_APP = (() => {
  try {
    return (createRequire(import.meta.url)("node:sea") as { isSea(): boolean }).isSea();
  } catch {
    return false;
  }
})();
/** Where the packaged app installs itself for this user. */
const installedExe = () => join(process.env.LOCALAPPDATA ?? join(process.env.HOME ?? ".", ".local", "share"), "Kenuxa Heimdall", process.platform === "win32" ? "HeimdallCompanion.exe" : "heimdall-companion");
import { Windows } from "./windows.js";
import { AutoProtect, systemScanDeps } from "./protect/auto.js";
import { Gate } from "./protect/gate.js";
import { runMcpProxy } from "./protect/mcp-proxy.js";
import { runClaudeCodeHook } from "./protect/hook.js";
import { scan } from "./protect/discover.js";
import type { Launcher } from "./protect/apply.js";

const argv = process.argv.slice(2);
const cmd = argv[0]?.startsWith("--") ? undefined : argv[0];
const flag = (n: string) => {
  const i = argv.indexOf(`--${n}`);
  return i >= 0 ? argv[i + 1] : undefined;
};
const has = (n: string) => argv.includes(`--${n}`);
const stateDir = defaultStateDir();
const win = new Windows();
const out = (x: unknown) => console.log(typeof x === "string" ? x : JSON.stringify(x, null, 2));

function startupCommand(): string {
  if (IS_APP) return `powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Process -WindowStyle Hidden -FilePath '${installedExe()}' -ArgumentList 'run'"`;
  const node = process.execPath;
  const self = fileURLToPath(import.meta.url);
  // Hidden start: nothing is shown at sign-in. Runs only when THIS user signs in (HKCU Run).
  return `powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Process -WindowStyle Hidden -FilePath '${node}' -ArgumentList '\\"${self}\\" run'"`;
}

async function enroll() {
  const url = (flag("url") ?? "").replace(/\/$/, "");
  const token = flag("token");
  if (!url || !token) throw new Error("Usage: enroll --url <dashboard url> --token <enrollment token>");
  const res = await fetch(`${url}/v1/device/enroll`, {
    method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ companion_version: COMPANION_VERSION, platform: process.platform === "win32" ? "windows" : "other" }), redirect: "error",
  });
  const body = (await res.json().catch(() => ({}))) as any;
  if (!res.ok) throw new Error(`Enrollment failed (${res.status}): ${body?.error?.message ?? "unknown error"}`);
  const protectedKey = process.platform === "win32" ? win.protect(body.device_key) : body.device_key;
  if (!protectedKey) throw new Error("Could not protect the device key with Windows DPAPI");
  saveConfig(stateDir, { url, device_id: body.device_id, device_key_protected: protectedKey, consent: { os_security: false, process_inventory: false }, enrolled_at: new Date().toISOString(), version: COMPANION_VERSION });
  const reg = win.registerAppId();
  out(`Enrolled as device ${body.device_id}.`);
  out(`Device key stored ${process.platform === "win32" ? "(Windows DPAPI, current user only)" : "(plain file: unsupported platform)"} in ${configPath(stateDir)}`);
  if (body.policy_signing_key) out(`Policy signing key id ${body.policy_signing_key.key_id}: compare it with the id shown in the dashboard.`);
  out(`Notification identity registered: ${reg.ok ? "yes" : "no (" + reg.err + ")"}`);
  // Windows reports a notification setting for an app identity only after its first toast, so confirm the path now.
  const first = win.showToast({ title: "Kenuxa Heimdall companion enrolled", body: "This computer is linked. Heimdall will show incident notifications here.", tag: "enrolled" });
  out(first.shown ? "A confirmation notification was shown." : `Windows did not show the confirmation notification (setting: ${first.setting}). Check Settings > System > Notifications.`);
  if (has("startup")) installStartup();
  out("Next: `run` to start (or sign out and in again if you used --startup).");
}

/** Where the dashboard is: --url, then HEIMDALL_URL, then a heimdall-url.txt next to the app (written by the download). */
function serverUrl(): string | undefined {
  const fromFile = (() => {
    try {
      const p = join(IS_APP ? dirname(process.execPath) : fileURLToPath(new URL(".", import.meta.url)), "heimdall-url.txt");
      return existsSync(p) ? readFileSync(p, "utf8").trim() : undefined;
    } catch {
      return undefined;
    }
  })();
  const u = flag("url") ?? process.env.HEIMDALL_URL ?? fromFile ?? BAKED_URL;
  return u ? u.replace(/\/$/, "") : undefined;
}

/** One-click setup: a person confirms this computer in the dashboard; nothing is copied. */
async function pair(opts: { startup: boolean }) {
  const url = serverUrl();
  if (!url) throw new Error("Which Heimdall? Start with --url https://your-heimdall-address (or download the app from the dashboard, which knows it).");
  const platform = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "macos" : process.platform === "linux" ? "linux" : "other";
  out(`Adding this computer to Kenuxa Heimdall at ${url}.`);
  const installToken = flag("install-token")?.toUpperCase() ?? (IS_APP ? installTokenFromPath(process.execPath) : undefined);
  if (installToken) out("Adding this computer…");
  const r = await pairDevice({
    url, companionVersion: COMPANION_VERSION, platform, installToken,
    onCode: (code, verify) => out(`Your browser is opening. Check that it shows the code ${code}, then choose Add.\nIf it did not open, go to ${verify}`),
  });
  const protectedKey = process.platform === "win32" ? win.protect(r.device_key) : r.device_key;
  if (!protectedKey) throw new Error("Could not protect the device key with Windows DPAPI");
  saveConfig(stateDir, { url, device_id: r.device_id, device_key_protected: protectedKey, consent: { os_security: false, process_inventory: false }, enrolled_at: new Date().toISOString(), version: COMPANION_VERSION });
  win.registerAppId();
  if (opts.startup) installStartup();
  win.showToast({ title: "Kenuxa Heimdall is protecting this computer", body: "This computer was added. You will be notified here about incidents and approvals.", tag: "enrolled" });
  out(`Added as device ${r.device_id}.`);
}

/**
 * Packaged app, first start from Downloads: copy itself to the user's app folder (no administrator rights needed), start at
 * sign-in from there, start that copy hidden now, and close this window. Later starts run the installed copy.
 */
function installAppAndLaunch(): boolean {
  if (!IS_APP) return false;
  const target = installedExe();
  if (process.execPath.toLowerCase() === target.toLowerCase()) return false;
  mkdirSync(dirname(target), { recursive: true });
  try {
    copyFileSync(process.execPath, target);
  } catch (e) {
    // Already running from a previous install: the copy is locked. Keep the existing one.
    if (!existsSync(target)) throw e;
  }
  installStartup();
  spawn(target, ["run"], { detached: true, stdio: "ignore", windowsHide: true }).unref();
  out(`Installed in ${dirname(target)} and running in the background. You can close this window.`);
  return true;
}

/** How AI tools should start Heimdall's proxy and hook: the installed app, or this source checkout in development. */
function launcher(): Launcher {
  if (IS_APP) return { command: installedExe(), prefix: [] };
  return { command: process.execPath, prefix: [...process.execArgv, fileURLToPath(import.meta.url)] };
}
const seal = (v: string) => (process.platform === "win32" ? win.protect(v) : v);
const unseal = (v: string) => (process.platform === "win32" ? win.unprotect(v) : v);
function autoProtect(gate: Gate, cfg: { url: string; device_key_protected: string }) {
  return new AutoProtect({
    stateDir, url: cfg.url, deviceKey: () => unseal(cfg.device_key_protected), launcher: launcher(), gate, seal, unseal,
    scanDeps: systemScanDeps(() => win.processes()),
    notify: (title, body) => { win.showToast({ title, body, tag: "protect" }); },
    log: (m) => console.error(m),
  });
}

function installStartup() {
  const r = win.setRunKey(startupCommand());
  out(r.ok ? "Start-at-sign-in enabled (HKCU Run). Nothing runs before you sign in." : `Could not enable startup: ${r.err}`);
}

async function run() {
  const lock = join(stateDir, "companion.lock");
  if (existsSync(lock)) {
    const pid = Number(readFileSync(lock, "utf8"));
    try {
      process.kill(pid, 0);
      throw new Error(`Another companion is already running (pid ${pid}).`);
    } catch (e) {
      if ((e as Error).message.startsWith("Another")) throw e; // process.kill throws when the pid is gone: stale lock
    }
  }
  const cfg0 = loadConfig(stateDir);
  if (!cfg0) throw new Error("This computer is not added to Heimdall yet. Start the app without a command to add it.");
  // The local decision service and automatic discovery: AI tools found on this computer are protected without anyone asking.
  const gate = new Gate({ url: cfg0.url, stateDir, announce: (line) => console.log(line) });
  console.log("Heimdall is watching this computer's AI tools. Every action they try is listed below as it is checked.\n");
  await gate.listen();
  const auto = autoProtect(gate, cfg0);
  await auto.start();
  let lastSummary = "";
  const scanNow = () => auto.tick().then((found) => {
    const lines = found.map((f) => `  ${f.protectable ? (f.protection === "restart_needed" ? "RESTART  " : f.protection === "off" ? "OFF      " : "GUARDING ") : "SEEN     "}${f.product}${f.detail ? ` (${f.detail})` : ""}`);
    const summary = lines.join("\n");
    if (summary !== lastSummary) {
      lastSummary = summary;
      console.log(found.length ? `\nAI tools on this computer (checked every 5 minutes):\n${summary}\n` : "\nNo AI tools found on this computer yet (checked every 5 minutes).\n");
    }
  }).catch((e) => console.error("discovery failed:", (e as Error).message));
  void scanNow();
  setInterval(scanNow, 5 * 60_000).unref();
  const c = new Companion({ stateDir, windows: win, fetch, onRemoved: () => { auto.restoreAll(); process.exit(0); } });
  writeFileSync(lock, String(process.pid));
  const stop = () => {
    rmSync(lock, { force: true });
    void gate.close().finally(() => process.exit(0));
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  out(`Heimdall companion ${COMPANION_VERSION} running for device ${c.cfg.device_id} -> ${c.cfg.url}`);
  for (;;) {
    await c.tick().catch((e) => console.error("tick failed:", (e as Error).message));
    await new Promise((r) => setTimeout(r, 15_000));
  }
}

async function main() {
  switch (cmd) {
    case undefined:
    case "start": {
      // Double-clicked: add this computer on first start (and start at sign-in), then keep running. Nothing to type.
      if (!loadConfig(stateDir)) await pair({ startup: !IS_APP });
      if (installAppAndLaunch()) return new Promise<void>((r) => setTimeout(r, 6000));
      return run();
    }
    case "pair": {
      await pair({ startup: !has("no-startup") });
      return out("Next: `run` (or sign out and in again: it starts at sign-in).");
    }
    case "enroll": return enroll();
    case "run": return run();
    case "status": {
      const cfg = loadConfig(stateDir);
      return out({
        enrolled: !!cfg, device_id: cfg?.device_id, url: cfg?.url, consent: cfg?.consent, version: COMPANION_VERSION,
        notification_setting: win.toastSetting(), notification_identity_registered: win.hasAppId(),
        start_at_sign_in: win.getRunKey() ? "enabled (HKCU Run, runs only after this user signs in)" : "not enabled",
        executor: readExecutorStatus(executorStatusPath(stateDir)),
      });
    }
    case "notify-test": {
      win.registerAppId();
      return out(win.showToast({ title: "Heimdall test notification", body: "If you can read this, Windows accepted a notification from Kenuxa Heimdall.", tag: "manual-test" }));
    }
    case "selftest": return out(await runSelfTest());
    case "consent": {
      const cfg = loadConfig(stateDir);
      if (!cfg) throw new Error("Not enrolled");
      const on = (v?: string) => v === "on";
      if (flag("os-security")) cfg.consent.os_security = on(flag("os-security"));
      if (flag("process-inventory")) cfg.consent.process_inventory = on(flag("process-inventory"));
      saveConfig(stateDir, cfg);
      return out({ consent: cfg.consent, note: "Optional telemetry is sent only while enabled. Process inventory reports matching process NAMES only." });
    }
    case "install-startup": return installStartup();
    case "remove-startup": return out(win.removeRunKey().ok ? "Startup entry removed." : "Could not remove startup entry.");
    case "uninstall": {
      const cfg = loadConfig(stateDir);
      if (!cfg) {
        win.removeRunKey(); win.unregisterAppId();
        return out("Not enrolled; removed any Heimdall startup entry and notification identity.");
      }
      autoProtect(new Gate({ url: cfg.url, stateDir }), cfg).restoreAll(); // AI tools back to their original settings
      const r = await new Companion({ stateDir, windows: win, fetch }, cfg).uninstall();
      return out(`${r.unenrolled ? "Device unenrolled in the dashboard." : "Could not reach the service: ask an administrator to remove the device."} Restored the AI tools' original settings and removed Heimdall's startup entry, notification identity and local configuration.`);
    }
    case "mcp-proxy": {
      // Started by an AI app in place of one of its tool servers. stdout belongs to the MCP protocol: print nothing else.
      const sep = argv.indexOf("--");
      if (sep < 0 || !flag("key") || !flag("server")) throw new Error("Usage: mcp-proxy --key <tool> --server <name> -- <command> [args...]");
      const [command, ...rest] = argv.slice(sep + 1);
      process.exitCode = await runMcpProxy({ key: flag("key")!, server: flag("server")!, command, args: rest, stateDir });
      return;
    }
    case "hook": {
      let input = "";
      for await (const chunk of process.stdin) input += chunk;
      const res = await runClaudeCodeHook(input, stateDir);
      if (res) process.stdout.write(res);
      return;
    }
    case "discover": {
      return out(scan(systemScanDeps(() => win.processes())).map(({ config, settingsPath, ...f }) => f));
    }
    case "unprotect": {
      const cfg = loadConfig(stateDir);
      if (!cfg) throw new Error("Not added to Heimdall.");
      autoProtect(new Gate({ url: cfg.url, stateDir }), cfg).restoreAll();
      return out("Restored the original settings of every AI tool Heimdall had protected. Automatic protection resumes at the next scan unless an administrator turns it off.");
    }
    default:
      return out("Commands: (none) | pair | enroll | run | status | notify-test | selftest | consent | install-startup | remove-startup | discover | unprotect | uninstall");
  }
}

if (IS_APP || import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((e) => {
    console.error((e as Error).message);
    process.exit(1);
  });
}
