/**
 * One-click companion setup: ask the service to add this computer, open the dashboard so a person can confirm, then collect
 * the device key. Used by `heimdall-companion` on first start (docs/DEVICES.md). No token is copied by hand.
 */
import { spawn } from "node:child_process";
import { hostname } from "node:os";

export interface PairingResult {
  device_id: string;
  device_key: string;
  policy_signing_key: { key_id: string; public_key_pem: string } | null;
}

export interface PairDeps {
  url: string;
  companionVersion: string;
  platform: "windows" | "linux" | "macos" | "other";
  deviceName?: string;
  fetch?: typeof fetch;
  /** Opens the confirmation page in the person's browser. Default: the system's default browser. */
  openUrl?: (url: string) => void;
  /** Told the code to show while waiting. */
  onCode?: (code: string, verifyUrl: string) => void;
  sleep?: (ms: number) => Promise<void>;
  /** Give up after this long (the request itself expires after 10 minutes). */
  timeoutMs?: number;
  /** One-time code from the downloaded file's name: adds the computer with no confirmation step (unless the org requires one). */
  installToken?: string;
}

/** The one-time code a download carries in its file name: Heimdall-Setup-<24 chars>.exe, also after a browser renames it "(1)". */
export function installTokenFromPath(p: string): string | undefined {
  const name = p.split(/[\\/]/).pop() ?? "";
  return /Heimdall-Setup-([0-9A-HJKMNP-TV-Z]{24})\b/i.exec(name)?.[1]?.toUpperCase();
}

export class PairingError extends Error {
  constructor(public code: string, message: string) {
    super(message);
  }
}

export async function pairDevice(d: PairDeps): Promise<PairingResult> {
  const f = d.fetch ?? fetch;
  const base = d.url.replace(/\/$/, "");
  const sleep = d.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const post = async (path: string, body: unknown) => {
    const r = await f(`${base}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), redirect: "error" });
    return { status: r.status, body: (await r.json().catch(() => ({}))) as any };
  };
  const deviceName = (d.deviceName ?? hostname()).slice(0, 100) || "Computer";
  let start: { status: number; body: any } | null = null;
  if (d.installToken) {
    const c = await post("/v1/device/install/claim", { install_token: d.installToken, device_name: deviceName, platform: d.platform, companion_version: d.companionVersion });
    if (c.status === 200 && c.body?.device_key) return { device_id: c.body.device_id, device_key: c.body.device_key, policy_signing_key: c.body.policy_signing_key ?? null };
    if (c.status === 202) start = { status: 201, body: c.body }; // the organization wants an administrator to confirm
    else if (c.status !== 410) throw new PairingError(c.body?.error?.code ?? "INSTALL_FAILED", c.body?.error?.message ?? `Could not add this computer (${c.status}).`);
    // 410: the download was old or already used. Fall back to asking an administrator, so the person is not stuck.
  }
  start ??= await post("/v1/device/pair/start", { device_name: deviceName, platform: d.platform, companion_version: d.companionVersion });
  if (start.status !== 201) throw new PairingError(start.body?.error?.code ?? "PAIRING_FAILED", start.body?.error?.message ?? `Could not start pairing (${start.status}).`);
  const { pairing_id, poll_secret, user_code, verify_url, interval_s } = start.body;
  // Only ever open our own server's page: never a URL the response could point elsewhere.
  if (typeof verify_url !== "string" || !/^https?:\/\//.test(verify_url)) throw new PairingError("PAIRING_FAILED", "The service returned an unexpected confirmation address.");
  d.onCode?.(user_code, verify_url);
  (d.openUrl ?? openInBrowser)(verify_url);
  const deadline = Date.now() + (d.timeoutMs ?? 10 * 60_000);
  while (Date.now() < deadline) {
    await sleep(Math.max(1, interval_s ?? 2) * 1000);
    const p = await post("/v1/device/pair/poll", { pairing_id, poll_secret });
    if (p.status === 202) continue;
    if (p.status === 200 && p.body?.device_key) return { device_id: p.body.device_id, device_key: p.body.device_key, policy_signing_key: p.body.policy_signing_key ?? null };
    if (p.status === 429) continue;
    throw new PairingError(p.body?.error?.code ?? "PAIRING_FAILED", p.body?.error?.message ?? `Pairing failed (${p.status}).`);
  }
  throw new PairingError("PAIRING_EXPIRED", "Nobody confirmed this computer in time. Start the app again to retry.");
}

/** Opens a URL in the default browser without a shell (the URL is never interpreted as a command). */
export function openInBrowser(url: string) {
  const [cmd, args] =
    process.platform === "win32" ? ["rundll32.exe", ["url.dll,FileProtocolHandler", url]] : process.platform === "darwin" ? ["open", [url]] : ["xdg-open", [url]];
  try {
    spawn(cmd, args as string[], { detached: true, stdio: "ignore", windowsHide: true }).unref();
  } catch {
    /* no browser: the code and address are printed for the person to open */
  }
}
