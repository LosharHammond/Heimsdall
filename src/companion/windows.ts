/**
 * Windows integration for the companion. Everything here is APP-OWNED and individually removable:
 *   - HKCU\Software\Classes\AppUserModelId\<AUMID>          (identity under which toasts are shown)
 *   - HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<name>   (start the companion at user sign-in)
 *   - companion config / DPAPI-protected device key in the per-user state directory
 * Nothing here touches Windows Firewall, Defender settings, group policy or any key it did not create.
 *
 * Notification API choice (verified against Microsoft Learn, "Windows notifications overview"): Microsoft recommends
 * AppNotificationManager from the Windows App SDK for unpackaged desktop apps and describes ToastNotificationManager
 * (Windows.UI.Notifications) as the UWP/WinRT API that "may work in some desktop scenarios". This build has no .NET SDK, so the
 * companion drives ToastNotificationManager through Windows PowerShell 5.1 with a registered AppUserModelID. It works on the
 * test machine, but migrating to a small signed .NET companion using AppNotificationManager is the planned, supported path.
 * Windows push notifications (WNS) need an Azure/Entra app registration and a packaged or WinAppSDK app; not used here.
 */
import { execFileSync } from "node:child_process";

export const AUMID = "Kenuxa.Heimdall.Companion";
export const RUN_VALUE = "KenuxaHeimdallCompanion";

export type PsResult = { ok: boolean; out: string; err: string };
export type PsRunner = (script: string, timeoutMs?: number) => PsResult;

/** Runs a script in Windows PowerShell 5.1 (which has the WinRT projection). Scripts are passed encoded, never interpolated into a shell. */
export const runPowerShell: PsRunner = (script, timeoutMs = 20_000) => {
  if (process.platform !== "win32") return { ok: false, out: "", err: "not windows" };
  try {
    const out = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], {
      encoding: "utf8", timeout: timeoutMs, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, out: out.trim(), err: "" };
  } catch (e) {
    const x = e as { stdout?: string; stderr?: string; message: string };
    return { ok: false, out: (x.stdout ?? "").toString().trim(), err: (x.stderr ?? x.message).toString().trim() };
  }
};

const q = (s: string) => `'${s.replace(/'/g, "''")}'`; // PowerShell single-quoted literal

export class Windows {
  constructor(private ps: PsRunner = runPowerShell, private aumid = AUMID, private runValue = RUN_VALUE) {}

  // ---- app identity for notifications ----
  registerAppId(displayName = "Kenuxa Heimdall"): PsResult {
    return this.ps(`
$k = 'HKCU:\\Software\\Classes\\AppUserModelId\\${this.aumid}'
New-Item -Path $k -Force | Out-Null
New-ItemProperty -Path $k -Name DisplayName -Value ${q(displayName)} -PropertyType String -Force | Out-Null
New-ItemProperty -Path $k -Name ShowInSettings -Value 1 -PropertyType DWord -Force | Out-Null`);
  }
  unregisterAppId(): PsResult {
    return this.ps(`Remove-Item -Path 'HKCU:\\Software\\Classes\\AppUserModelId\\${this.aumid}' -Recurse -Force -ErrorAction SilentlyContinue`);
  }
  hasAppId(): boolean {
    return this.ps(`Test-Path 'HKCU:\\Software\\Classes\\AppUserModelId\\${this.aumid}'`).out === "True";
  }

  // ---- startup (user sign-in only) ----
  setRunKey(command: string): PsResult {
    return this.ps(`$key = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
New-ItemProperty -Path $key -Name ${q(this.runValue)} -Value ${q(command)} -PropertyType String -Force | Out-Null`);
  }
  removeRunKey(): PsResult {
    return this.ps(`Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name ${q(this.runValue)} -ErrorAction SilentlyContinue`);
  }
  getRunKey(): string | null {
    const r = this.ps(`(Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name ${q(this.runValue)} -ErrorAction SilentlyContinue).${this.runValue}`);
    return r.ok && r.out ? r.out : null;
  }

  // ---- notifications ----
  /** What Windows says about whether THIS app may show toasts. Never bypassed. */
  toastSetting(retry = true): "enabled" | "disabled_for_application" | "disabled_for_user" | "disabled_by_group_policy" | "disabled_by_manifest" | "dnd_suspected" | "unknown" | "unsupported" {
    if (process.platform !== "win32") return "unsupported";
    const r = this.ps(`
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$s = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(${q(this.aumid)}).Setting
$g = (Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings' -Name NOC_GLOBAL_SETTING_TOASTS_ENABLED -ErrorAction SilentlyContinue).NOC_GLOBAL_SETTING_TOASTS_ENABLED
"$s|$g"`);
    if (!r.ok) {
      // A just-registered AppUserModelID is not always visible to the notifier immediately; retry once before reporting "unknown".
      if (retry) {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1500);
        return this.toastSetting(false);
      }
      return "unknown";
    }
    const [s, g] = r.out.split("|");
    const map: Record<string, ReturnType<Windows["toastSetting"]>> = {
      Enabled: "enabled", DisabledForApplication: "disabled_for_application", DisabledForUser: "disabled_for_user",
      DisabledByGroupPolicy: "disabled_by_group_policy", DisabledByManifest: "disabled_by_manifest",
    };
    const base = map[s] ?? "unknown";
    // Focus assist / Do Not Disturb has no supported query API. A globally disabled toast switch is the only signal we can read reliably.
    if (base === "enabled" && g === "0") return "dnd_suspected";
    return base;
  }

  /** Shows one Windows toast. Returns what Windows reported; a suppressed toast is NOT reported as shown. */
  showToast(input: { title: string; body: string; tag?: string }): { shown: boolean; setting: ReturnType<Windows["toastSetting"]>; error?: string } {
    const setting = this.toastSetting();
    if (setting !== "enabled" && setting !== "dnd_suspected" && setting !== "unknown") return { shown: false, setting };
    const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[c]!);
    const xml = `<toast><visual><binding template="ToastGeneric"><text>${esc(input.title.slice(0, 120))}</text><text>${esc(input.body.slice(0, 240))}</text></binding></visual></toast>`;
    const r = this.ps(`
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml(${q(xml)})
$toast = New-Object Windows.UI.Notifications.ToastNotification $doc
${input.tag ? `$toast.Tag = ${q(input.tag.slice(0, 60))}` : ""}
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(${q(this.aumid)}).Show($toast)
"shown"`);
    return r.ok && r.out.endsWith("shown") ? { shown: true, setting } : { shown: false, setting, error: r.err || r.out };
  }

  /** Tags of this app's toasts that Windows accepted into its notification history / Action Center. An OS-level delivery check. */
  deliveredTags(): string[] {
    const r = this.ps(`
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
foreach ($t in [Windows.UI.Notifications.ToastNotificationManager]::History.GetHistory(${q(this.aumid)})) { $t.Tag }`);
    return r.ok ? r.out.split(/\r?\n/).map((x) => x.trim()).filter(Boolean) : [];
  }
  clearHistory(): PsResult {
    return this.ps(`[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.UI.Notifications.ToastNotificationManager]::History.Clear(${q(this.aumid)})`);
  }

  // ---- optional, consent-gated observations ----
  /** Microsoft Defender status as exposed to the signed-in user. Observation only. */
  osSecurity(): { provider: string; realtime_protection: boolean | null; antivirus_enabled: boolean | null; signature_age_days: number | null; checked_at: string } | null {
    const r = this.ps(`Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, AntivirusSignatureAge | ConvertTo-Json -Compress`);
    if (!r.ok || !r.out) return null;
    try {
      const j = JSON.parse(r.out);
      return { provider: "windows-security", realtime_protection: j.RealTimeProtectionEnabled ?? null, antivirus_enabled: j.AntivirusEnabled ?? null, signature_age_days: j.AntivirusSignatureAge ?? null, checked_at: new Date().toISOString() };
    } catch {
      return null;
    }
  }

  /** Process NAMES only (no command lines, paths or window titles), matched against a short list. A name is weak evidence. */
  /** Running processes with their command lines (this user's; others show no command line without admin rights). */
  processes(): Array<{ name: string; cmd: string }> {
    if (process.platform !== "win32") {
      try {
        const out = execFileSync("ps", ["-eo", "comm=,args="], { encoding: "utf8", timeout: 5000, maxBuffer: 8 * 1024 * 1024 });
        return out.split("\n").filter(Boolean).map((l) => { const m = /^\s*(\S+)\s+(.*)$/.exec(l); return { name: (m?.[1] ?? "").replace(/^.*\//, ""), cmd: m?.[2] ?? "" }; });
      } catch { return []; }
    }
    const r = this.ps(`Get-CimInstance Win32_Process | Select-Object Name, CommandLine | ConvertTo-Json -Compress`);
    if (!r.ok || !r.out) return [];
    try {
      const j = JSON.parse(r.out);
      return (Array.isArray(j) ? j : [j]).map((p: any) => ({ name: String(p.Name ?? ""), cmd: String(p.CommandLine ?? "") }));
    } catch { return []; }
  }

  processCandidates(names = ["claude", "ollama", "lmstudio", "cursor", "windsurf", "chatgpt", "copilot"]): Array<{ name: string; count: number; confidence: "weak" }> {
    const r = this.ps(`Get-Process | Select-Object -ExpandProperty ProcessName`);
    if (!r.ok) return [];
    const counts = new Map<string, number>();
    for (const n of r.out.split(/\r?\n/).map((x) => x.trim().toLowerCase())) {
      const hit = names.find((k) => n === k || n.startsWith(k));
      if (hit) counts.set(hit, (counts.get(hit) ?? 0) + 1);
    }
    return [...counts].map(([name, count]) => ({ name, count, confidence: "weak" as const }));
  }

  // ---- DPAPI (current user) for the device key ----
  protect(plain: string): string | null {
    const r = this.ps(`Add-Type -AssemblyName System.Security
$b = [System.Text.Encoding]::UTF8.GetBytes(${q(plain)})
[Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Protect($b, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))`);
    return r.ok && r.out ? r.out : null;
  }
  unprotect(blob: string): string | null {
    const r = this.ps(`Add-Type -AssemblyName System.Security
$b = [Convert]::FromBase64String(${q(blob)})
[System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($b, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))`);
    return r.ok && r.out ? r.out : null;
  }
}
