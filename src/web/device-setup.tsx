/**
 * "Add this device?" — shown once per browser per organization. Yes adds this browser as an active device, turns on
 * notifications (Web Push, so they arrive even when Heimdall is closed) and keeps it working. Nothing else to do.
 * Also the /pair page, where an administrator confirms the companion app on a computer.
 */
import { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router";
import { api, ApiError } from "./api";
import { useApp, useToast, ErrorBox, PageHeader, Spinner, Badge, Field } from "./ui";

const key = (orgId: string) => `hd_device:${orgId}`;
type Saved = { id: string } | { declinedAt: number };
const REASK_MS = 7 * 24 * 3600_000;
const read = (orgId: string): Saved | null => { try { return JSON.parse(localStorage.getItem(key(orgId)) ?? "null"); } catch { return null; } };
const write = (orgId: string, v: Saved | null) => { try { v ? localStorage.setItem(key(orgId), JSON.stringify(v)) : localStorage.removeItem(key(orgId)); } catch { /* storage off */ } };

export function describeBrowser(ua = navigator.userAgent): { label: string; platform: "windows" | "linux" | "macos" | "android" | "ios" | "other" } {
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const platform = /Android/.test(ua) ? "android" : /iPhone|iPad|iPod/.test(ua) ? "ios" : /Windows/.test(ua) ? "windows" : /Mac OS X|Macintosh/.test(ua) ? "macos" : /Linux/.test(ua) ? "linux" : "other";
  const os = { android: "Android", ios: "iPhone/iPad", windows: "Windows", macos: "Mac", linux: "Linux", other: "this device" }[platform];
  return { label: `${browser} on ${os}`, platform };
}

const b64ToBytes = (s: string) => {
  const raw = atob((s + "=".repeat((4 - (s.length % 4)) % 4)).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
};

/** Turns on push for this browser and tells the server. Safe to call again (it reuses the subscription). */
async function enablePush(orgId: string, deviceId: string, vapidKey: string | null) {
  const base = `/api/orgs/${orgId}/browser-devices/${deviceId}/push`;
  const supported = typeof Notification !== "undefined" && "serviceWorker" in navigator && "PushManager" in window;
  if (!supported) return api("POST", base, { subscription: null, permission: "unsupported" });
  const permission = Notification.permission === "default" ? await Notification.requestPermission() : Notification.permission;
  if (permission !== "granted" || !vapidKey) return api("POST", base, { subscription: null, permission });
  const reg = await navigator.serviceWorker.register("/sw.js");
  await navigator.serviceWorker.ready;
  let sub = await reg.pushManager.getSubscription();
  if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64ToBytes(vapidKey) });
  const j = sub.toJSON() as { endpoint: string; keys: { p256dh: string; auth: string } };
  return api("POST", base, { subscription: { endpoint: j.endpoint, keys: { p256dh: j.keys.p256dh, auth: j.keys.auth } }, permission });
}

/**
 * "Protect this computer": downloads the Windows app carrying a one-time code for this person. Opening the file adds the
 * computer, installs the app for this user, starts it at sign-in and starts protecting. Shown on Windows only.
 */
export function ProtectComputer({ compact, onDone }: { compact?: boolean; onDone?: () => void }) {
  const { org } = useApp();
  const info = useLoadInfo(org.id);
  const [state, setState] = useState<"idle" | "busy" | "started">("idle");
  const [error, setError] = useState<Error | null>(null);
  const windows = describeBrowser().platform === "windows";
  if (!info) return null;
  const go = async () => {
    setState("busy"); setError(null);
    try {
      const r = await api<{ download_url: string }>("POST", `/api/orgs/${org.id}/device-installs`);
      location.assign(r.download_url);
      setState("started");
    } catch (e) { setError(e as Error); setState("idle"); }
  };
  if (state === "started") return (
    <div className={compact ? "" : "card"} role="status">
      <strong>Open the downloaded file to finish.</strong>
      <ol className="small" style={{ margin: ".4rem 0 0", paddingLeft: "1.2rem" }}>
        <li>Open <code>Heimdall-Setup.cmd</code> from your downloads (in the browser's download bar or the Downloads folder).</li>
        <li>The setup downloads the app from our GitHub release and verifies it before running. Follow any Windows confirmation prompts.</li>
        <li>{info.approval_required ? "An administrator of your organization confirms the computer; then it starts protecting." : "The computer is added and Heimdall starts with Windows. Restart supported AI tools once, then check their individual protection status below."}</li>
      </ol>
      <div className="row" style={{ marginTop: ".6rem", gap: ".5rem" }}><button onClick={go}>Download again</button>{onDone && <button onClick={onDone}>Done</button>}</div>
    </div>
  );
  return (
    <div className={compact ? "" : "card"} style={{ display: "flex", gap: "1rem", alignItems: "center", flexWrap: "wrap" }}>
      <div className="grow" style={{ minWidth: 240 }}>
        <strong>Protect this computer too</strong>
        <div className="muted small">
          {!windows ? "The Heimdall app is for Windows. Open this page on the Windows computer you want to protect."
            : !info.available ? "The Windows download is being prepared. Reload this page shortly."
            : "Download the Heimdall app and open it. It adds this computer, finds the AI tools on it and protects them. Nothing to type."}
        </div>
        {error && <ErrorBox error={error} />}
      </div>
      {windows && info.available && <button className="primary" disabled={state === "busy"} onClick={go}>{state === "busy" ? <Spinner label="Preparing" /> : `Download for Windows${info.size ? ` (${Math.round(info.size / 1e6)} MB)` : ""}`}</button>}
      {onDone && <button onClick={onDone}>Not now</button>}
    </div>
  );
}

function useLoadInfo(orgId: string) {
  const [info, setInfo] = useState<{ available: boolean; size: number | null; approval_required: boolean } | null>(null);
  useEffect(() => { api<any>("GET", `/api/orgs/${orgId}/installer`).then(setInfo).catch(() => setInfo(null)); }, [orgId]);
  return info;
}

/** Banner on every page until answered; keeps an added browser checked in while the dashboard is open. */
export function DevicePrompt() {
  const { org } = useApp();
  const toast = useToast();
  const [saved, setSaved] = useState<Saved | null>(() => read(org.id));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  useEffect(() => setSaved(read(org.id)), [org.id]);

  // Added: check in now and every 2 minutes; if an admin removed it, forget it so the question comes back.
  const deviceId = saved && "id" in saved ? saved.id : null;
  useEffect(() => {
    if (!deviceId) return;
    let stop = false;
    const beat = async () => {
      try {
        const r = await api<{ status: string }>("POST", `/api/orgs/${org.id}/browser-devices/${deviceId}/heartbeat`);
        if (!stop && r.status !== "active") { write(org.id, null); setSaved(null); }
      } catch (e) {
        if (!stop && e instanceof ApiError && e.status === 404) { write(org.id, null); setSaved(null); }
      }
    };
    void beat();
    const t = setInterval(beat, 120_000);
    return () => { stop = true; clearInterval(t); };
  }, [deviceId, org.id]);

  const [followUp, setFollowUp] = useState(false);
  const show = !saved || ("declinedAt" in saved && Date.now() - saved.declinedAt > REASK_MS);
  if (followUp) return <div className="card device-prompt" style={{ marginBottom: "1rem" }}><ProtectComputer compact onDone={() => setFollowUp(false)} /></div>;
  if (!show) return null;

  const yes = async () => {
    setBusy(true); setError(null);
    try {
      const r = await api<{ device: { id: string; name: string }; vapid_public_key: string }>("POST", `/api/orgs/${org.id}/browser-devices`, describeBrowser());
      write(org.id, { id: r.device.id });
      setSaved({ id: r.device.id });
      let note = "Alerts and approvals will reach it even when Heimdall is closed.";
      try {
        const p = await enablePush(org.id, r.device.id, r.vapid_public_key);
        if (p?.notification_state !== "enabled") note = "Notifications are off in this browser, so it will only alert you while Heimdall is open. You can allow them in the browser's site settings.";
      } catch { note = "This browser could not turn on notifications; it will alert you while Heimdall is open."; }
      toast(`Added "${r.device.name}". ${note}`);
      if (describeBrowser().platform === "windows") setFollowUp(true);
    } catch (e) { setError(e as Error); }
    finally { setBusy(false); }
  };
  const later = () => { const v = { declinedAt: Date.now() }; write(org.id, v); setSaved(v); };

  return (
    <div className="card device-prompt" role="region" aria-label="Add this device" style={{ marginBottom: "1rem", display: "flex", gap: "1rem", alignItems: "center", flexWrap: "wrap" }}>
      <div className="grow" style={{ minWidth: 240 }}>
        <strong>Add this device to {org.name}?</strong>
        <div className="muted small">{describeBrowser().label}. It starts working at once: you'll be notified here about incidents{" "}and approvals, even when this tab is closed.</div>
        {error && <ErrorBox error={error} />}
      </div>
      <button className="primary" disabled={busy} onClick={yes}>{busy ? <Spinner label="Adding" /> : "Yes, add it"}</button>
      <button disabled={busy} onClick={later}>Not now</button>
    </div>
  );
}

/** Re-subscribes silently when the browser changed or renewed its push subscription. */
export function usePushRefresh() {
  const { org } = useApp();
  useEffect(() => {
    const s = read(org.id);
    if (!s || !("id" in s) || typeof Notification === "undefined" || Notification.permission !== "granted") return;
    api<{ vapid_public_key?: string }>("GET", `/api/orgs/${org.id}/push-key`).then((k) => enablePush(org.id, s.id, k.vapid_public_key ?? null)).catch(() => undefined);
  }, [org.id]);
}

/** /pair?code=XXXX-XXXX — confirm the companion app on a computer. */
export function PairPage() {
  const [params] = useSearchParams();
  const nav = useNavigate();
  const toast = useToast();
  const { org } = useApp();
  const [code, setCode] = useState(params.get("code") ?? "");
  const [info, setInfo] = useState<any>(null);
  const [orgId, setOrgId] = useState("");
  const [error, setError] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);

  const look = async (c: string) => {
    setError(null); setInfo(null);
    try {
      const r = await api<any>("GET", `/api/device-pairings/${encodeURIComponent(c.trim())}`);
      setInfo(r);
      setOrgId(r.orgs.find((o: any) => o.id === org.id)?.id ?? r.orgs[0]?.id ?? "");
    } catch (e) { setError(e as Error); }
  };
  useEffect(() => { if (params.get("code")) void look(params.get("code")!); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const decide = async (approve: boolean) => {
    setBusy(true); setError(null);
    try {
      const r = await api<any>("POST", "/api/device-pairings/decide", { code: info.user_code, org_id: approve ? orgId : undefined, approve });
      setDone(approve ? `"${r.device.name}" was added and is starting protection now. You can close this tab.` : "Refused. The app on that computer will stop asking.");
      if (approve) toast(`Added ${r.device.name}`);
    } catch (e) { setError(e as Error); }
    finally { setBusy(false); }
  };

  return (
    <>
      <PageHeader title="Add a computer" subtitle="Confirm the Heimdall app that is asking to join. Check that the code matches what the app shows." />
      <div className="card" style={{ maxWidth: 560 }}>
        {done ? (
          <><p>{done}</p><button onClick={() => nav("/protection")}>Go to Protection Center</button></>
        ) : !info ? (
          <form onSubmit={(e) => { e.preventDefault(); void look(code); }}>
            <Field label="Code shown by the app"><input value={code} onChange={(e) => setCode(e.target.value)} placeholder="ABCD-2345" autoFocus /></Field>
            <button className="primary" type="submit">Continue</button>
            {error && <ErrorBox error={error} />}
          </form>
        ) : (
          <>
            <p style={{ fontSize: "1.6rem", letterSpacing: ".15em", fontWeight: 700 }}>{info.user_code}</p>
            <p><strong>{info.device_name}</strong> · {info.platform} · app {info.companion_version}</p>
            {!info.same_network && <p><Badge tone="warn">Different network</Badge> This request came from a different network than yours. Only add it if you just started the app yourself, or someone you trust did.</p>}
            {info.orgs.length === 0 ? (
              <p className="muted">Only an organization administrator can add computers. Ask one to open this page.</p>
            ) : (
              <Field label="Add to organization">
                <select value={orgId} onChange={(e) => setOrgId(e.target.value)}>{info.orgs.map((o: any) => <option key={o.id} value={o.id}>{o.name}</option>)}</select>
              </Field>
            )}
            <div className="row" style={{ gap: ".5rem", marginTop: ".75rem" }}>
              <button className="primary" disabled={busy || !orgId} onClick={() => decide(true)}>Add this computer</button>
              <button disabled={busy} onClick={() => decide(false)}>Refuse</button>
            </div>
            {error && <ErrorBox error={error} />}
          </>
        )}
      </div>
    </>
  );
}

export function BrowserConnection() {
  const { org } = useApp();
  const toast = useToast();
  const [saved, setSaved] = useState<Saved | null>(() => read(org.id));
  const [busy, setBusy] = useState(false);
  useEffect(() => setSaved(read(org.id)), [org.id]);
  const add = async () => {
    setBusy(true);
    try {
      const d = describeBrowser();
      const r = await api<any>("POST", `/api/orgs/${org.id}/browser-devices`, { label: d.label, platform: d.platform });
      write(org.id, { id: r.device.id }); setSaved({ id: r.device.id });
      await enablePush(org.id, r.device.id, r.vapid_public_key);
      toast("Browser linked for notifications. Computer protection requires the Windows companion.");
    } catch (e) { toast((e as Error).message); }
    finally { setBusy(false); }
  };
  return <div className="card"><h2>This browser</h2><p>{saved && "id" in saved ? "Registered for Heimdall notifications." : "Not registered for notifications."}</p><p className="muted small">Browser registration delivers alerts and approvals. Web conversations, browsing, and actions inside websites are not intercepted. Install the companion for supported local AI tools; their individual coverage is shown below.</p>{(!saved || !("id" in saved)) && <button disabled={busy} onClick={add}>Enable browser notifications</button>}</div>;
}
