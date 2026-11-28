/**
 * One answer at the top of the dashboard: is anything protected right now? Two things Heimdall can protect, each with one
 * button to start: the AI apps on a Windows computer (the Heimdall app) and AI chat websites in this browser (the extension).
 * Both statuses come from evidence (check-ins in the last 20 minutes), never from a setting.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, useLoad } from "./api";
import { describeBrowser } from "./device-setup";
import { ErrorBox, Spinner, useApp, useToast } from "./ui";

const FRESH = 20 * 60_000;
const fresh = (t?: string | null) => !!t && Date.now() - new Date(t).getTime() < FRESH;
const AI_SITES = ["ChatGPT", "Claude", "Gemini", "Copilot", "Perplexity", "DeepSeek", "Grok", "Mistral", "Meta AI", "Poe"];
const TEST_KEY = "sk-proj-HEIMDALLTEST0000000000000000000000000";

/** Is the Heimdall extension installed in this browser, and is it linked? (connect.js tells the page.) */
function useExtension() {
  const [ext, setExt] = useState<{ installed: boolean; connected: boolean; agentName: string }>(() => ({
    installed: !!document.documentElement.getAttribute("data-heimdall-guard"), connected: false, agentName: "",
  }));
  useEffect(() => {
    const on = (e: MessageEvent) => {
      if (e.source !== window || e.origin !== location.origin) return;
      if (e.data?.type === "heimdall-guard-status") setExt({ installed: true, connected: !!e.data.connected, agentName: e.data.agentName || "" });
      if (e.data?.type === "heimdall-guard-connected" && e.data.ok) setExt({ installed: true, connected: true, agentName: e.data.agentName || "" });
    };
    window.addEventListener("message", on);
    const t = setInterval(() => { if (document.documentElement.getAttribute("data-heimdall-guard")) setExt((x) => (x.installed ? x : { ...x, installed: true })); }, 1500);
    return () => { window.removeEventListener("message", on); clearInterval(t); };
  }, []);
  return [ext, setExt] as const;
}

const Check = () => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5" /></svg>;
const Shield = ({ ok }: { ok: boolean }) => (
  <svg width="56" height="56" viewBox="0 0 24 24" aria-hidden="true">
    <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill={ok ? "var(--ok)" : "var(--straw)"} />
    {ok ? <path d="m8.2 12.2 2.6 2.6 5-5.2" stroke="#fff" strokeWidth="2.2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      : <path d="M12 7v6M12 16.5v.5" stroke="var(--dusk)" strokeWidth="2.4" strokeLinecap="round" />}
  </svg>
);

export function ProtectionHero() {
  const { org } = useApp();
  const tools = useLoad<any>(`/api/orgs/${org.id}/discovered`);
  const guard = useLoad<any>(`/api/orgs/${org.id}/browser-guard`);
  const [ext] = useExtension();
  useEffect(() => { const t = setInterval(() => { tools.reload(); guard.reload(); }, 8000); return () => clearInterval(t); }, [tools.reload, guard.reload]);

  const items: any[] = tools.data?.items ?? [];
  const protectedTools = items.filter((t) => t.protection === "protected" && fresh(t.last_seen_at));
  const restart = items.filter((t) => t.protection === "restart_needed" && fresh(t.last_seen_at));
  const computers = [...new Set(items.filter((t) => fresh(t.last_seen_at)).map((t) => t.device_name))];
  const browsers: any[] = guard.data?.browsers ?? [];
  const liveBrowsers = browsers.filter((b) => fresh(b.last_seen_at));
  const appsOn = protectedTools.length > 0;
  const browserOn = liveBrowsers.length > 0 || ext.connected;
  const all = appsOn && browserOn;
  const some = appsOn || browserOn;
  const tone = all ? "ok" : some ? "part" : "off";
  const blocked = browsers.reduce((n, b) => n + (b.stopped_24h || 0), 0);

  return (
    <section className={`ph ph-${tone}`} aria-live="polite">
      <div className="ph-top">
        <Shield ok={some} />
        <div>
          <p className="ph-eyebrow">{tone === "ok" ? "Fully protected" : tone === "part" ? "Partly protected" : "Not protected yet"}</p>
          <h1>{tone === "ok" ? "You’re protected." : tone === "part" ? (appsOn ? "Your AI apps are protected." : "This browser is protected.") : "Let’s protect your AI tools."}</h1>
          <p className="ph-sub">
            {some ? <>Heimdall checked in {computers.length ? <>from <b>{computers.length}</b> computer{computers.length === 1 ? "" : "s"}</> : null}{computers.length && liveBrowsers.length ? " and " : ""}{liveBrowsers.length ? <><b>{liveBrowsers.length}</b> browser{liveBrowsers.length === 1 ? "" : "s"}</> : null} in the last 20 minutes{blocked ? <> · <b>{blocked}</b> risky {blocked === 1 ? "action" : "actions"} stopped today</> : null}. <Link to="/live">Watch it live →</Link></>
              : <>Two one-click steps. Each card below turns green by itself as soon as protection is running — no project folder, no commands.</>}
          </p>
        </div>
      </div>
      <div className="ph-cards">
        <AppsCard on={appsOn} tools={protectedTools} restart={restart} stale={items.filter((t) => t.protectable && !fresh(t.last_seen_at)).length > 0 && !appsOn} />
        <BrowserCard on={browserOn} ext={ext} browsers={liveBrowsers} webstore={guard.data?.webstore_url} onDone={guard.reload} />
      </div>
    </section>
  );
}

function AppsCard({ on, tools, restart, stale }: { on: boolean; tools: any[]; restart: any[]; stale: boolean }) {
  const { org } = useApp();
  const info = useLoad<any>(`/api/orgs/${org.id}/installer`);
  const [state, setState] = useState<"idle" | "busy" | "waiting">("idle");
  const [error, setError] = useState<Error | null>(null);
  const windows = describeBrowser().platform === "windows";
  const download = async () => {
    setState("busy"); setError(null);
    try {
      const r = await api<{ download_url: string }>("POST", `/api/orgs/${org.id}/device-installs`);
      location.assign(r.download_url);
      setState("waiting");
    } catch (e) { setError(e as Error); setState("idle"); }
  };
  return (
    <article className={`ph-card ${on ? "on" : ""}`}>
      <header><span className="ph-ic">🖥</span><div><h2>AI apps on your computer</h2><p>Claude Desktop, Claude Code, Cursor, Windsurf, VS Code</p></div>
        <span className={`ph-chip ${on ? "ok" : restart.length ? "warn" : "off"}`}>{on ? "Protected" : restart.length ? "Restart needed" : "Off"}</span></header>
      {on ? (
        <>
          <ul className="ph-list">{tools.slice(0, 6).map((t) => <li key={t.id ?? t.key + t.device_name}><Check /> <b>{t.product}</b> <span className="muted">on {t.device_name}</span></li>)}</ul>
          {restart.length > 0 && <p className="ph-note warn">Restart {restart.map((t) => t.product).join(", ")} once to finish.</p>}
          <p className="ph-foot">Keys, saved passwords and dangerous commands are refused; deleting and sending data out wait for your approval. <Link to="/protection">Details</Link></p>
        </>
      ) : (
        <>
          {stale && <p className="ph-note warn">The Heimdall app stopped checking in. Restart the computer or download setup again.</p>}
          {state === "waiting" ? (
            <div className="ph-wait" role="status">
              <p><Spinner label="Waiting" /> <b>Waiting for your computer…</b> This card turns green by itself.</p>
              <ol className="ph-steps">
                <li className="done"><b>Downloaded</b> Heimdall-Setup</li>
                <li><b>Open it</b> from your browser’s downloads bar. If Windows asks, choose <i>More info → Run anyway</i>.</li>
                <li><b>Restart</b> Claude, Cursor or VS Code once.</li>
              </ol>
              <button className="ghost" onClick={download}>Download again</button>
            </div>
          ) : (
            <>
              <ol className="ph-steps">
                <li><b>Download</b> Heimdall for Windows{info.data?.size ? ` (${Math.round(info.data.size / 1e6)} MB)` : ""}</li>
                <li><b>Open</b> the downloaded file — it installs, links to your account and starts with Windows</li>
                <li><b>Done.</b> This card turns green</li>
              </ol>
              <button className="primary big" disabled={state === "busy" || info.data?.available === false} onClick={download}>
                {state === "busy" ? <Spinner label="Preparing" /> : <>⬇ Download for Windows</>}
              </button>
              {!windows && <p className="ph-note">You’re on {describeBrowser().label}. Download here and open it on the Windows PC you want to protect, or open this page on that PC.</p>}
              {info.data?.available === false && <p className="ph-note">The Windows download is being published. Reload in a few minutes.</p>}
            </>
          )}
          <ErrorBox error={error} />
        </>
      )}
    </article>
  );
}

function BrowserCard({ on, ext, browsers, webstore, onDone }: { on: boolean; ext: { installed: boolean; connected: boolean; agentName: string }; browsers: any[]; webstore?: string | null; onDone: () => void }) {
  const { org } = useApp();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [guide, setGuide] = useState(() => new URLSearchParams(location.search).get("guard") === "guide");
  const thisBrowser = describeBrowser();
  const chromium = /Chrome|Edge|Opera|Brave/.test(thisBrowser.label);
  const connect = async () => {
    setBusy(true); setError(null);
    try {
      const r = await api<{ api_key: string; api_url: string; agent_name: string }>("POST", `/api/orgs/${org.id}/browser-guard`, { browser: thisBrowser.label });
      const done = new Promise<boolean>((res) => {
        const on = (e: MessageEvent) => { if (e.source === window && e.data?.type === "heimdall-guard-connected") { window.removeEventListener("message", on); res(!!e.data.ok); } };
        window.addEventListener("message", on);
        setTimeout(() => res(false), 10000);
      });
      window.postMessage({ type: "heimdall-guard-connect", apiKey: r.api_key, apiUrl: location.origin, agentName: r.agent_name }, location.origin);
      if (await done) { toast("This browser is protected."); onDone(); }
      else throw new Error("The extension didn’t answer. Reload this page and try again.");
    } catch (e) { setError(e as Error); }
    finally { setBusy(false); }
  };
  const copyTest = async () => { try { await navigator.clipboard.writeText(TEST_KEY); toast("Copied a harmless test key. Paste it into ChatGPT or Claude — Heimdall will stop it."); } catch { toast(`Copy this test key: ${TEST_KEY}`); } };
  const status = on ? "Protected" : ext.installed ? "Not linked" : "Off";
  return (
    <article className={`ph-card ${on ? "on" : ""}`}>
      <header><span className="ph-ic">🌐</span><div><h2>AI chats in your browser</h2><p>{AI_SITES.slice(0, 5).join(", ")} and {AI_SITES.length - 5} more</p></div>
        <span className={`ph-chip ${on ? "ok" : ext.installed ? "warn" : "off"}`}>{status}</span></header>
      {on ? (
        <>
          <ul className="ph-list">
            {(browsers.length ? browsers : [{ id: "this", name: ext.agentName || "This browser", checked_24h: 0, stopped_24h: 0 }]).slice(0, 5).map((b) =>
              <li key={b.id}><Check /> <b>{b.name.replace(/^Browser guard: /, "")}</b> <span className="muted">{b.stopped_24h ? `${b.stopped_24h} stopped today` : "nothing risky today"}</span></li>)}
          </ul>
          <p className="ph-foot">Passwords, API keys, private keys and card numbers can’t be pasted or sent into AI chats; personal-data lists wait for approval. The text itself never leaves the browser.</p>
          <button className="ghost" onClick={copyTest}>Try it: copy a harmless test key</button>
          {!ext.installed && <p className="ph-note">Open this page in each browser you use to protect it too.</p>}
        </>
      ) : ext.installed ? (
        <>
          <p>The Heimdall extension is installed. Link it to your account so its blocks and approvals show here.</p>
          <button className="primary big" onClick={connect} disabled={busy}>{busy ? <Spinner label="Linking" /> : "Protect this browser"}</button>
          <p className="ph-note">Even before linking, it already blocks secrets on its own.</p>
        </>
      ) : !chromium ? (
        <p className="ph-note">The browser guard works in Chrome, Edge, Brave and Opera. Open this page in one of them to add it.</p>
      ) : (
        <>
          <ol className="ph-steps">
            <li><b>Add</b> the Heimdall extension to {thisBrowser.label.split(" on ")[0]}</li>
            <li><b>Click “Protect this browser”</b> here — it appears by itself</li>
            <li><b>Done.</b> Secrets can’t reach AI chats</li>
          </ol>
          {webstore ? (
            <a className="btn primary big" href={webstore} target="_blank" rel="noopener">＋ Add to {thisBrowser.label.split(" on ")[0]} — free</a>
          ) : (
            <>
              <a className="btn primary big" href="/downloads/heimdall-browser-guard.zip" download onClick={() => setGuide(true)}>⬇ Download the browser extension</a>
              {guide && (
                <ol className="ph-guide">
                  <li>Open the downloaded <code>heimdall-browser-guard.zip</code> and choose <b>Extract all</b>.</li>
                  <li>In the address bar type <code>{/Edge/.test(thisBrowser.label) ? "edge://extensions" : "chrome://extensions"}</code> and press Enter.</li>
                  <li>Turn on <b>Developer mode</b> (top right), click <b>Load unpacked</b> and choose the extracted folder.</li>
                  <li>Come back to this tab — the <b>Protect this browser</b> button appears.</li>
                </ol>
              )}
              {!guide && <button className="linklike" onClick={() => setGuide(true)}>How do I install it?</button>}
            </>
          )}
        </>
      )}
      <ErrorBox error={error} />
    </article>
  );
}
