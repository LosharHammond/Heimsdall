import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, useLoad } from "../api";
import { Icon } from "../icons";
import { disableBrowserNotifications, enableBrowserNotifications, browserNotifState } from "../notifier";
import { BrowserConnection, ProtectComputer } from "../device-setup";
import { Discovered } from "./Discovered";
import { Badge, Confirm, Empty, ErrorBox, Field, Loading, Modal, PageHeader, Time, fieldErrors, useApp, useCan, useToast } from "../ui";

const STATUS: Record<string, { label: string; tone?: "ok" | "info" | "warn" | "bad" | "demo"; icon: string; help: string }> = {
  enforcing: { label: "Enforcing", tone: "ok", icon: "shield", help: "A running component is actively preventing or permitting the covered actions." },
  observing_only: { label: "Observing only", tone: "info", icon: "eye", help: "Heimdall can see this but is not preventing anything here." },
  setup_required: { label: "Setup required", icon: "settings", help: "Nothing is covering this yet." },
  degraded: { label: "Degraded", tone: "warn", icon: "warn", help: "This was working or partly working but cannot be relied on right now." },
  unsupported: { label: "Unsupported", tone: "demo", icon: "ban", help: "Heimdall cannot cover this on this platform." },
  not_protected: { label: "Not protected", tone: "bad", icon: "ban", help: "There is no live component covering this. No protection is claimed." },
};
export const StatusBadge = ({ s }: { s: string }) => {
  const m = STATUS[s] ?? STATUS.setup_required;
  return <Badge tone={m.tone} title={m.help}><span className="dot" aria-hidden />{m.label}</Badge>;
};

export default function Protection() {
  const { org, user } = useApp();
  const can = useCan("admin");
  const toast = useToast();
  const p = useLoad<any>(`/api/orgs/${org.id}/protection`);
  const devices = useLoad<any>(`/api/orgs/${org.id}/devices`);
  const [adding, setAdding] = useState(false);
  const [enroll, setEnroll] = useState<any>(null);
  const [revoke, setRevoke] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  useEffect(() => {
    const t = setInterval(() => { p.reload(); devices.reload(); }, 10_000);
    return () => clearInterval(t);
  }, [p.reload, devices.reload]);

  const queue = async (id: string, kind: "selftest" | "test_notification") => {
    try {
      await api("POST", `/api/orgs/${org.id}/devices/${id}/commands`, { kind });
      toast(kind === "selftest" ? "Protection test queued. The companion picks it up on its next check-in (within about 15 seconds)." : "Test notification queued for the device.");
      devices.reload();
    } catch (e) {
      toast((e as Error).message);
    }
  };
  const steps = p.data?.onboarding ?? [];
  const done = steps.filter((s: any) => s.done).length;

  return (
    <div className="stack">
      <PageHeader title="Protection Center" subtitle="What is protected, how we know, and what is not. Each layer is separate: there is no overall “protected” badge." actions={can && <button onClick={() => setAdding(true)}>Add a device by hand</button>} />
      <BrowserConnection />
      <ProtectComputer />
      {can && <DeviceApproval />}
      <Discovered />
      <ErrorBox error={p.error} retry={p.reload} />
      {p.loading && !p.data ? <Loading kind="dashboard" /> : p.data && (
        <>
          <div className="alert info small" role="note">{p.data.notice} Statuses reflect the last evidence received, <Time value={p.data.generated_at} relativeToo />.</div>

          <section className="card" aria-labelledby="h-onb">
            <div className="row between"><h2 id="h-onb">Set up and verify</h2><Badge tone={done === steps.length ? "ok" : undefined}>{done} of {steps.length} steps verified</Badge></div>
            <p className="muted small">Setup progress only. Completing every step does not mean everything on your computer is protected; read each layer below for its exact scope.</p>
            <ol className="steps">
              {steps.map((s: any, i: number) => (
                <li key={s.id} className={s.done ? "done" : ""}>
                  <span className="step-ic" aria-hidden>{s.done ? <Icon name="check" size={16} /> : i + 1}</span>
                  <div>
                    <strong>{s.title}</strong> {s.done && <Badge tone="ok">verified</Badge>}
                    <div className="muted small">{s.detail}</div>
                    {s.id === "agent" && !s.done && <Link to="/agents" className="small">Register an agent</Link>}
                    {s.id === "device" && !s.done && can && <button className="link small" onClick={() => setAdding(true)}>Add a device</button>}
                  </div>
                </li>
              ))}
            </ol>
            {p.data.last_selftest && (
              <div className="small" style={{ marginTop: ".6rem" }}>
                Last protection test: <Badge tone={p.data.last_selftest.result?.passed ? "ok" : p.data.last_selftest.status === "done" ? "bad" : undefined}>{p.data.last_selftest.status === "done" ? (p.data.last_selftest.result?.passed ? "all checks passed" : "a check failed") : p.data.last_selftest.status}</Badge>{" "}
                {p.data.last_selftest.completed_at && <Time value={p.data.last_selftest.completed_at} relativeToo />} · <button className="link" onClick={() => setResult(p.data.last_selftest.result)}>View checks</button>
              </div>
            )}
          </section>

          <div className="grid cols-2">
            {p.data.layers.map((l: any) => <LayerCard key={l.key} l={l} />)}
          </div>
        </>
      )}

      <section className="card" aria-labelledby="h-dev">
        <div className="row between"><h2 id="h-dev">Enrolled devices</h2>{can && <button onClick={() => setAdding(true)}>Add a device</button>}</div>
        {devices.loading && !devices.data ? <Loading /> : !devices.data?.items.length ? (
          <Empty icon="agents" title="No devices yet">Answer “Yes” when the dashboard asks to add this device, or start the Heimdall app on a computer: it asks to join and you confirm here. Heimdall never inspects a device that has not been enrolled by its user.</Empty>
        ) : (
          <div className="table-wrap"><table>
            <caption className="skip">Enrolled devices</caption>
            <thead><tr><th>Device</th><th>Companion</th><th>Notifications</th><th>Optional telemetry (consent)</th><th><span className="skip">Actions</span></th></tr></thead>
            <tbody>{devices.data.items.map((d: any) => (
              <tr key={d.id}>
                <td><strong>{d.name}</strong><div className="muted small">{d.kind === "browser" ? <>Browser · {d.platform}</> : <>{d.platform} · v{d.companion_version ?? "?"}</>}</div></td>
                <td><Badge tone={d.connection.state === "online" ? "ok" : d.connection.state === "stale" ? "warn" : d.connection.state === "offline" || d.connection.state === "revoked" || d.connection.state === "removed" ? "bad" : undefined}><span className="dot" aria-hidden />{d.connection.label}</Badge><div className="muted small">{d.last_heartbeat_at ? <>heartbeat <Time value={d.last_heartbeat_at} relativeToo /></> : "no heartbeat yet"}</div></td>
                <td className="small">{d.notification_state ? d.notification_state.replace(/_/g, " ") : "unknown"}</td>
                <td className="small">{d.consent?.os_security ? "OS security status" : "—"}{d.consent?.process_inventory ? " · process names" : ""}{!d.consent?.os_security && !d.consent?.process_inventory ? <span className="muted">none (default)</span> : null}</td>
                <td className="nowrap">{d.kind === "browser" ? (d.status === "active" && (d.user_id === user.id || can) && <>{d.user_id === user.id && <button onClick={async () => { try { await api("POST", `/api/orgs/${org.id}/browser-devices/${d.id}/test`); toast("Test notification sent to this browser."); } catch (x) { toast((x as Error).message); } }}>Test notification</button>} <button className="danger" onClick={() => setRevoke(d)}>Remove</button></>) : can && d.status === "active" && <><button onClick={() => queue(d.id, "test_notification")}>Test notification</button> <button onClick={() => queue(d.id, "selftest")}>Run protection test</button> <button className="danger" onClick={() => setRevoke(d)}>Remove</button></>}</td>
              </tr>))}</tbody>
          </table></div>
        )}
      </section>

      <BrowserNotifications />

      {adding && <AddDevice onClose={() => setAdding(false)} onCreated={(r) => { setAdding(false); setEnroll(r); devices.reload(); }} />}
      {enroll && <EnrollModal data={enroll} onClose={() => { setEnroll(null); p.reload(); devices.reload(); }} />}
      {revoke && <Confirm title="Remove this device?" confirmLabel="Remove device" body={<><strong>{revoke.name}</strong> will be signed out of Heimdall immediately. Its companion removes only Heimdall’s own startup entry and credentials. Anything its executor decided offline is limited to the cached policy’s expiry.</>} onClose={() => setRevoke(null)} onConfirm={async () => { await api("POST", `/api/orgs/${org.id}/devices/${revoke.id}/revoke`); toast("Device removed"); devices.reload(); p.reload(); }} />}
      {result && <Modal title="Protection test checks" onClose={() => setResult(null)}>
        <p className="muted small">{result.scope}</p>
        <ul className="list-plain">{(result.checks ?? []).map((c: any) => <li key={c.name} className="row" style={{ flexWrap: "nowrap", alignItems: "flex-start" }}><Badge tone={c.skipped ? undefined : c.pass ? "ok" : "bad"}>{c.skipped ? "Skipped" : c.pass ? "Pass" : "Fail"}</Badge><span><strong>{c.name}</strong><div className="muted small">{c.detail}</div></span></li>)}</ul>
      </Modal>}
    </div>
  );
}

function LayerCard({ l }: { l: any }) {
  const m = STATUS[l.status] ?? STATUS.setup_required;
  return (
    <section className={`card layer ${l.status}`} aria-labelledby={`l-${l.key}`}>
      <div className="row between" style={{ alignItems: "flex-start" }}>
        <h2 id={`l-${l.key}`} style={{ marginBottom: ".35rem" }}>{l.title}</h2>
        <StatusBadge s={l.status} />
      </div>
      <p style={{ margin: "0 0 .6rem" }}>{l.summary}</p>
      {l.evidence.length > 0 && (
        <>
          <div className="small muted" style={{ fontWeight: 600 }}>Evidence</div>
          <ul className="small" style={{ margin: ".2rem 0 .6rem", paddingLeft: "1.1rem" }}>{l.evidence.slice(0, 6).map((e: string, i: number) => <li key={i}>{e}</li>)}</ul>
        </>
      )}
      <dl className="kv" style={{ gridTemplateColumns: "92px 1fr" }}>
        <dt>Last check</dt><dd>{l.last_check ? <Time value={l.last_check} relativeToo /> : <span className="muted">never</span>}</dd>
        <dt>Exact scope</dt><dd className="small">{l.scope}</dd>
      </dl>
      {l.items?.length > 0 && (
        <details style={{ marginTop: ".5rem" }}>
          <summary className="small">Details for {l.items.length} item{l.items.length === 1 ? "" : "s"}</summary>
          <ul className="list-plain small">{l.items.map((i: any, k: number) => <li key={k} className="row between"><span>{i.name}<div className="muted">{i.detail}</div></span><StatusBadge s={i.status} /></li>)}</ul>
        </details>
      )}
      <details style={{ marginTop: ".4rem" }}>
        <summary className="small">What this does not cover</summary>
        <ul className="small" style={{ margin: ".3rem 0 0", paddingLeft: "1.1rem" }}>{l.limits.map((x: string, i: number) => <li key={i}>{x}</li>)}</ul>
      </details>
      <span className="skip">{m.help}</span>
    </section>
  );
}

function AddDevice({ onClose, onCreated }: { onClose: () => void; onCreated: (r: any) => void }) {
  const { org } = useApp();
  const [name, setName] = useState("");
  const [err, setErr] = useState<Error | null>(null);
  return (
    <Modal title="Add a device" onClose={onClose}>
      <form className="form" onSubmit={async (e) => { e.preventDefault(); try { onCreated(await api("POST", `/api/orgs/${org.id}/devices`, { name, platform: "windows" })); } catch (x) { setErr(x as Error); } }}>
        <p className="muted small" style={{ margin: 0 }}><strong>Easiest:</strong> on the computer, run <code>npm run companion -- --url {location.origin}</code>. It opens this dashboard with a code; an administrator clicks Add and the computer is protected from then on (it also starts at sign-in). Browsers are added by answering “Yes” to the prompt at the top of the dashboard.</p>
        <p className="muted small" style={{ margin: 0 }}>Or create a token below and enroll by hand. Windows only. The person who uses the computer runs a command on it; nothing is installed or inspected remotely. Optional telemetry (Windows Security status, process names) is off unless that person turns it on.</p>
        <Field label="Device name" hint="For example: Ama’s laptop" error={fieldErrors(err).name}><input required maxLength={120} value={name} onChange={(e) => setName(e.target.value)} /></Field>
        {err && !fieldErrors(err).name && <ErrorBox error={err} />}
        <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" onClick={onClose}>Cancel</button><button className="primary">Create enrollment token</button></div>
      </form>
    </Modal>
  );
}

function EnrollModal({ data, onClose }: { data: any; onClose: () => void }) {
  const { org } = useApp();
  const toast = useToast();
  const live = useLoad<any>(`/api/orgs/${org.id}/devices/${data.id}`);
  useEffect(() => { const t = setInterval(live.reload, 3000); return () => clearInterval(t); }, [live.reload]);
  const enrolled = live.data && live.data.status === "active";
  const cmd = `npm run companion -- enroll --url ${location.origin} --token ${data.enrollment_token} --startup`;
  return (
    <Modal title="Enroll the device" onClose={onClose}>
      <div className="stack">
        <div className={`alert ${enrolled ? "ok" : "info"}`} role="status" aria-live="polite">{enrolled ? <><strong>Enrolled.</strong> Waiting for heartbeats ({live.data.connection.label}).</> : <><span className="spinner" aria-hidden /> <strong>Waiting for the device to enroll…</strong></>}</div>
        <p className="small muted" style={{ margin: 0 }}>Run this on the Windows computer, in the Heimdall project folder. The token works once and expires at <Time value={data.expires_at} />. It is shown only now.</p>
        <pre className="block" style={{ userSelect: "all" }}>{cmd}</pre>
        <div className="row"><button onClick={() => navigator.clipboard?.writeText(cmd).then(() => toast("Copied"), () => toast("Copy failed: select and copy manually"))}>Copy command</button></div>
        <ul className="small" style={{ margin: 0, paddingLeft: "1.1rem" }}>
          <li><code>--startup</code> starts the companion when <em>this user signs in</em>. Nothing runs before sign-in.</li>
          {data.signing_key_id && <li>Policy signing key id: <code>{data.signing_key_id}</code>. The companion prints the same id when it enrolls; they should match.</li>}
          <li>To remove everything Heimdall added later: <code>npm run companion -- uninstall</code>.</li>
        </ul>
        <div className="row" style={{ justifyContent: "flex-end" }}><button className="primary" onClick={onClose}>Done</button></div>
      </div>
    </Modal>
  );
}

function BrowserNotifications() {
  const [s, setS] = useState(browserNotifState());
  const toast = useToast();
  return (
    <section className="card" aria-labelledby="h-bn">
      <h2 id="h-bn">Browser notifications (this dashboard only)</h2>
      <p className="small muted">While this dashboard is loaded (open, minimized or in a background tab) Heimdall can show a desktop notification for new incidents. When the tab or browser is closed, <strong>nothing is delivered by the browser</strong>: install the device companion for that. Browsers also decide whether to show notifications (Do Not Disturb and per-site settings still apply).</p>
      <div className="row">
        <Badge tone={s.enabled ? "ok" : s.permission === "denied" ? "bad" : undefined}>{!s.supported ? "Not supported in this browser" : s.permission === "denied" ? "Blocked in browser settings" : s.enabled ? "Enabled" : "Off"}</Badge>
        {s.supported && !s.enabled && s.permission !== "denied" && <button className="primary" onClick={async () => { setS(await enableBrowserNotifications()); toast("Browser notifications requested"); }}>Enable in this browser</button>}
        {s.enabled && <button onClick={() => { disableBrowserNotifications(); setS(browserNotifState()); }}>Turn off</button>}
        {s.enabled && <button onClick={async () => { const reg = await navigator.serviceWorker.ready; await reg.showNotification("Heimdall test", { body: "A test notification from the dashboard.", tag: "dashboard-test" }); }}>Send a test</button>}
      </div>
    </section>
  );
}

function DeviceApproval() {
  const { org } = useApp();
  const toast = useToast();
  const info = useLoad<any>(`/api/orgs/${org.id}/installer`);
  if (!info.data) return null;
  return (
    <label className="row small" style={{ gap: ".5rem", margin: ".25rem 0 1rem" }}>
      <input type="checkbox" checked={info.data.approval_required} onChange={async (e) => {
        try { await api("PUT", `/api/orgs/${org.id}/device-settings`, { device_approval_required: e.target.checked }); toast(e.target.checked ? "New computers now wait for an administrator." : "Computers are added as soon as someone opens the app they downloaded."); info.reload(); } catch (x) { toast((x as Error).message); }
      }} />
      Computers added from a download wait for an administrator to confirm them
    </label>
  );
}
