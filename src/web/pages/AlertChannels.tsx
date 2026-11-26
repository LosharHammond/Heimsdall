/** Settings → Alerts to Slack and email, and audit/activity export (docs/ALERTS.md). */
import { useState } from "react";
import { api, useLoad } from "../api";
import { useApp, useCan, useAllowed, useToast, Badge, Confirm, Empty, ErrorBox, Field, Loading, Modal, Time, fieldErrors } from "../ui";

const SEV = { low: "Low and above", medium: "Medium and above", high: "High only" } as const;

export function AlertChannels() {
  const { org } = useApp();
  const toast = useToast();
  const admin = useCan("admin");
  const list = useLoad<any>(`/api/orgs/${org.id}/channels`);
  const [edit, setEdit] = useState<any | null>(null);
  const [remove, setRemove] = useState<any | null>(null);
  const test = async (c: any) => {
    try { await api("POST", `/api/orgs/${org.id}/channels/${c.id}/test`); toast(`Test alert sent to ${c.name}.`); list.reload(); } catch (x) { toast((x as Error).message); list.reload(); }
  };
  return (
    <section className="card" aria-labelledby="h-chan">
      <div className="row between"><h2 id="h-chan">Alerts to Slack and email</h2>{admin && <button onClick={() => setEdit({ kind: "slack", name: "", webhook_url: "", recipients: "", min_severity: "medium", enabled: true })}>Add a channel</button>}</div>
      <p className="muted small">New alerts are sent once to each matching channel, retried if Slack or the mail server is down. Repeats of the same alert only raise its counter.</p>
      {list.loading && !list.data ? <Loading /> : list.error ? <ErrorBox error={list.error} retry={list.reload} /> : !list.data?.items.length ? (
        <Empty icon="alerts" title="No channels yet">{admin ? "Add a Slack incoming webhook or email addresses to hear about incidents outside the dashboard." : "An administrator can send alerts to Slack or email."}</Empty>
      ) : (
        <div className="table-wrap"><table>
          <caption className="skip">Alert channels</caption>
          <thead><tr><th>Channel</th><th>Sends</th><th>Status</th><th><span className="skip">Actions</span></th></tr></thead>
          <tbody>{list.data.items.map((c: any) => (
            <tr key={c.id}>
              <td><strong>{c.name}</strong><div className="muted small">{c.kind === "slack" ? "Slack" : "Email"} · {c.target}</div></td>
              <td className="small">{SEV[c.min_severity as keyof typeof SEV]}{c.enabled ? "" : <> · <Badge>Paused</Badge></>}</td>
              <td className="small">{c.failing ? <Badge tone="bad" title={c.last_error ?? ""}>Failing: {c.last_error ?? "delivery error"}</Badge> : c.last_success_at ? <>Delivered <Time value={c.last_success_at} relativeToo /></> : <span className="muted">Nothing sent yet</span>}</td>
              <td className="nowrap">{admin && <><button onClick={() => test(c)}>Send test</button> <button onClick={() => setEdit({ ...c, webhook_url: "", recipients: "" })}>Edit</button> <button className="danger" onClick={() => setRemove(c)}>Delete</button></>}</td>
            </tr>))}</tbody>
        </table></div>
      )}
      {edit && <ChannelForm initial={edit} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); list.reload(); }} />}
      {remove && <Confirm title="Delete channel?" confirmLabel="Delete" body={<><strong>{remove.name}</strong> will stop receiving alerts.</>} onClose={() => setRemove(null)} onConfirm={async () => { await api("DELETE", `/api/orgs/${org.id}/channels/${remove.id}`); toast("Channel deleted"); list.reload(); }} />}
      <ExportBox />
    </section>
  );
}

function ChannelForm({ initial, onClose, onSaved }: { initial: any; onClose: () => void; onSaved: () => void }) {
  const { org } = useApp();
  const toast = useToast();
  const [f, setF] = useState(initial);
  const [err, setErr] = useState<Error | null>(null);
  const editing = !!initial.id;
  const fe = fieldErrors(err);
  const save = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(null);
    const body: any = { kind: f.kind, name: f.name, min_severity: f.min_severity, enabled: f.enabled };
    if (f.kind === "slack" && f.webhook_url) body.webhook_url = f.webhook_url.trim();
    if (f.kind === "email" && f.recipients) body.recipients = String(f.recipients).split(/[\s,;]+/).filter(Boolean);
    try {
      await api(editing ? "PUT" : "POST", editing ? `/api/orgs/${org.id}/channels/${initial.id}` : `/api/orgs/${org.id}/channels`, body);
      toast(editing ? "Channel saved" : "Channel added. Use “Send test” to check it.");
      onSaved();
    } catch (x) { setErr(x as Error); }
  };
  return (
    <Modal title={editing ? `Edit ${initial.name}` : "Add an alert channel"} onClose={onClose}>
      <form className="form" onSubmit={save}>
        {!editing && <Field label="Send to"><select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}><option value="slack">Slack</option><option value="email">Email</option></select></Field>}
        <Field label="Name" hint="For example: #security-alerts" error={fe.name}><input required maxLength={80} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        {f.kind === "slack" ? (
          <Field label="Slack incoming webhook address" hint={editing ? "Leave empty to keep the current one." : "Slack → Apps → Incoming Webhooks → Add to a channel → copy the address."} error={fe.webhook_url}>
            <input required={!editing} type="url" placeholder="https://hooks.slack.com/services/…" value={f.webhook_url} onChange={(e) => setF({ ...f, webhook_url: e.target.value })} />
          </Field>
        ) : (
          <Field label="Email addresses" hint={editing ? "Leave empty to keep the current list." : "Separate with commas. Up to 20."} error={fe.recipients}>
            <textarea required={!editing} rows={2} value={f.recipients} onChange={(e) => setF({ ...f, recipients: e.target.value })} />
          </Field>
        )}
        <Field label="Which alerts"><select value={f.min_severity} onChange={(e) => setF({ ...f, min_severity: e.target.value })}>{Object.entries(SEV).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Field>
        <label className="row" style={{ gap: ".5rem" }}><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Sending</label>
        {err && !Object.keys(fe).length && <ErrorBox error={err} />}
        <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" onClick={onClose}>Cancel</button><button className="primary">{editing ? "Save" : "Add channel"}</button></div>
      </form>
    </Modal>
  );
}

function ExportBox() {
  const { org } = useApp();
  const can = useAllowed("audit.read");
  const day = (d: Date) => d.toISOString().slice(0, 10);
  const [kind, setKind] = useState("audit");
  const [format, setFormat] = useState("csv");
  const [from, setFrom] = useState(day(new Date(Date.now() - 30 * 86400_000)));
  const [to, setTo] = useState(day(new Date()));
  if (!can) return null;
  const href = `/api/orgs/${org.id}/export?${new URLSearchParams({ kind, format, from: new Date(`${from}T00:00:00`).toISOString(), to: new Date(`${to}T23:59:59.999`).toISOString() })}`;
  return (
    <div style={{ marginTop: "1.5rem" }}>
      <h3>Export</h3>
      <p className="muted small">For auditors and your SIEM. JSON Lines exports end with a manifest signed by this server's policy key, so tampering can be detected (<code>npm run verify-export</code>). CSV cells that could run as spreadsheet formulas are neutralized.</p>
      <div className="row" style={{ alignItems: "end", gap: ".75rem" }}>
        <Field label="What"><select value={kind} onChange={(e) => setKind(e.target.value)}><option value="audit">Audit log</option><option value="activity">Agent activity</option></select></Field>
        <Field label="Format"><select value={format} onChange={(e) => setFormat(e.target.value)}><option value="csv">CSV (spreadsheet)</option><option value="jsonl">JSON Lines (signed)</option></select></Field>
        <Field label="From"><input type="date" value={from} max={to} onChange={(e) => setFrom(e.target.value)} /></Field>
        <Field label="To"><input type="date" value={to} min={from} onChange={(e) => setTo(e.target.value)} /></Field>
        <a className="btn primary" href={href} download>Download</a>
      </div>
    </div>
  );
}
