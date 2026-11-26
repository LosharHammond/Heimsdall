import { useState } from "react";
import { Link } from "react-router";
import { api, qs, useLoad } from "../api";
import { Badge, DemoBadge, Empty, ErrorBox, Field, Loading, Modal, OP_LABEL, PageHeader, Pager, SeverityBadge, Time, useApp, useToast, useAllowed } from "../ui";

export function Approvals() {
  const { org } = useApp();
  const can = useAllowed("approvals.decide");
  const toast = useToast();
  const [status, setStatus] = useState("pending");
  const [page, setPage] = useState(1);
  const { data, error, loading, reload } = useLoad<any>(`/api/orgs/${org.id}/approvals${qs({ status, page })}`);
  const [deciding, setDeciding] = useState<{ a: any; verdict: "approve" | "reject" } | null>(null);
  return (
    <div className="stack">
      <PageHeader title="Approvals" subtitle="A human decision applies to exactly one action, once. Approval for one request never covers a different one." actions={<button onClick={reload}>Refresh</button>} />
      <div className="tabs" role="tablist" aria-label="Approval status">
        {["pending", "approved", "rejected", "expired", ""].map((s) => (
          <button key={s} role="tab" aria-selected={status === s} onClick={() => { setStatus(s); setPage(1); }}>{s ? s[0].toUpperCase() + s.slice(1) : "All"}</button>
        ))}
      </div>
      <ErrorBox error={error} retry={reload} />
      {loading && !data ? <Loading /> : data && (data.items.length === 0 ? (
        <div className="card"><Empty title={status === "pending" ? "Nothing is waiting for approval" : "No approvals in this view"}>Requests appear here when a policy rule requires a human to approve an action.</Empty></div>
      ) : (
        <div className="stack">
          {data.items.map((a: any) => {
            const eff = a.timed_out ? "expired" : a.status;
            return (
              <article key={a.id} className="card" aria-label={`Approval request: ${OP_LABEL[a.operation]} ${a.resource}`}>
                <div className="row between">
                  <div className="row"><Badge tone={eff === "pending" ? "warn" : eff === "approved" ? "ok" : eff === "rejected" ? "bad" : undefined}>{eff[0].toUpperCase() + eff.slice(1)}{a.consumed_at ? " · used" : ""}</Badge>{a.is_demo && <DemoBadge />}<span className="muted small">needs {a.required_role}</span></div>
                  <span className="muted small">Requested <Time value={a.requested_at} relativeToo /></span>
                </div>
                <h2 style={{ marginTop: ".6rem" }}>{OP_LABEL[a.operation]} <code>{a.resource}</code></h2>
                <dl className="kv">
                  <dt>Agent</dt><dd><Link to={`/agents/${a.agent_id}`}>{a.agent_name}</Link> <span className="muted small">{a.environment}</span></dd>
                  <dt>Tool</dt><dd><code>{a.tool}</code></dd>
                  {a.destination && (<><dt>Destination</dt><dd><code>{a.destination}</code></dd></>)}
                  {a.data_classification && (<><dt>Data class (self-declared)</dt><dd>{a.data_classification}</dd></>)}
                  <dt>Why approval</dt><dd>{a.explanation}</dd>
                  <dt>Arguments (redacted)</dt><dd><code>{JSON.stringify(a.args_summary)}</code></dd>
                  <dt>Policy version</dt><dd>{a.policy_version} <span className="muted small">(approval is void if the policy changes)</span></dd>
                  <dt>{eff === "pending" ? "Decide before" : "Expires"}</dt><dd><Time value={a.expires_at} /></dd>
                  {a.decided_at && (<><dt>Decided</dt><dd>{a.decided_by_name} · <Time value={a.decided_at} />{a.decision_note && <> · “{a.decision_note}”</>}</dd></>)}
                </dl>
                {eff === "pending" && (can ? (
                  <div className="row" style={{ marginTop: ".75rem" }}>
                    <button className="primary" onClick={() => setDeciding({ a, verdict: "approve" })}>Approve this action</button>
                    <button className="danger" onClick={() => setDeciding({ a, verdict: "reject" })}>Reject</button>
                  </div>
                ) : <p className="muted small">Only administrators and owners can decide approvals.</p>)}
              </article>
            );
          })}
          <Pager total={data.total} limit={data.limit} offset={data.offset} onPage={setPage} />
        </div>
      ))}
      {deciding && <DecideModal a={deciding.a} verdict={deciding.verdict} onClose={() => setDeciding(null)} onDone={() => { setDeciding(null); toast(deciding.verdict === "approve" ? "Approved. The agent can now run this one action, once." : "Rejected."); reload(); }} />}
    </div>
  );
}

function DecideModal({ a, verdict, onClose, onDone }: { a: any; verdict: "approve" | "reject"; onClose: () => void; onDone: () => void }) {
  const { org } = useApp();
  const [note, setNote] = useState("");
  const [err, setErr] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Modal title={verdict === "approve" ? "Approve this exact action?" : "Reject this action?"} onClose={onClose}>
      <form className="form" onSubmit={async (e) => { e.preventDefault(); setBusy(true); try { await api("POST", `/api/orgs/${org.id}/approvals/${a.id}/${verdict}`, note ? { note } : {}); onDone(); } catch (x) { setErr(x as Error); setBusy(false); } }}>
        <p style={{ margin: 0 }}><strong>{a.agent_name}</strong> wants to <strong>{OP_LABEL[a.operation].toLowerCase()}</strong> <code>{a.resource}</code>{a.destination && <> → <code>{a.destination}</code></>}.</p>
        {verdict === "approve" && <div className="alert warn small">This approval lets the agent run this one action, one time, within 5 minutes. It does not approve anything else.</div>}
        <Field label="Note (optional)"><input maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} /></Field>
        <ErrorBox error={err} />
        <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" onClick={onClose}>Cancel</button><button className={verdict === "approve" ? "primary" : "danger solid"} disabled={busy}>{verdict === "approve" ? "Approve" : "Reject"}</button></div>
      </form>
    </Modal>
  );
}

export function Alerts() {
  const { org } = useApp();
  const can = useAllowed("alerts.manage");
  const toast = useToast();
  const [f, setF] = useState({ status: "open", severity: "", page: 1 });
  const { data, error, loading, reload } = useLoad<any>(`/api/orgs/${org.id}/alerts${qs(f)}`);
  const act = async (id: string, what: "acknowledge" | "resolve") => {
    try { await api("POST", `/api/orgs/${org.id}/alerts/${id}/${what}`); toast(what === "resolve" ? "Alert resolved" : "Alert acknowledged"); reload(); } catch (e) { toast((e as Error).message); }
  };
  return (
    <div className="stack">
      <PageHeader title="Alerts" subtitle="Raised from recorded events: high-risk denials, argument changes after authorization, revoked-key use and execution failures. Repeats are grouped." actions={<button onClick={reload}>Refresh</button>} />
      <div className="toolbar">
        <select aria-label="Status" value={f.status} onChange={(e) => setF({ ...f, status: e.target.value, page: 1 })}><option value="">All statuses</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option></select>
        <select aria-label="Severity" value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value, page: 1 })}><option value="">Any severity</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
      </div>
      <ErrorBox error={error} retry={reload} />
      {loading && !data ? <Loading /> : data && (data.items.length === 0 ? (
        <div className="card"><Empty title="No alerts in this view">Nothing needs investigating right now.</Empty></div>
      ) : (
        <div className="stack">
          {data.items.map((a: any) => (
            <article key={a.id} className="card" aria-label={a.title}>
              <div className="row between">
                <div className="row"><SeverityBadge s={a.severity} /><Badge tone={a.status === "open" ? "warn" : a.status === "resolved" ? "ok" : undefined}>{a.status}</Badge>{a.is_demo && <DemoBadge />}{a.occurrences > 1 && <Badge>seen {a.occurrences}×</Badge>}</div>
                <span className="muted small">Last seen <Time value={a.last_seen_at} relativeToo /></span>
              </div>
              <h2 style={{ marginTop: ".5rem" }}>{a.title}</h2>
              <p style={{ margin: 0 }}>{a.detail}</p>
              <p className="muted small">First seen <Time value={a.created_at} />{a.agent_name && <> · agent <Link to={`/agents/${a.agent_id}`}>{a.agent_name}</Link></>}{a.action_request_id && <> · <Link to={`/activity?q=${encodeURIComponent(a.agent_name ?? "")}`}>View activity</Link></>}{a.handled_by_name && <> · {a.status} by {a.handled_by_name}</>}</p>
              {can && a.status !== "resolved" && (
                <div className="row">
                  {a.status === "open" && <button onClick={() => act(a.id, "acknowledge")}>Acknowledge</button>}
                  <button className="primary" onClick={() => act(a.id, "resolve")}>Mark resolved</button>
                </div>
              )}
            </article>
          ))}
          <Pager total={data.total} limit={data.limit} offset={data.offset} onPage={(p) => setF({ ...f, page: p })} />
        </div>
      ))}
    </div>
  );
}
