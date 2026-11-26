import { useState } from "react";
import { Link } from "react-router";
import { api, qs, useLoad } from "../api";
import { Badge, Confirm, Empty, ErrorBox, Loading, PageHeader, Pager, SecretModal, Time, useApp, useCan, useToast } from "../ui";
import { KeyForm } from "./Agents";

export function Credentials() {
  const { org } = useApp();
  const can = useCan("admin");
  const toast = useToast();
  const { data, error, loading, reload } = useLoad<any>(`/api/orgs/${org.id}/credentials`);
  const agents = useLoad<any>(`/api/orgs/${org.id}/agents${qs({ status: "active", limit: 100 })}`);
  const [creating, setCreating] = useState(false);
  const [secret, setSecret] = useState<string | null>(null);
  const [revoke, setRevoke] = useState<any>(null);
  const [replace, setReplace] = useState<any>(null);
  return (
    <div className="stack">
      <PageHeader title="Credentials" subtitle="Integration keys let one agent request decisions or report events. A key can never approve requests or open this dashboard." actions={can && <button className="primary" disabled={!agents.data?.items.length} onClick={() => setCreating(true)}>Create key</button>} />
      <ErrorBox error={error} retry={reload} />
      {loading && !data ? <Loading /> : data && (
        <div className="card" style={{ padding: 0 }}>
          {data.items.length === 0 ? <Empty title="No keys yet">Create a key for an active agent to connect it.</Empty> : (
            <div className="table-wrap"><table>
              <caption className="skip">Integration keys</caption>
              <thead><tr><th>Name</th><th>Agent</th><th>Prefix</th><th>Can</th><th>Created</th><th>Last used</th><th>Status</th>{can && <th><span className="skip">Actions</span></th>}</tr></thead>
              <tbody>{data.items.map((c: any) => (
                <tr key={c.id}>
                  <td>{c.name}</td><td><Link to={`/agents/${c.agent_id}`}>{c.agent_name}</Link> <span className="muted small">{c.environment}</span></td>
                  <td><code>asg_{c.prefix}_…</code></td><td className="small">{c.scopes.map((s: string) => (s === "actions" ? "request decisions" : "report events")).join(", ")}</td>
                  <td><Time value={c.created_at} /></td><td><Time value={c.last_used_at} /></td>
                  <td>{c.revoked_at ? <Badge tone="bad">Revoked <Time value={c.revoked_at} /></Badge> : <Badge tone="ok">Active</Badge>}</td>
                  {can && <td className="nowrap">{!c.revoked_at && <><button onClick={() => setReplace(c)}>Replace</button> <button className="danger" onClick={() => setRevoke(c)}>Revoke</button></>}</td>}
                </tr>))}</tbody>
            </table></div>
          )}
        </div>
      )}
      <p className="muted small">Keys are shown in full once, when created. We keep only a one-way hash, so a lost key must be replaced. Store keys in your server’s secret manager, never in source code or browser code.</p>
      {creating && <KeyForm agents={agents.data?.items ?? []} onClose={() => setCreating(false)} onCreated={(s) => { setCreating(false); setSecret(s); reload(); }} />}
      {secret && <SecretModal secret={secret} onClose={() => setSecret(null)} />}
      {revoke && <Confirm title="Revoke this key?" confirmLabel="Revoke key" body={<>Anything using <strong>{revoke.name}</strong> for <strong>{revoke.agent_name}</strong> stops working immediately and fails closed (nothing is authorized).</>} onClose={() => setRevoke(null)} onConfirm={async () => { await api("POST", `/api/orgs/${org.id}/credentials/${revoke.id}/revoke`); toast("Key revoked"); reload(); }} />}
      {replace && <Confirm title="Replace this key?" confirmLabel="Revoke and issue a new key" body={<>The old key stops working immediately. You’ll be shown the replacement once; deploy it right away.</>} onClose={() => setReplace(null)} onConfirm={async () => { const r = await api("POST", `/api/orgs/${org.id}/credentials/${replace.id}/replace`); setSecret(r.secret); reload(); }} />}
    </div>
  );
}

export function Audit() {
  const { org } = useApp();
  const can = useCan("admin");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const { data, error, loading, reload } = useLoad<any>(can ? `/api/orgs/${org.id}/audit${qs({ q, page })}` : null);
  if (!can) return <div className="stack"><PageHeader title="Audit log" /><div className="alert info">The audit log is visible to owners and administrators.</div></div>;
  return (
    <div className="stack">
      <PageHeader title="Audit log" subtitle="Who changed what, and notable security events. Entries are append-only at the application level; this is not tamper-proof against someone with direct database access." actions={<button onClick={reload}>Refresh</button>} />
      <div className="toolbar" role="search"><input className="grow" aria-label="Search audit log" placeholder="Search by action or target ID, e.g. credential" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} /></div>
      <ErrorBox error={error} retry={reload} />
      {loading && !data ? <Loading /> : data && (
        <div className="card" style={{ padding: 0 }}>
          {data.items.length === 0 ? <Empty title="No entries">Nothing matches.</Empty> : (
            <div className="table-wrap"><table>
              <caption className="skip">Audit entries</caption>
              <thead><tr><th>When</th><th>Who</th><th>What</th><th>Details</th></tr></thead>
              <tbody>{data.items.map((e: any) => (
                <tr key={e.id}>
                  <td><Time value={e.created_at} /></td>
                  <td>{e.actor_type === "user" ? e.actor_name ?? "User" : e.actor_type === "credential" ? <span title={e.actor_id}>Integration key</span> : "System"}</td>
                  <td><code>{e.action}</code></td>
                  <td className="small muted"><code>{Object.keys(e.metadata ?? {}).length ? JSON.stringify(e.metadata) : ""}</code></td>
                </tr>))}</tbody>
            </table></div>
          )}
          <div style={{ padding: "0 1rem 1rem" }}><Pager total={data.total} limit={data.limit} offset={data.offset} onPage={setPage} /></div>
        </div>
      )}
    </div>
  );
}
