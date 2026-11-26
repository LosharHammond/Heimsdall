import { useState } from "react";
import { useSearchParams } from "react-router";
import { qs, useLoad } from "../api";
import { Badge, DecisionBadge, DemoBadge, Empty, ErrorBox, Loading, OP_LABEL, PageHeader, Pager, STATE_LABEL, StateBadge, Time, useApp } from "../ui";
import { ActionDrawer } from "./Agents";

export default function Activity() {
  const { org } = useApp();
  const [sp, setSp] = useSearchParams();
  const f = { q: sp.get("q") ?? "", agent_id: sp.get("agent") ?? "", decision: sp.get("decision") ?? "", operation: sp.get("operation") ?? "", state: sp.get("state") ?? "", demo: sp.get("demo") ?? "", page: Number(sp.get("page") ?? 1) };
  const set = (k: string, v: string | number) => {
    const n = new URLSearchParams(sp);
    const key = k === "agent_id" ? "agent" : k;
    if (v === "" || v === 1) n.delete(key); else n.set(key, String(v));
    if (k !== "page") n.delete("page");
    setSp(n, { replace: true });
  };
  const agents = useLoad<any>(`/api/orgs/${org.id}/agents?limit=100`);
  const { data, error, loading, reload } = useLoad<any>(`/api/orgs/${org.id}/actions${qs({ ...f, limit: 25 })}`);
  const [open, setOpen] = useState<string | null>(null);
  return (
    <div className="stack">
      <PageHeader
        title="Activity"
        subtitle="Every authorization decision and what the executor reported afterwards. A decision is not an execution; the Result column shows what was actually confirmed."
        actions={<button onClick={reload}>Refresh</button>}
      />
      <div className="toolbar" role="search">
        <input className="grow" aria-label="Search activity" placeholder="Search tool, resource, agent or request ID" value={f.q} onChange={(e) => set("q", e.target.value)} />
        <select aria-label="Agent" value={f.agent_id} onChange={(e) => set("agent_id", e.target.value)}><option value="">All agents</option>{agents.data?.items.map((a: any) => <option key={a.id} value={a.id}>{a.name} ({a.environment})</option>)}</select>
        <select aria-label="Decision" value={f.decision} onChange={(e) => set("decision", e.target.value)}><option value="">Any decision</option><option value="allow">Allowed</option><option value="deny">Denied</option><option value="require_approval">Needs approval</option></select>
        <select aria-label="Operation" value={f.operation} onChange={(e) => set("operation", e.target.value)}><option value="">Any operation</option>{Object.entries(OP_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
        <select aria-label="Result" value={f.state} onChange={(e) => set("state", e.target.value)}><option value="">Any result</option>{Object.entries(STATE_LABEL).map(([k, v]) => <option key={k} value={k}>{v[0]}</option>)}</select>
        <select aria-label="Source" value={f.demo} onChange={(e) => set("demo", e.target.value)}><option value="">Demonstration and real</option><option value="false">Real only</option><option value="true">Demonstration only</option></select>
      </div>
      <ErrorBox error={error} retry={reload} />
      {loading && !data ? <Loading /> : data && (
        <div className="card" style={{ padding: 0 }}>
          {data.items.length === 0 ? (
            <Empty title="No matching activity">{Object.values({ ...f, page: "" }).some(Boolean) ? "Try clearing some filters." : "Decisions appear here once an agent requests authorization."}</Empty>
          ) : (
            <div className="table-wrap"><table>
              <caption className="skip">Authorization decisions and results</caption>
              <thead><tr><th>When</th><th>Agent</th><th>Action</th><th>Decision</th><th>Result</th></tr></thead>
              <tbody>
                {data.items.map((x: any) => (
                  <tr key={x.id} className="click" tabIndex={0} onClick={() => setOpen(x.id)} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setOpen(x.id)} aria-label={`${OP_LABEL[x.operation]} ${x.resource}, ${x.decision}`}>
                    <td><Time value={x.created_at} /></td>
                    <td>{x.agent_name}</td>
                    <td>{OP_LABEL[x.operation]} <code>{x.resource}</code>{x.destination && <div className="muted small">→ {x.destination}</div>} {x.is_demo && <DemoBadge />} {x.source === "offline_cache" && <Badge tone="warn" title="Decided locally from the signed policy cache while the service was unreachable">Offline</Badge>} {x.source === "local_fast" && <Badge tone="info" title="Decided in-process by the executor's fast path from the signed policy, then synced and re-checked by the service">Fast path</Badge>}</td>
                    <td><DecisionBadge d={x.decision} policyDecision={x.policy_decision} /><div className="muted small"><code>{x.reason_code}</code></div></td>
                    <td><StateBadge s={x.state} /></td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
          <div style={{ padding: "0 1rem 1rem" }}><Pager total={data.total} limit={data.limit} offset={data.offset} onPage={(p) => set("page", p)} /></div>
        </div>
      )}
      {open && <ActionDrawer id={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
