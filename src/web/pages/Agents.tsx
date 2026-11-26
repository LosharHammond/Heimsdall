import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { api, qs, useLoad } from "../api";
import {
  Badge, ConnBadge, Confirm, DecisionBadge, DemoBadge, Empty, ErrorBox, Field, Loading, Modal, OP_LABEL, PageHeader, Pager, SecretModal, StateBadge, Time, fieldErrors, useApp, useCan, useToast,
} from "../ui";

const ENV_TONE = { development: undefined, staging: "warn", production: "bad" } as const;

export function Agents() {
  const { org } = useApp();
  const can = useCan("admin");
  const [f, setF] = useState({ q: "", environment: "", status: "", connection: "", page: 1 });
  const { data, error, loading, reload } = useLoad<any>(`/api/orgs/${org.id}/agents${qs({ q: f.q, environment: f.environment, status: f.status, connection: f.connection, page: f.page })}`);
  const [adding, setAdding] = useState(false);
  const [connect, setConnect] = useState<ConnectInfo | null>(null);
  const set = (k: string, v: string) => setF({ ...f, [k]: v, page: 1 });
  return (
    <div className="stack">
      <PageHeader title="Agents" subtitle="AI agents registered in this organization. Registering an agent does not mean it is connected." actions={can && <button className="primary" onClick={() => setAdding(true)}>Register agent</button>} />
      <div className="toolbar" role="search">
        <input className="grow" aria-label="Search agents" placeholder="Search by name or description" value={f.q} onChange={(e) => set("q", e.target.value)} />
        <select aria-label="Environment" value={f.environment} onChange={(e) => set("environment", e.target.value)}><option value="">All environments</option><option value="development">Development</option><option value="staging">Staging</option><option value="production">Production</option></select>
        <select aria-label="Status" value={f.status} onChange={(e) => set("status", e.target.value)}><option value="">Active and revoked</option><option value="active">Active</option><option value="revoked">Revoked</option></select>
        <select aria-label="Connection" value={f.connection} onChange={(e) => set("connection", e.target.value)}><option value="">Any connection</option><option value="not_connected">Registered, not connected</option><option value="connected">Connected, no enforcement yet</option><option value="monitoring">Monitor mode</option><option value="reporting_only">Reporting events only</option><option value="enforcing">Enforcing through adapter</option><option value="revoked">Revoked</option></select>
      </div>
      <ErrorBox error={error} retry={reload} />
      {loading && !data ? <Loading /> : data && (
        <div className="card" style={{ padding: 0 }}>
          {data.items.length === 0 ? (
            <Empty title={f.q || f.environment || f.status || f.connection ? "No agents match these filters" : "No agents yet"}>
              {can ? "Register an agent to start controlling what it may do." : "An administrator can register agents."}
            </Empty>
          ) : (
            <div className="table-wrap"><table>
              <caption className="skip">Registered agents</caption>
              <thead><tr><th>Agent</th><th>Environment</th><th>Connection</th><th>Mode</th><th>Policy</th><th>Last seen</th></tr></thead>
              <tbody>
                {data.items.map((a: any) => (
                  <tr key={a.id}>
                    <td><Link to={`/agents/${a.id}`}><strong>{a.name}</strong></Link><div className="muted small">{a.integration_type === "typescript_sdk" ? "TypeScript SDK (can enforce)" : a.integration_type === "auto_discovered" ? "Found automatically (protected by Heimdall)" : "Event reporting (observe only)"}</div></td>
                    <td><Badge tone={ENV_TONE[a.environment as keyof typeof ENV_TONE]}>{a.environment}</Badge></td>
                    <td><ConnBadge c={a.connection} /></td>
                    <td>{a.integration_type === "event_reporting" ? <span className="muted" title="Event-only agents can be observed but not blocked">Observe only</span> : a.enforcement_mode === "enforce" ? "Enforce" : <span title="Decisions are recorded but not enforced">Monitor</span>}</td>
                    <td>{a.integration_type === "event_reporting" ? <span className="muted">Not applicable</span> : a.policy_name ?? <span className="muted">None (denies everything)</span>}</td>
                    <td><Time value={a.last_seen_at} relativeToo /></td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
          <div style={{ padding: "0 1rem 1rem" }}><Pager total={data.total} limit={data.limit} offset={data.offset} onPage={(p) => setF({ ...f, page: p })} /></div>
        </div>
      )}
      {adding && <AgentForm onClose={() => setAdding(false)} onSaved={(c) => { setAdding(false); setConnect(c); reload(); }} />}
      {connect && <ConnectModal agent={connect} onClose={() => { setConnect(null); reload(); }} />}
    </div>
  );
}

function AgentForm({ onClose, onSaved }: { onClose: () => void; onSaved: (c: ConnectInfo) => void }) {
  const { org } = useApp();
  const policies = useLoad<any>(`/api/orgs/${org.id}/policies`);
  const [f, setF] = useState({ name: "", description: "", environment: "development", integration_type: "typescript_sdk", policy_id: "", enforcement_mode: "enforce" });
  const [err, setErr] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);
  const fe = fieldErrors(err);
  return (
    <Modal title="Register an agent" onClose={onClose}>
      <form className="form" onSubmit={async (e) => {
        e.preventDefault(); setBusy(true); setErr(null);
        try {
          const a = await api("POST", `/api/orgs/${org.id}/agents`, { ...f, policy_id: f.policy_id || null });
          // Registering is only half the job: issue the first key right away so the agent can actually connect.
          const k = await api("POST", `/api/orgs/${org.id}/credentials`, { agent_id: a.id, name: "first key" });
          onSaved({ id: a.id, name: f.name, integration_type: f.integration_type, secret: k.secret, hasPolicy: !!f.policy_id });
        } catch (x) { setErr(x as Error); setBusy(false); }
      }}>
        <Field label="Name" error={fe.name}><input required maxLength={120} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        <Field label="Description" hint="What does this agent do?"><textarea rows={2} maxLength={1000} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        <div className="row">
          <Field label="Environment"><select value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value })}><option value="development">Development</option><option value="staging">Staging</option><option value="production">Production</option></select></Field>
          <Field label="Integration type"><select value={f.integration_type} onChange={(e) => setF({ ...f, integration_type: e.target.value })}><option value="typescript_sdk">TypeScript SDK (authorize and enforce)</option><option value="event_reporting">Event reporting only (observe)</option></select></Field>
        </div>
        {f.integration_type === "typescript_sdk" && (
          <>
            <Field label="Policy" hint="Required for the agent to be allowed to do anything. With no policy, every action is denied."><select value={f.policy_id} onChange={(e) => setF({ ...f, policy_id: e.target.value })}><option value="">None (deny everything)</option>{policies.data?.items.map((p: any) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></Field>
            <Field label="Enforcement mode" hint="Monitor records what the policy would do without stopping anything. Use it to trial a policy."><select value={f.enforcement_mode} onChange={(e) => setF({ ...f, enforcement_mode: e.target.value })}><option value="enforce">Enforce</option><option value="monitor">Monitor only</option></select></Field>
          </>
        )}
        {f.integration_type === "event_reporting" && <div className="alert info small">Event-reporting agents can only <em>tell</em> the dashboard what happened. They cannot be blocked, and nothing they report will ever be labelled “blocked”.</div>}
        {err && !Object.keys(fe).length && <ErrorBox error={err} />}
        <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" onClick={onClose}>Cancel</button><button className="primary" disabled={busy}>{busy ? "Registering…" : "Register and get connection key"}</button></div>
      </form>
    </Modal>
  );
}

export function AgentDetail() {
  const { id } = useParams();
  const { org } = useApp();
  const nav = useNavigate();
  const toast = useToast();
  const can = useCan("admin");
  const a = useLoad<any>(`/api/orgs/${org.id}/agents/${id}`);
  const acts = useLoad<any>(`/api/orgs/${org.id}/actions${qs({ agent_id: id, limit: 8 })}`);
  const policies = useLoad<any>(`/api/orgs/${org.id}/policies`);
  const [edit, setEdit] = useState(false);
  const [revoke, setRevoke] = useState(false);
  const [secret, setSecret] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [openAct, setOpenAct] = useState<any>(null);
  if (a.loading && !a.data) return <Loading />;
  if (a.error) return <div className="stack"><Link to="/agents">← Agents</Link><ErrorBox error={a.error} retry={a.reload} /></div>;
  const g = a.data;
  const active = g.status === "active";
  return (
    <div className="stack">
      <Link to="/agents">← Agents</Link>
      <PageHeader
        title={g.name}
        subtitle={g.description || "No description"}
        actions={can && active && <><button onClick={() => setEdit(true)}>Edit</button><button className="danger" onClick={() => setRevoke(true)}>Revoke agent</button></>}
      />
      <div className="grid cols-2">
        <section className="card">
          <h2>Status</h2>
          <dl className="kv">
            <dt>Connection</dt><dd><ConnBadge c={g.connection} /></dd>
            <dt>What this means</dt><dd className="small">{explain(g)}</dd>
            <dt>Environment</dt><dd>{g.environment}</dd>
            <dt>Integration</dt><dd>{g.integration_type === "typescript_sdk" ? "TypeScript SDK" : "Event reporting only"}</dd>
            <dt>Enforcement mode</dt><dd>{g.integration_type === "event_reporting" ? "Observe only (cannot be blocked)" : g.enforcement_mode === "enforce" ? "Enforce" : "Monitor only (advisory)"}</dd>
            <dt>Policy</dt><dd>{g.integration_type === "event_reporting" ? <span className="muted">Not applicable to event-only agents</span> : g.policy_id ? <Link to={`/policies/${g.policy_id}`}>{g.policy_name}</Link> : <span className="muted">None: every action is denied</span>}</dd>
            <dt>Registered</dt><dd><Time value={g.created_at} /></dd>
            <dt>Last seen</dt><dd><Time value={g.last_seen_at} relativeToo /></dd>
            <dt>Last authorization</dt><dd><Time value={g.last_authorized_at} relativeToo /></dd>
            <dt>Last enforcement report</dt><dd><Time value={g.last_enforced_at} relativeToo /></dd>
            {g.revoked_at && (<><dt>Revoked</dt><dd><Time value={g.revoked_at} /></dd></>)}
          </dl>
        </section>
        <section className="card">
          <h2>Last 7 days</h2>
          <div className="row" style={{ gap: "1.5rem" }}>
            <div className="stat"><div className="n" style={{ color: "var(--ok)" }}>{g.last_7_days.allowed}</div><div className="l">Allowed</div></div>
            <div className="stat"><div className="n" style={{ color: "var(--bad)" }}>{g.last_7_days.denied}</div><div className="l">Denied</div></div>
            <div className="stat"><div className="n">{g.last_7_days.approvals}</div><div className="l">Needed approval</div></div>
          </div>
          <p className="muted small">Counts are decisions recorded by the policy engine, not confirmed executions.</p>
          <Link to={`/activity?agent=${g.id}`}>See full activity</Link>
        </section>
      </div>

      <section className="card">
        <div className="row between"><h2>Integration keys</h2>{can && active && <button className="primary" onClick={() => setCreating(true)}>Create key</button>}</div>
        {g.credentials.length === 0 ? <Empty title="No keys yet">Create a key so this agent can connect.</Empty> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Name</th><th>Key prefix</th><th>Allowed to</th><th>Created</th><th>Last used</th><th>Status</th></tr></thead>
            <tbody>{g.credentials.map((c: any) => (
              <tr key={c.id}><td>{c.name}</td><td><code>asg_{c.prefix}_…</code></td><td>{c.scopes.map((s: string) => s === "actions" ? "request decisions" : "report events").join(", ")}</td><td><Time value={c.created_at} /></td><td><Time value={c.last_used_at} /></td><td>{c.revoked_at ? <Badge tone="bad">Revoked</Badge> : <Badge tone="ok">Active</Badge>}</td></tr>
            ))}</tbody>
          </table></div>
        )}
        <p className="muted small">Manage, replace and revoke keys on the <Link to="/credentials">Credentials</Link> page.</p>
      </section>

      <ExecutorCard e={g.executor} />

      <section className="card">
        <h2>Recent activity</h2>
        {acts.loading && !acts.data ? <Loading /> : acts.data?.items.length ? (
          <div className="table-wrap"><table>
            <thead><tr><th>When</th><th>Action</th><th>Decision</th><th>Result</th></tr></thead>
            <tbody>{acts.data.items.map((x: any) => (
              <tr key={x.id} className="click" tabIndex={0} onClick={() => setOpenAct(x)} onKeyDown={(e) => e.key === "Enter" && setOpenAct(x)}>
                <td><Time value={x.created_at} /></td><td>{OP_LABEL[x.operation]} <code>{x.resource}</code> {x.is_demo && <DemoBadge />} {x.source === "offline_cache" && <Badge tone="warn">Offline</Badge>}</td><td><DecisionBadge d={x.decision} policyDecision={x.policy_decision} /></td><td><StateBadge s={x.state} /></td>
              </tr>))}</tbody>
          </table></div>
        ) : <Empty title="No activity yet">Decisions appear here once the agent requests authorization.</Empty>}
      </section>

      {g.integration_type === "typescript_sdk" && active && (
        <section className="card">
          <h2>Connect this agent</h2>
          <pre className="block">{`import { GuardianClient, ProtectedExecutor } from "kenuxa-heimdall/sdk";

const client = new GuardianClient({ baseUrl: "${location.origin}", apiKey: process.env.HEIMDALL_KEY! });
const executor = new ProtectedExecutor(client, {
  documents: async (action) => { /* the ONLY place that touches your files */ },
});
const result = await executor.run({ tool: "documents", operation: "read", resource: "docs/handbook.txt" });`}</pre>
          <p className="muted small">The adapter protects tools that run through it. Keep resource access inside the handlers; an application that can reach those resources directly can bypass it.</p>
        </section>
      )}

      {edit && <EditAgent g={g} policies={policies.data?.items ?? []} onClose={() => setEdit(false)} onSaved={() => { setEdit(false); a.reload(); toast("Agent updated"); }} />}
      {revoke && <Confirm title="Revoke this agent?" confirmLabel="Revoke agent" body={<>This permanently revokes <strong>{g.name}</strong> and all of its keys. Pending approvals are cancelled and further requests are refused. This cannot be undone; register a new agent to replace it.</>} onClose={() => setRevoke(false)} onConfirm={async () => { await api("POST", `/api/orgs/${org.id}/agents/${id}/revoke`); toast("Agent revoked"); a.reload(); nav(`/agents/${id}`); }} />}
      {creating && <KeyForm agentId={g.id} integration={g.integration_type} onClose={() => setCreating(false)} onCreated={(s) => { setCreating(false); setSecret(s); a.reload(); }} />}
      {secret && <SecretModal secret={secret} onClose={() => setSecret(null)} />}
      {openAct && <ActionDrawer id={openAct.id} onClose={() => setOpenAct(null)} />}
    </div>
  );
}

function explain(g: any) {
  switch (g.connection.state) {
    case "not_connected": return "Registered, but it has never authenticated. It will show as connected only after it successfully calls the service.";
    case "connected": return "It has authenticated successfully. Enforcement is confirmed only once the adapter claims an action or reports a refusal.";
    case "monitoring": return "Connected, but in monitor mode: decisions are recorded and advisory, nothing is enforced.";
    case "reporting_only": return "Sends events only. Nothing it reports can be blocked.";
    case "enforcing": return "The adapter has confirmed execution claims or refusals, so decisions are enforced for tools run through it.";
    default: return "This agent and its keys are revoked. Requests are refused.";
  }
}

function EditAgent({ g, policies, onClose, onSaved }: { g: any; policies: any[]; onClose: () => void; onSaved: () => void }) {
  const { org } = useApp();
  const [f, setF] = useState({ name: g.name, description: g.description, policy_id: g.policy_id ?? "", enforcement_mode: g.enforcement_mode });
  const [err, setErr] = useState<Error | null>(null);
  return (
    <Modal title="Edit agent" onClose={onClose}>
      <form className="form" onSubmit={async (e) => { e.preventDefault(); try { await api("PATCH", `/api/orgs/${org.id}/agents/${g.id}`, { ...f, policy_id: f.policy_id || null }); onSaved(); } catch (x) { setErr(x as Error); } }}>
        <Field label="Name" error={fieldErrors(err).name}><input required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        <Field label="Description"><textarea rows={2} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        {g.integration_type === "typescript_sdk" && (<>
          <Field label="Policy"><select value={f.policy_id} onChange={(e) => setF({ ...f, policy_id: e.target.value })}><option value="">None (deny everything)</option>{policies.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></Field>
          <Field label="Enforcement mode" hint="Switching to Monitor stops enforcement. Do this only to trial a policy."><select value={f.enforcement_mode} onChange={(e) => setF({ ...f, enforcement_mode: e.target.value })}><option value="enforce">Enforce</option><option value="monitor">Monitor only</option></select></Field>
        </>)}
        {err && !fieldErrors(err).name && <ErrorBox error={err} />}
        <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" onClick={onClose}>Cancel</button><button className="primary">Save changes</button></div>
      </form>
    </Modal>
  );
}

export interface ConnectInfo { id: string; name: string; integration_type: string; secret: string; hasPolicy: boolean }

function CopyBlock({ text, label }: { text: string; label: string }) {
  const toast = useToast();
  return (
    <div>
      <div className="row between" style={{ marginBottom: ".25rem" }}><span className="small muted">{label}</span><button onClick={() => navigator.clipboard?.writeText(text).then(() => toast("Copied"), () => toast("Copy failed: select and copy manually"))}>Copy</button></div>
      <pre className="block" style={{ userSelect: "all" }}>{text}</pre>
    </div>
  );
}

/** Shown right after registering: the key, the exact command, and a live indicator that flips when the agent really connects. */
export function ConnectModal({ agent, onClose }: { agent: ConnectInfo; onClose: () => void }) {
  const { org } = useApp();
  const live = useLoad<any>(`/api/orgs/${org.id}/agents/${agent.id}`);
  useEffect(() => { const t = setInterval(live.reload, 3000); return () => clearInterval(t); }, [live.reload]);
  const state = live.data?.connection?.state ?? "not_connected";
  const connected = state !== "not_connected";
  const sdk = agent.integration_type === "typescript_sdk";
  const cmd = sdk
    ? `npm run connect -- --url ${location.origin} --key ${agent.secret}`
    : `curl -X POST ${location.origin}/v1/events -H "Authorization: Bearer ${agent.secret}" -H "Content-Type: application/json" -d '{"event_type":"tool_call","tool":"crm","operation":"read","resource":"contacts/1"}'`;
  return (
    <Modal title={`Connect ${agent.name}`} onClose={onClose}>
      <div className="stack">
        <div className={`alert ${connected ? "ok" : "info"}`} role="status" aria-live="polite">
          {connected ? <><strong>Connected.</strong> The agent authenticated successfully{live.data?.connection?.connected_recently ? " and is online" : ""}.</> : <><span className="spinner" aria-hidden /> <strong>Waiting for the first connection…</strong> Registered agents show as connected only after they authenticate with the key below.</>}
        </div>
        <ol style={{ margin: 0, paddingLeft: "1.2rem", display: "grid", gap: ".9rem" }}>
          <li>
            <strong>Run this on the computer that should be linked</strong>{sdk ? " (in the project folder)" : ""}.
            <div style={{ marginTop: ".4rem" }}><CopyBlock text={cmd} label={sdk ? "Starts the laptop connector with your key" : "Sends one test event"} /></div>
          </li>
          <li>The key is shown <strong>only now</strong>; we keep just a hash. If you lose it, replace it on the Credentials page.</li>
          {sdk && !agent.hasPolicy && <li className="err">No policy is assigned, so every action will be denied. Assign one on the agent page.</li>}
          {sdk && <li>Type <code>read docs/handbook.txt</code> at the <code>guardian&gt;</code> prompt. It appears in Activity, and the agent becomes <em>Enforcing</em> once the adapter confirms an execution.</li>}
        </ol>
        <div className="row" style={{ justifyContent: "flex-end" }}><Link to={`/agents/${agent.id}`} onClick={onClose} className="btn">Open agent page</Link><button className="primary" onClick={onClose}>Done</button></div>
      </div>
    </Modal>
  );
}

export function KeyForm({ agentId, integration, agents, onClose, onCreated }: { agentId?: string; integration?: string; agents?: any[]; onClose: () => void; onCreated: (secret: string) => void }) {
  const { org } = useApp();
  const [agent, setAgent] = useState(agentId ?? agents?.[0]?.id ?? "");
  const [name, setName] = useState("");
  const [err, setErr] = useState<Error | null>(null);
  const kind = agentId ? integration : agents?.find((a) => a.id === agent)?.integration_type;
  return (
    <Modal title="Create an integration key" onClose={onClose}>
      <form className="form" onSubmit={async (e) => { e.preventDefault(); try { const r = await api("POST", `/api/orgs/${org.id}/credentials`, { agent_id: agent, name }); onCreated(r.secret); } catch (x) { setErr(x as Error); } }}>
        {!agentId && <Field label="Agent"><select required value={agent} onChange={(e) => setAgent(e.target.value)}>{agents?.map((a) => <option key={a.id} value={a.id}>{a.name} ({a.environment})</option>)}</select></Field>}
        <Field label="Key name" hint="For example: production server" error={fieldErrors(err).name}><input required maxLength={120} value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <div className="alert info small">{kind === "event_reporting" ? "This key can only report events for this one agent." : "This key can request decisions and report events for this one agent only. It cannot approve anything or reach the dashboard."}</div>
        {err && !fieldErrors(err).name && <ErrorBox error={err} />}
        <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" onClick={onClose}>Cancel</button><button className="primary">Create key</button></div>
      </form>
    </Modal>
  );
}

export function ActionDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { org } = useApp();
  const { data, error, loading } = useLoad<any>(`/api/orgs/${org.id}/actions/${id}`);
  return (
    <Modal title="Action details" onClose={onClose} drawer>
      {loading && <Loading />}
      <ErrorBox error={error} />
      {data && (
        <div className="stack">
          <div className="row"><DecisionBadge d={data.decision} policyDecision={data.policy_decision} /><StateBadge s={data.state} />{data.is_demo && <DemoBadge />}</div>
          <p style={{ margin: 0 }}>{data.explanation}</p>
          <dl className="kv">
            <dt>Agent</dt><dd><Link to={`/agents/${data.agent_id}`} onClick={onClose}>{data.agent_name}</Link></dd>
            <dt>Operation</dt><dd>{OP_LABEL[data.operation]} via <code>{data.tool}</code></dd>
            <dt>Resource</dt><dd><code>{data.resource}</code></dd>
            {data.destination && (<><dt>Destination</dt><dd><code>{data.destination}</code></dd></>)}
            <dt>Data classification</dt><dd><ClassBadge level={data.classification_level} source={data.classification_source} declared={data.data_classification} /></dd>
            <dt>Reason code</dt><dd><code>{data.reason_code}</code>{data.matched_rule_id && <> · rule <code>{data.matched_rule_id}</code></>}</dd>
            <dt>Policy version</dt><dd>{data.policy_version ?? "—"}{data.enforcement_mode === "monitor" && " (monitor mode)"}</dd>
            <dt>Requested</dt><dd><Time value={data.created_at} /></dd>
            {data.source === "offline_cache" && (<><dt>Decided</dt><dd><Badge tone="warn">Offline</Badge> <span className="muted small">The executor decided this from its signed policy cache while the service was unreachable; the server re-checked it after reconnect.</span></dd></>)}
            <dt>Request ID</dt><dd><code>{data.request_id}</code></dd>
            <dt>Action digest</dt><dd><code className="small">{data.action_digest.slice(0, 24)}…</code></dd>
            <dt>Adapter</dt><dd>{data.adapter_name ? `${data.adapter_name} ${data.adapter_version ?? ""}` : "—"}</dd>
          </dl>
          <div><h3>Redacted arguments</h3><pre className="block">{JSON.stringify(data.args_summary, null, 2)}</pre><p className="muted small">Sensitive values and document contents are removed before storage.</p></div>
          {data.approval_id && (
            <div><h3>Approval</h3><dl className="kv">
              <dt>Status</dt><dd>{data.approval_status}{data.approval_consumed_at ? " (used)" : ""}</dd>
              <dt>Needs role</dt><dd>{data.required_role}</dd>
              <dt>Expires</dt><dd><Time value={data.approval_expires_at} /></dd>
              {data.decided_at && (<><dt>Decided by</dt><dd>{data.decided_by_name} · <Time value={data.decided_at} /></dd></>)}
              {data.decision_note && (<><dt>Note</dt><dd>{data.decision_note}</dd></>)}
            </dl></div>
          )}
          <div><h3>Execution</h3>{data.outcome_status ? (<dl className="kv">
            <dt>Reported status</dt><dd>{data.outcome_status}{data.enforcement_confirmed ? " (confirmed by adapter)" : ""}</dd>
            {data.error_code && (<><dt>Error code</dt><dd><code>{data.error_code}</code></dd></>)}
            {data.claimed_at && (<><dt>Permit used</dt><dd><Time value={data.claimed_at} /></dd></>)}
            {data.reported_at && (<><dt>Reported</dt><dd><Time value={data.reported_at} /></dd></>)}
          </dl>) : <p className="muted">No execution report. “Allowed” or “Denied” alone does not prove what the executor did.</p>}</div>
        </div>
      )}
    </Modal>
  );
}

/** Classification is never taken on the agent's word when the policy defines it. Unknown is handled conservatively. */
export function ClassBadge({ level, source, declared }: { level: string | null; source: string | null; declared?: string | null }) {
  if (!level) return <span className="muted">not evaluated</span>;
  if (level === "unclassified") {
    return <span><Badge tone="warn">Unclassified</Badge> <span className="muted small">Treated conservatively: deny and approval rules that name a class still apply; allow rules that require a class do not match.{declared ? ` The agent claimed "${declared}"; that claim is not trusted.` : ""}</span></span>;
  }
  return <span><Badge tone={level === "restricted" || level === "confidential" ? "bad" : level === "internal" ? "warn" : "ok"}>{level}</Badge> <span className="muted small">{source === "policy" ? "set by your policy (trusted)" : source === "policy_raised_by_agent" ? "raised by the agent above your policy's level (only tightens)" : "declared by the agent (untrusted: add a classifications map to your policy)"}{source === "policy" && declared && declared !== level ? `; the agent claimed "${declared}", which was ignored` : ""}</span></span>;
}

/** What the executor says about itself. Evidence, not proof: it is the executor's own report. */
function ExecutorCard({ e }: { e: any }) {
  if (!e) {
    return <section className="card"><h2>Executor</h2><p className="muted small" style={{ margin: 0 }}>No executor has reported yet. Start the MCP server or the laptop connector for this agent; it reports its protected folder and policy-cache state here.</p></section>;
  }
  return (
    <section className="card">
      <h2>Executor <span className="muted small" style={{ fontWeight: 400 }}>(self-reported, last <Time value={e.reported_at} relativeToo />)</span></h2>
      <dl className="kv">
        <dt>Mode</dt><dd>{e.mode === "online" ? "Online" : e.mode === "offline_cache" ? <Badge tone="warn">Service unreachable: deciding from cached signed policy</Badge> : <Badge tone="bad">Degraded</Badge>}</dd>
        <dt>Protected folders</dt><dd>{(e.roots ?? []).length ? e.roots.map((r: any) => <code key={r.label}>{r.label}{r.prefix ? ` (${r.prefix})` : ""}</code>) : "none reported"}</dd>
        <dt>External transfers</dt><dd>{e.egress_enabled ? "Enabled (approved destinations only)" : "Disabled on this executor"}</dd>
        <dt>Policy cache expires</dt><dd>{e.cache_expires_at ? <Time value={e.cache_expires_at} relativeToo /> : "no cache"}</dd>
        <dt>Queued offline records</dt><dd>{e.queued_events}</dd>
        <dt>Version</dt><dd>{e.executor_version ?? "?"}</dd>
      </dl>
    </section>
  );
}
