import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { api, useLoad } from "../api";
import { Badge, Empty, ErrorBox, Field, Loading, PageHeader, Time, fieldErrors, useApp, useCan, useToast } from "../ui";

const RULE_ORDER = ["id", "description", "effect", "match", "approval"];
const MATCH_ORDER = ["tools", "operations", "resources", "destination_domains", "data_classifications"];
const pick = (o: any, keys: string[]) => Object.fromEntries(keys.filter((k) => o?.[k] !== undefined).map((k) => [k, o[k]]));
/** jsonb does not preserve key order; show documents in the conventional order. */
export function tidy(doc: any) {
  if (!doc || typeof doc !== "object") return doc;
  return { ...pick(doc, ["schema_version", "description", "budget"]), rules: (doc.rules ?? []).map((r: any) => ({ ...pick(r, RULE_ORDER), match: pick(r.match, MATCH_ORDER) })) };
}

const BLANK = { schema_version: 1, description: "", rules: [] };

export function PolicyPage() {
  const { id } = useParams();
  const { org } = useApp();
  const can = useCan("admin");
  const nav = useNavigate();
  const list = useLoad<any>(`/api/orgs/${org.id}/policies`);
  const examples = useLoad<any>("/api/policy-examples");
  return (
    <div className="stack">
      <PageHeader title="Policies" subtitle="Rules that decide what each agent may do. Anything not explicitly allowed is denied." actions={can && <button className="primary" onClick={() => nav("/policies/new")}>New policy</button>} />
      <div className="grid" style={{ gridTemplateColumns: "minmax(220px, 300px) 1fr", alignItems: "start" }}>
        <section className="card" aria-label="Policy list">
          <ErrorBox error={list.error} retry={list.reload} />
          {list.loading && !list.data ? <Loading /> : list.data?.items.length === 0 ? (
            <Empty title="No policies yet">{can ? "Create one, or start from an example." : "An administrator can create policies."}</Empty>
          ) : (
            <ul className="list-plain">
              {list.data?.items.map((p: any) => (
                <li key={p.id}><Link to={`/policies/${p.id}`} aria-current={p.id === id ? "page" : undefined}><strong>{p.name}</strong></Link><div className="muted small">v{p.current_version} · {p.agent_count} active agent{p.agent_count === 1 ? "" : "s"}</div></li>
              ))}
            </ul>
          )}
        </section>
        <div>
          {!id && <Empty title="Select a policy">Choose a policy on the left{can ? ", or create a new one." : "."}</Empty>}
          {id && <Editor key={id} id={id} examples={examples.data?.items ?? []} onSaved={list.reload} />}
        </div>
      </div>
    </div>
  );
}

function Editor({ id, examples, onSaved }: { id: string; examples: any[]; onSaved: () => void }) {
  const { org } = useApp();
  const can = useCan("admin");
  const nav = useNavigate();
  const toast = useToast();
  const isNew = id === "new";
  const p = useLoad<any>(isNew ? null : `/api/orgs/${org.id}/policies/${id}`);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [text, setText] = useState(JSON.stringify(BLANK, null, 2));
  const [err, setErr] = useState<Error | null>(null);
  const [parseErr, setParseErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [ver, setVer] = useState<number | null>(null);
  useEffect(() => {
    if (p.data) {
      setName(p.data.name); setDescription(p.data.description);
      const cur = p.data.versions.find((v: any) => v.version === p.data.current_version) ?? p.data.versions[0];
      setText(JSON.stringify(tidy(cur.document), null, 2)); setVer(p.data.current_version);
    }
  }, [p.data]);
  const issues = (err as any)?.details as Array<{ path: string; message: string }> | undefined;
  const fe = fieldErrors(err);
  const parse = () => { try { setParseErr(""); return JSON.parse(text); } catch (e) { setParseErr(`This isn't valid JSON: ${(e as Error).message}`); return undefined; } };

  if (!isNew && p.loading && !p.data) return <Loading />;
  if (p.error) return <ErrorBox error={p.error} retry={p.reload} />;
  return (
    <div className="stack">
      <section className="card">
        <form className="form" onSubmit={async (e) => {
          e.preventDefault();
          const document = parse();
          if (document === undefined) return;
          setBusy(true); setErr(null);
          try {
            if (isNew) { const r = await api("POST", `/api/orgs/${org.id}/policies`, { name, description, document }); toast("Policy created"); onSaved(); nav(`/policies/${r.id}`); }
            else { const r = await api("PUT", `/api/orgs/${org.id}/policies/${id}`, { name, description, document }); toast(r.changed_version ? `Saved as version ${r.version}. Pending approvals tied to the old version will need to be requested again.` : "Saved (no rule changes)"); onSaved(); p.reload(); }
          } catch (x) { setErr(x as Error); }
          setBusy(false);
        }}>
          <div className="row between"><h2 style={{ margin: 0 }}>{isNew ? "New policy" : name}</h2>{!isNew && <Badge>Current version {ver}</Badge>}</div>
          {isNew && can && examples.length > 0 && (
            <Field label="Start from an example">
              <select defaultValue="" onChange={(e) => { const ex = examples.find((x) => x.key === e.target.value); if (ex) { setText(JSON.stringify(ex.document, null, 2)); if (!name) setName(ex.title); setDescription(ex.summary); } }}>
                <option value="">Blank policy</option>{examples.map((ex) => <option key={ex.key} value={ex.key}>{ex.title}</option>)}
              </select>
            </Field>
          )}
          <Field label="Name" error={fe.name}><input required value={name} readOnly={!can} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Description"><input value={description} readOnly={!can} onChange={(e) => setDescription(e.target.value)} /></Field>
          <Field label="Policy document (JSON)" hint="Precedence: explicit deny, then approval rules, then explicit allow, then default deny." error={parseErr}>
            <textarea className="code" spellCheck={false} value={text} readOnly={!can} aria-invalid={!!parseErr || !!issues} onChange={(e) => setText(e.target.value)} />
          </Field>
          {err && (
            <div className="alert bad" role="alert">
              <strong>{err.message}</strong>
              {issues && <ul>{issues.map((i, k) => <li key={k}><code>{i.path || "document"}</code>: {i.message}</li>)}</ul>}
            </div>
          )}
          {can ? <div className="row"><button className="primary" disabled={busy}>{busy ? "Saving…" : isNew ? "Create policy" : "Save as new version"}</button></div> : <div className="alert info small">You have view-only access. Owners and administrators can edit policies.</div>}
        </form>
      </section>
      <Glance text={text} />
      {!isNew && p.data && (
        <>
          <Simulator text={text} />
          <section className="card">
            <h2>Used by</h2>
            {p.data.agents.length === 0 ? <p className="muted">No agents use this policy.</p> : <ul className="list-plain">{p.data.agents.map((a: any) => <li key={a.id}><Link to={`/agents/${a.id}`}>{a.name}</Link> <span className="muted small">{a.environment}{a.status === "revoked" ? " · revoked" : ""}</span></li>)}</ul>}
          </section>
          <section className="card">
            <h2>Version history</h2>
            <ul className="list-plain">{p.data.versions.map((v: any) => (
              <li key={v.version} className="row between"><span>Version {v.version} {v.version === p.data.current_version && <Badge tone="ok">current</Badge>}<span className="muted small"> · {v.created_by_name ?? "unknown"} · <Time value={v.created_at} /></span></span><button className="link" onClick={() => { setText(JSON.stringify(v.document, null, 2)); toast(`Loaded version ${v.version} into the editor. Save to make it current.`); }}>Load into editor</button></li>
            ))}</ul>
          </section>
        </>
      )}
    </div>
  );
}

const OPS: Record<string, string> = { read: "read", create: "create", update: "update", delete: "delete", external_transfer: "send data outside", command_execution: "run commands" };
function summarize(r: any) {
  const m = r.match ?? {};
  const parts: string[] = [];
  parts.push(m.operations ? m.operations.map((o: string) => OPS[o] ?? o).join(", ") : "any operation");
  parts.push(m.tools && !(m.tools.length === 1 && m.tools[0] === "*") ? "via " + m.tools.join(", ") : "via any tool");
  if (m.resources) parts.push("on " + m.resources.join(", "));
  if (m.destination_domains) parts.push("to " + m.destination_domains.join(", "));
  if (m.data_classifications) parts.push("for " + m.data_classifications.join("/") + " data");
  return parts.join(" · ");
}

/** Plain-language view of the document being edited, so administrators don't have to read JSON. */
function Glance({ text }: { text: string }) {
  let doc: any = null;
  try {
    doc = JSON.parse(text);
  } catch {
    return null;
  }
  if (!Array.isArray(doc?.rules)) return null;
  const order: Record<string, number> = { deny: 0, require_approval: 1, allow: 2 };
  const rules = [...doc.rules].sort((a, b) => (order[a.effect] ?? 9) - (order[b.effect] ?? 9));
  const budget = doc.budget ? ` Budget: at most ${doc.budget.max_allowed_actions} allowed actions per ${Math.round(doc.budget.window_seconds / 60)} min.` : "";
  return (
    <section className="card">
      <h2>Rules at a glance</h2>
      <p className="muted small">Evaluated in this order: explicit denies, then approval rules, then allows. Anything not listed is denied.{budget}</p>
      <ol className="list-plain">
        {rules.map((r: any) => (
          <li key={r.id} className="row" style={{ flexWrap: "nowrap", alignItems: "flex-start" }}>
            <span style={{ minWidth: 128 }}><Badge tone={r.effect === "allow" ? "ok" : r.effect === "deny" ? "bad" : "warn"}>{r.effect === "allow" ? "Allow" : r.effect === "deny" ? "Deny" : "Needs approval"}</Badge></span>
            <span>
              <strong>{summarize(r)}</strong>
              {r.effect === "require_approval" && <span className="muted small"> · approver: {r.approval?.required_role ?? "admin"}</span>}
              <div className="muted small"><code>{r.id}</code>{r.description ? ` · ${r.description}` : ""}</div>
            </span>
          </li>
        ))}
        <li className="row" style={{ flexWrap: "nowrap" }}><span style={{ minWidth: 128 }}><Badge tone="bad">Deny</Badge></span><span><strong>Everything else</strong><div className="muted small">The default for any action no rule allows.</div></span></li>
      </ol>
    </section>
  );
}

function Simulator({ text }: { text: string }) {
  const { org } = useApp();
  const [a, setA] = useState({ tool: "documents", operation: "read", resource: "docs/handbook.txt", destination: "", data_classification: "", has_valid_approval: false });
  const [res, setRes] = useState<any>(null);
  const [err, setErr] = useState<Error | null>(null);
  return (
    <section className="card">
      <h2>Try it (dry run)</h2>
      <p className="muted small">Evaluates the document above against a sample action. Nothing is recorded and no budget is used.</p>
      <form className="form" onSubmit={async (e) => {
        e.preventDefault(); setErr(null); setRes(null);
        try {
          const document = JSON.parse(text);
          setRes(await api("POST", `/api/orgs/${org.id}/policies/simulate`, { document, has_valid_approval: a.has_valid_approval, action: { tool: a.tool, operation: a.operation, resource: a.resource, ...(a.destination ? { destination: a.destination } : {}), ...(a.data_classification ? { data_classification: a.data_classification } : {}) } }));
        } catch (x) { setErr(x as Error); }
      }}>
        <div className="grid cols-2">
          <Field label="Tool"><input required value={a.tool} onChange={(e) => setA({ ...a, tool: e.target.value })} /></Field>
          <Field label="Operation"><select value={a.operation} onChange={(e) => setA({ ...a, operation: e.target.value })}>{["read", "create", "update", "delete", "external_transfer", "command_execution"].map((o) => <option key={o}>{o}</option>)}</select></Field>
          <Field label="Resource"><input required value={a.resource} onChange={(e) => setA({ ...a, resource: e.target.value })} /></Field>
          <Field label="Destination (for external transfers)"><input value={a.destination} placeholder="https://partner.example.com/inbox" onChange={(e) => setA({ ...a, destination: e.target.value })} /></Field>
          <Field label="Data classification"><select value={a.data_classification} onChange={(e) => setA({ ...a, data_classification: e.target.value })}><option value="">Not declared</option><option>public</option><option>internal</option><option>confidential</option><option>restricted</option></select></Field>
          <label className="row" style={{ alignSelf: "end" }}><input type="checkbox" style={{ width: "auto" }} checked={a.has_valid_approval} onChange={(e) => setA({ ...a, has_valid_approval: e.target.checked })} /> Pretend a valid approval exists</label>
        </div>
        <div><button>Evaluate</button></div>
      </form>
      <ErrorBox error={err} />
      {res && (
        <div className={`alert ${res.decision === "allow" ? "ok" : res.decision === "deny" ? "bad" : "warn"}`} style={{ marginTop: ".75rem" }} role="status">
          <strong>{res.decision === "allow" ? "Allow" : res.decision === "deny" ? "Deny" : "Require approval"}</strong> · <code>{res.reason_code}</code>
          <div>{res.explanation}</div>
        </div>
      )}
    </section>
  );
}
