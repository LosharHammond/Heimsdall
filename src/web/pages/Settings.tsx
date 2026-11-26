import { useState } from "react";
import { AlertChannels } from "./AlertChannels";
import { api, useLoad } from "../api";
import { Badge, Confirm, ErrorBox, Field, Loading, PageHeader, ROLE_LABEL, Time, fieldErrors, useApp, useCan, useToast, type Role } from "../ui";

const ROLES: Role[] = ["owner", "admin", "approver", "auditor", "viewer"];

const ZONES: string[] = (() => {
  try {
    const z = (Intl as any).supportedValuesOf("timeZone") as string[];
    return z.includes("Africa/Accra") ? z : ["Africa/Accra", ...z];
  } catch {
    return ["Africa/Accra", "UTC", "Europe/London"];
  }
})();

export default function Settings() {
  const { org, refresh, user } = useApp();
  const owner = useCan("owner");
  const toast = useToast();
  const o = useLoad<any>(`/api/orgs/${org.id}`);
  const members = useLoad<any>(`/api/orgs/${org.id}/members`);
  const [f, setF] = useState<any>(null);
  const [err, setErr] = useState<Error | null>(null);
  const [add, setAdd] = useState({ email: "", role: "viewer" });
  const [addErr, setAddErr] = useState<Error | null>(null);
  const [remove, setRemove] = useState<any>(null);
  const cur = f ?? (o.data && { name: o.data.name, timezone: o.data.timezone, retention_days: o.data.retention_days, audit_retention_days: o.data.audit_retention_days });
  const fe = fieldErrors(err);
  if (o.loading && !o.data) return <Loading />;
  return (
    <div className="stack">
      <PageHeader title="Settings" subtitle={owner ? "Only owners can change organization settings." : "You can view these settings. Only owners can change them."} />
      <ErrorBox error={o.error} retry={o.reload} />
      {cur && (
        <section className="card">
          <h2>Organization</h2>
          <form className="form" onSubmit={async (e) => {
            e.preventDefault(); setErr(null);
            try { await api("PATCH", `/api/orgs/${org.id}`, { name: cur.name, timezone: cur.timezone, retention_days: Number(cur.retention_days), audit_retention_days: Number(cur.audit_retention_days) }); toast("Settings saved"); setF(null); o.reload(); refresh(); } catch (x) { setErr(x as Error); }
          }}>
            <Field label="Name" error={fe.name}><input disabled={!owner} required value={cur.name} onChange={(e) => setF({ ...cur, name: e.target.value })} /></Field>
            <Field label="Display timezone" hint="All times are stored in UTC and shown in this timezone. Default: Africa/Accra.">
              <select disabled={!owner} value={cur.timezone} onChange={(e) => setF({ ...cur, timezone: e.target.value })}>{ZONES.map((z) => <option key={z}>{z}</option>)}</select>
            </Field>
            <div className="grid cols-2">
              <Field label="Keep activity for (days)" hint="Decisions, approvals, outcomes, observations and closed alerts older than this are deleted. 7–730." error={fe.retention_days}><input disabled={!owner} type="number" min={7} max={730} value={cur.retention_days} onChange={(e) => setF({ ...cur, retention_days: e.target.value })} /></Field>
              <Field label="Keep audit log for (days)" hint="30–3650." error={fe.audit_retention_days}><input disabled={!owner} type="number" min={30} max={3650} value={cur.audit_retention_days} onChange={(e) => setF({ ...cur, audit_retention_days: e.target.value })} /></Field>
            </div>
            {err && !Object.keys(fe).length && <ErrorBox error={err} />}
            {owner && <div><button className="primary">Save settings</button></div>}
          </form>
        </section>
      )}
      <section className="card">
        <h2>Members</h2>
        <p className="muted small">Owners manage settings, members and sign-in security. Administrators manage agents, policies, keys and approvals. Approvers decide approvals and handle alerts. Auditors can read the audit log. Viewers can only look. People must have an account first (or sign in once with your organization's single sign-on); email invitations are not available yet.</p>
        <ErrorBox error={members.error} retry={members.reload} />
        {members.data && (
          <div className="table-wrap"><table>
            <caption className="skip">Organization members</caption>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Joined</th>{owner && <th><span className="skip">Actions</span></th>}</tr></thead>
            <tbody>{members.data.items.map((m: any) => (
              <tr key={m.user_id}>
                <td>{m.name}{m.user_id === user.id && <> <Badge>you</Badge></>}</td><td>{m.email}</td>
                <td>{owner ? (
                  <select aria-label={`Role for ${m.name}`} value={m.role} onChange={async (e) => { try { await api("PATCH", `/api/orgs/${org.id}/members/${m.user_id}`, { role: e.target.value }); toast("Role updated"); members.reload(); refresh(); } catch (x) { toast((x as Error).message); members.reload(); } }}>
                    {ROLES.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
                  </select>) : m.role}</td>
                <td><Time value={m.created_at} /></td>
                {owner && <td><button className="danger" onClick={() => setRemove(m)}>Remove</button></td>}
              </tr>))}</tbody>
          </table></div>
        )}
        {owner && (
          <form className="form" style={{ marginTop: "1rem" }} onSubmit={async (e) => {
            e.preventDefault(); setAddErr(null);
            try { await api("POST", `/api/orgs/${org.id}/members`, add); toast("Member added"); setAdd({ email: "", role: "viewer" }); members.reload(); } catch (x) { setAddErr(x as Error); }
          }}>
            <h3>Add a member</h3>
            <div className="row" style={{ alignItems: "end" }}>
              <Field label="Their account email"><input required type="email" value={add.email} onChange={(e) => setAdd({ ...add, email: e.target.value })} /></Field>
              <Field label="Role"><select value={add.role} onChange={(e) => setAdd({ ...add, role: e.target.value })}>{[...ROLES].reverse().map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}</select></Field>
              <button className="primary">Add</button>
            </div>
            <ErrorBox error={addErr} />
          </form>
        )}
      </section>
      <AlertChannels />
      <section className="card">
        <h2>Data handling</h2>
        <ul>
          <li>By default only action metadata and decisions are stored: tool, operation, resource name, destination, a redacted argument summary and a digest. Documents, prompts and model responses are not collected.</li>
          <li>Values that look like passwords, keys, tokens, card numbers or email addresses are removed before storage and logging.</li>
          <li>Expired data is deleted automatically using the retention periods above.</li>
        </ul>
      </section>
      {remove && <Confirm title="Remove member?" confirmLabel="Remove" body={<><strong>{remove.name}</strong> will lose access to this organization immediately.</>} onClose={() => setRemove(null)} onConfirm={async () => { await api("DELETE", `/api/orgs/${org.id}/members/${remove.user_id}`); toast("Member removed"); members.reload(); }} />}
    </div>
  );
}
