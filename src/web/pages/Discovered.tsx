/** Protection Center → everything Heimdall found on added computers, and whether it is protected. */
import { Link } from "react-router";
import { api, useLoad } from "../api";
import { Badge, Empty, ErrorBox, Loading, Time, useApp, useCan, useToast } from "../ui";

const KIND: Record<string, string> = { mcp_client: "AI app with tools", coding_agent: "Coding agent", ai_app: "AI app", local_model: "Local AI models", agent_script: "AI agent (script)", automation: "Automation" };
const STATE: Record<string, [string, "ok" | "warn" | "bad" | undefined, string]> = {
  protected: ["Protected", "ok", "Heimdall checks its actions before they happen."],
  restart_needed: ["Restart it once", "warn", "Protection is set up; it starts the next time this app is opened."],
  unprotected: ["Setting up…", "warn", "Heimdall is switching protection on."],
  off: ["Automatic protection off", undefined, "Turned off for this organization."],
  not_possible: ["Listed only", "bad", "Heimdall can see it but cannot stand in front of its actions."],
};

export function Discovered() {
  const { org } = useApp();
  const admin = useCan("admin");
  const toast = useToast();
  const d = useLoad<any>(`/api/orgs/${org.id}/discovered`);
  return (
    <section className="card" aria-labelledby="h-found" style={{ marginBottom: "1rem" }}>
      <div className="row between">
        <h2 id="h-found">Found on your computers</h2>
        {admin && d.data && (
          <label className="row small" style={{ gap: ".45rem" }}>
            <input type="checkbox" checked={d.data.auto_protect} onChange={async (e) => {
              try { await api("PUT", `/api/orgs/${org.id}/auto-protect`, { auto_protect: e.target.checked }); toast(e.target.checked ? "Found AI tools will be protected automatically." : "Automatic protection off: computers restore the tools' original settings within 5 minutes."); d.reload(); } catch (x) { toast((x as Error).message); }
            }} />
            Protect found AI tools automatically
          </label>
        )}
      </div>
      <p className="muted small">Every added computer looks for AI apps, coding agents, agent scripts and automations every few minutes. Tools Heimdall can sit in front of are protected automatically with the “Recommended for AI tools” policy: everyday work runs at once, deleting and sending data out wait for approval. Nothing to register by hand.</p>
      {d.loading && !d.data ? <Loading /> : d.error ? <ErrorBox error={d.error} retry={d.reload} /> : !d.data?.items.length ? (
        <Empty icon="agents" title="Nothing found yet">Add a computer with “Protect this computer”. It reports what it finds within a minute.</Empty>
      ) : (
        <div className="table-wrap"><table>
          <caption className="skip">AI tools found on computers</caption>
          <thead><tr><th>Tool</th><th>Computer</th><th>Protection</th><th>Last seen</th></tr></thead>
          <tbody>{d.data.items.map((t: any) => {
            const [label, tone, hint] = STATE[t.protection] ?? [t.protection, undefined, ""];
            return (
              <tr key={t.id}>
                <td><strong>{t.product}</strong><div className="muted small">{KIND[t.kind] ?? t.kind}{t.detail ? ` · ${t.detail}` : ""}{t.running ? " · running" : ""}</div></td>
                <td>{t.device_name}</td>
                <td><Badge tone={tone} title={hint}>{label}</Badge>{t.agent_id && <div className="small"><Link to={`/agents/${t.agent_id}`}>Activity and policy</Link></div>}{t.protection === "not_possible" && t.kind === "agent_script" && <div className="muted small">Add the Heimdall SDK to protect it</div>}</td>
                <td className="small"><Time value={t.last_seen_at} relativeToo /></td>
              </tr>
            );
          })}</tbody>
        </table></div>
      )}
    </section>
  );
}
