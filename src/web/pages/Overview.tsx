import { useEffect, useState } from "react";
import { Link } from "react-router";
import { ProtectComputer } from "../device-setup";
import { useLoad } from "../api";
import { DecisionChart, ReasonBars } from "../charts";
import { Icon } from "../icons";
import { ConnBadge, DemoBadge, Empty, ErrorBox, Loading, SeverityBadge, Time, useApp } from "../ui";

export default function Overview() {
  const { org } = useApp();
  const [hours, setHours] = useState(168);
  const { data, error, loading, reload } = useLoad<any>(`/api/orgs/${org.id}/overview?hours=${hours}`);
  const label = hours === 24 ? "last 24 hours" : hours === 168 ? "last 7 days" : "last 30 days";
  const d = data;
  return (
    <div className="stack">
      <section className="hero">
        <div className="row between" style={{ alignItems: "flex-start" }}>
          <div>
            <h1>{org.name}</h1>
            <p>Every figure here is counted from recorded events. Nothing is estimated, scored or invented.</p>
          </div>
          <label className="small">
            Period
            <select value={hours} onChange={(e) => setHours(Number(e.target.value))} aria-label="Period">
              <option value={24}>Last 24 hours</option><option value={168}>Last 7 days</option><option value={720}>Last 30 days</option>
            </select>
          </label>
        </div>
        {d && (
          <div className="row" style={{ marginTop: "1rem", gap: ".5rem" }}>
            <span className="pill"><span className="dot" />{d.agents.by_state.enforcing} enforcing through adapter</span>
            <span className="pill"><span className="dot" style={{ color: "#93c5fd" }} />{d.agents.by_state.connected + d.agents.by_state.monitoring + d.agents.by_state.reporting_only} connected, not enforcing</span>
            <span className="pill"><span className="dot" style={{ color: "#94a3b8" }} />{d.agents.by_state.not_connected} not connected</span>
            {d.pending_approvals > 0 && <Link to="/approvals" className="pill warn" style={{ textDecoration: "none" }}><span className="dot" />{d.pending_approvals} waiting for approval</Link>}
          </div>
        )}
      </section>
      <ProtectionStatus />
      <ErrorBox error={error} retry={reload} />
      {loading && !d && <Loading kind="dashboard" />}
      {d && (
        <>
          {d.agents.total === 0 && (
            <div className="alert info"><strong>Start here.</strong> <Link to="/agents">Register your first agent</Link>, assign it a <Link to="/policies">policy</Link>, then connect it with the SDK and an integration key.</div>
          )}
          <div className="grid cols-4" aria-label={`Decisions in the ${label}`}>
            <Stat icon="check" accent="var(--c-allow)" n={d.decisions.allowed} label="Allowed decisions" hint="Policy permitted the action. It does not mean it ran." />
            <Stat icon="ban" accent="var(--c-deny)" n={d.decisions.denied} label="Denied decisions" hint="Policy refused the action." />
            <Stat icon="clock" accent="var(--c-appr)" n={d.decisions.needs_approval} label="Sent for approval" hint="A human had to decide." />
            <Stat icon="shield" accent="var(--brand)" n={d.executions.blocked_confirmed} label="Blocks confirmed by executor" hint="The adapter confirmed it did not run the action." />
          </div>
          <div className="grid cols-4">
            <Stat icon="approvals" accent="var(--c-appr)" n={d.pending_approvals} label="Pending approvals" link={d.pending_approvals ? "/approvals" : undefined} hint="Waiting for a human decision now." />
            <Stat icon="alerts" accent="var(--c-deny)" n={d.open_alerts} label="Open alerts" link={d.open_alerts ? "/alerts" : undefined} hint="Raised from recorded events." />
            <Stat icon="warn" accent={d.executions.failed ? "var(--c-deny)" : "var(--line-strong)"} n={d.executions.failed} label="Execution failures" hint="Permitted, but failed while running." />
            <Stat icon="eye" accent="var(--info)" n={d.decisions.monitor_would_block} label="Monitor “would block”" hint="Advisory only: these were not stopped." />
          </div>

          <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))" }}>
            <section className="card" style={{ gridColumn: "span 2", minWidth: 0 }} aria-labelledby="h-chart">
              <h2 id="h-chart">Decisions over time <span className="muted small" style={{ fontWeight: 400 }}>· per {d.unit}, {org.timezone}</span></h2>
              <DecisionChart data={d.timeline} unit={d.unit} />
            </section>
          </div>

          <div className="grid cols-2">
            <section className="card" aria-labelledby="h-agents">
              <div className="row between"><h2 id="h-agents">Recently communicating agents</h2><Link to="/agents" className="small">All agents</Link></div>
              {d.recent_agents.length === 0 ? (
                <Empty icon="agents" title="No agent has connected yet">Registered agents appear here only after they authenticate successfully.</Empty>
              ) : (
                <ul className="list-plain">
                  {d.recent_agents.map((a: any) => (
                    <li key={a.id} className="row between">
                      <span><Link to={`/agents/${a.id}`}><strong>{a.name}</strong></Link> <span className="muted small">{a.environment}</span></span>
                      <span className="row" style={{ gap: ".6rem" }}><ConnBadge c={a.connection} /><span className="muted small nowrap"><Time value={a.last_seen_at} relativeToo /></span></span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
            <section className="card" aria-labelledby="h-deny">
              <h2 id="h-deny">Why actions were denied</h2>
              {d.top_denials.length === 0 ? <Empty icon="shield" title="No denials in this period">Denied actions will be broken down by reason here.</Empty> : <ReasonBars items={d.top_denials} />}
            </section>
          </div>

          <div className="grid cols-2">
            <section className="card" aria-labelledby="h-alerts">
              <div className="row between"><h2 id="h-alerts">Open alerts</h2><Link to="/alerts" className="small">All alerts</Link></div>
              {d.recent_alerts.length === 0 ? (
                <Empty icon="alerts" title="No open alerts">Alerts are raised from recorded denials, failures and suspicious attempts.</Empty>
              ) : (
                <ul className="list-plain">
                  {d.recent_alerts.map((a: any) => (
                    <li key={a.id}>
                      <div className="row between"><span className="row" style={{ gap: ".4rem" }}><SeverityBadge s={a.severity} />{a.is_demo && <DemoBadge />}</span><span className="muted small"><Time value={a.last_seen_at} relativeToo /></span></div>
                      <div style={{ marginTop: ".25rem" }}>{a.title}{a.occurrences > 1 && <span className="muted small"> · seen {a.occurrences}×</span>}</div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
            <section className="card" aria-labelledby="h-fail">
              <h2 id="h-fail">Recent execution failures</h2>
              {d.recent_failures.length === 0 ? (
                <Empty icon="check" title="No execution failures recorded">Failures are reported by integrated executors after a permitted action fails to run.</Empty>
              ) : (
                <ul className="list-plain">
                  {d.recent_failures.map((f: any) => (
                    <li key={f.id}>
                      <div className="row between"><strong>{f.agent_name}</strong><span className="muted small"><Time value={f.reported_at} relativeToo /></span></div>
                      <div className="small"><code>{f.tool}.{f.operation}</code> {f.resource} · error <code>{f.error_code ?? "unspecified"}</code></div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        </>
      )}
    </div>
  );
}

function Stat({ n, label, hint, link, icon, accent }: { n: number; label: string; hint?: string; link?: string; icon: string; accent: string }) {
  const body = (
    <div className="card stat-card" style={{ ["--accent" as any]: accent }}>
      <span className="ic"><Icon name={icon} size={18} /></span>
      <div className="n">{n}</div>
      <div className="l">{label}</div>
      {hint && <div className="h">{hint}</div>}
    </div>
  );
  return link ? <Link to={link} style={{ color: "inherit", textDecoration: "none" }} aria-label={`${label}: ${n}`}>{body}</Link> : body;
}


/**
 * The first question anyone has: is anything actually being stopped right now? Heimdall only stops actions on computers where
 * the Heimdall app is running and has set the AI tools up to ask it first. Say so plainly.
 */
function ProtectionStatus() {
  const { org } = useApp();
  const d = useLoad<any>(`/api/orgs/${org.id}/discovered`);
  useEffect(() => { const t = setInterval(d.reload, 10000); return () => clearInterval(t); }, [d.reload]);
  if (!d.data) return null;
  const items: any[] = d.data.items ?? [];
  const fresh = (t: string) => Date.now() - new Date(t).getTime() < 20 * 60_000;
  const protectedNow = items.filter((t) => t.protection === "protected" && fresh(t.last_seen_at));
  const restart = items.filter((t) => t.protection === "restart_needed");
  const stale = items.filter((t) => t.protectable && !fresh(t.last_seen_at));
  const devices = [...new Set(items.map((t) => t.device_name))];
  if (!d.data.auto_protect) {
    return <div className="alert warn"><strong>Automatic protection is off.</strong> AI tools on your computers are not being checked. Turn it on in <Link to="/protection">Protection Center</Link>.</div>;
  }
  if (!items.length) {
    return (
      <div className="alert bad" role="status">
        <strong>Nothing is being blocked yet: no computer is protecting its AI tools.</strong>
        <div style={{ marginTop: ".35rem" }}>Download and open the setup below. It installs the companion, links this computer, and starts it at Windows sign-in. No project folder or npm command is needed. Restart supported AI tools once after setup.</div>
        <ProtectComputer compact />
      </div>
    );
  }
  if (stale.length && !protectedNow.length) {
    return (
      <div className="alert bad" role="status">
        <strong>The Heimdall app stopped reporting from {devices.join(", ")}.</strong> Until it is running again those computers fall back to Standard protection on their own (keys, saved passwords and dangerous commands stay blocked; anything that needs approval is refused). Open the installed Heimdall app or download setup again from Protection Center.
      </div>
    );
  }
  return (
    <div className={`alert ${restart.length ? "warn" : "ok"}`} role="status">
      <strong>{protectedNow.length} AI {protectedNow.length === 1 ? "tool is" : "tools are"} protected on {devices.length} {devices.length === 1 ? "computer" : "computers"}.</strong>{" "}
      {restart.length ? <>Restart {restart.map((t) => t.product).join(", ")} once to finish protecting {restart.length === 1 ? "it" : "them"}. </> : null}
      <Link to="/live">Watch it live</Link> · <Link to="/protection">See what was found</Link>
    </div>
  );
}
