import { useState } from "react";
import { Link } from "react-router";
import { ProtectionHero } from "../protection-hero";
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
      <ProtectionHero />
      <div className="row between section-bar">
        <h2>Activity <span className="muted small" style={{ fontWeight: 500 }}>· counted from recorded events</span></h2>
        <label className="small row" style={{ gap: ".5rem" }}>
          Period
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))} aria-label="Period">
            <option value={24}>Last 24 hours</option><option value={168}>Last 7 days</option><option value={720}>Last 30 days</option>
          </select>
        </label>
      </div>
      {d && d.pending_approvals > 0 && <Link to="/approvals" className="alert warn" style={{ textDecoration: "none", color: "inherit" }}><strong>{d.pending_approvals} {d.pending_approvals === 1 ? "action is" : "actions are"} waiting for your approval.</strong> Review →</Link>}
      <ErrorBox error={error} retry={reload} />
      {loading && !d && <Loading kind="dashboard" />}
      {d && (
        <>
          <div className="grid cols-4" aria-label={`Decisions in the ${label}`}>
            <Stat icon="check" accent="var(--c-allow)" n={d.decisions.allowed} label="Allowed" hint="Policy permitted the action." />
            <Stat icon="ban" accent="var(--c-deny)" n={d.decisions.denied} label="Blocked" hint="Policy refused the action." />
            <Stat icon="clock" accent="var(--c-appr)" n={d.decisions.needs_approval} label="Sent for approval" hint="A person decided." />
            <Stat icon="shield" accent="var(--brand)" n={d.executions.blocked_confirmed} label="Confirmed stopped" hint="The protected tool confirmed it did not run." />
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


