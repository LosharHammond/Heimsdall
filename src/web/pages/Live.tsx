/**
 * Live: so people can see Heimdall working. What it is watching (computers, AI tools, rules in force), what it checked in
 * the last hour, and every check as it happens.
 */
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { api } from "../api";
import { Badge, ErrorBox, Loading, PageHeader, Time, useApp } from "../ui";

const POLL_MS = 3000;
const FRESH_MS = 3 * 60_000;

const WATCHES: Record<string, string> = {
  "claude-code": "Every command, file read and change, web fetch and MCP tool call",
  mcp_client: "Every tool call to its MCP tool servers",
  coding_agent: "Seen on this computer",
  ai_app: "Seen on this computer",
  local_model: "Seen on this computer",
  agent_script: "Seen on this computer",
  automation: "Seen on this computer",
};
const STATE: Record<string, [string, "ok" | "warn" | "bad" | undefined]> = {
  protected: ["Guarded", "ok"], restart_needed: ["Restart it once", "warn"], unprotected: ["Setting up", "warn"],
  off: ["Automatic protection off", undefined], not_possible: ["Seen only", "bad"],
};

/** Turns a Heimdall resource into what a person would call it. */
function where(resource: string): string {
  if (resource.startsWith("files/")) {
    const p = resource.slice(6);
    return /^[A-Z]\//.test(p) ? `${p[0]}:\\${p.slice(2).replace(/\//g, "\\")}` : `/${p}`;
  }
  if (resource.startsWith("shell/")) return resource.slice(6);
  if (resource.startsWith("mcp/")) { const [, server, tool] = resource.split("/"); return `${tool ?? "tool"} on ${server}`; }
  return resource;
}

export function describe(a: any): string {
  const cmd = a.args_summary?.command as string | undefined;
  const special: Record<string, string> = {
    "shell/download-and-run": "Run a script downloaded from the internet", "shell/encoded-command": "Run a hidden (encoded) command",
    "shell/disable-protection": "Turn off antivirus or the firewall", "shell/sends-data": "Send data out",
  };
  if (special[a.resource]) return `${special[a.resource]}${cmd ? `: ${cmd}` : ""}`;
  if (a.operation === "command_execution" || (cmd && a.resource.startsWith("shell/"))) return `Run: ${cmd ?? where(a.resource)}`;
  const target = where(a.resource);
  switch (a.operation) {
    case "read": return a.resource.startsWith("mcp/") ? `Use ${target}` : `Read ${target}`;
    case "create": return `Create ${target}`;
    case "update": return a.resource.startsWith("mcp/") ? `Use ${target}` : `Change ${target}`;
    case "delete": return cmd ? `Delete: ${cmd}` : `Delete ${target}`;
    case "external_transfer": return `Send data to ${a.destination ? new URL(a.destination).host : "the internet"}${cmd ? `: ${cmd}` : ""}`;
    default: return target;
  }
}

function Verdict({ a }: { a: any }) {
  if (a.decision === "deny") return <Badge tone="bad">Blocked</Badge>;
  if (a.decision === "require_approval") return <Badge tone="warn">Waiting for approval</Badge>;
  return <Badge tone="ok">Allowed</Badge>;
}

export default function Live() {
  const { org } = useApp();
  const [data, setData] = useState<any>(null);
  const [feed, setFeed] = useState<any[]>([]);
  const [error, setError] = useState<Error | null>(null);
  const [paused, setPaused] = useState(false);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const latest = useRef<string | null>(null);

  useEffect(() => {
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      if (!paused) {
        try {
          const d = await api<any>("GET", `/api/orgs/${org.id}/live${latest.current ? `?since=${encodeURIComponent(latest.current)}` : ""}`);
          if (stop) return;
          setData(d);
          setError(null);
          if (d.feed.length) {
            const firstLoad = latest.current === null;
            latest.current = d.feed[0].created_at;
            setFeed((old) => {
              const seen = new Set(old.map((x) => x.id));
              return [...d.feed.filter((x: any) => !seen.has(x.id)), ...old].slice(0, 150);
            });
            if (!firstLoad) setFresh(new Set(d.feed.map((x: any) => x.id)));
          } else if (latest.current === null) latest.current = d.now;
        } catch (e) { if (!stop) setError(e as Error); }
      }
      if (!stop) timer = setTimeout(tick, POLL_MS);
    };
    void tick();
    return () => { stop = true; clearTimeout(timer); };
  }, [org.id, paused]);

  if (!data && !error) return <Loading kind="dashboard" />;
  const devices: any[] = data?.devices ?? [];
  const tools: any[] = data?.tools ?? [];
  const online = devices.filter((d) => d.last_heartbeat_at && Date.now() - new Date(d.last_heartbeat_at).getTime() < FRESH_MS);
  const guarded = tools.filter((t) => t.protection === "protected" || t.protection === "restart_needed");
  const watching = online.length > 0 && guarded.length > 0;

  return (
    <div className="stack">
      <PageHeader
        title="Live"
        subtitle="What Heimdall is watching right now, the rules it holds AI tools to, and every action it checks as it happens."
        actions={<button onClick={() => setPaused(!paused)} aria-pressed={paused}>{paused ? "Resume" : "Pause"}</button>}
      />
      <ErrorBox error={error} />

      <section className={`watch-banner ${watching ? "on" : "off"}`} aria-live="polite">
        <span className={`beacon ${watching && !paused ? "on" : ""}`} aria-hidden="true" />
        <div>
          <strong>{watching ? `Watching ${guarded.length} AI ${guarded.length === 1 ? "tool" : "tools"} on ${online.length} ${online.length === 1 ? "computer" : "computers"}` : "Not watching any computer right now"}</strong>
          <p>{watching
            ? "Every action they try is checked against the rules below before it happens. New checks appear here within seconds."
            : <>No computer with the Heimdall app has reported in the last 3 minutes. Open <a href="/protection">Protection Center</a>, download the Windows setup, and open it on the computer you want to protect.</>}</p>
        </div>
        <dl className="watch-stats">
          <div><dt>Checked, last hour</dt><dd>{data?.last_hour.checked ?? 0}</dd></div>
          <div><dt>Allowed</dt><dd className="ok">{data?.last_hour.allowed ?? 0}</dd></div>
          <div><dt>Blocked</dt><dd className="bad">{data?.last_hour.blocked ?? 0}</dd></div>
          <div><dt>Waiting</dt><dd className="warn">{data?.last_hour.waiting ?? 0}</dd></div>
          <div><dt>Blocked, 24 hours</dt><dd>{data?.last_day.blocked ?? 0}</dd></div>
        </dl>
      </section>

      <div className="live-grid">
        <section className="card tight" aria-labelledby="h-feed">
          <div className="row between card-pad"><h2 id="h-feed">Every check, as it happens</h2>{paused ? <Badge tone="warn">Paused</Badge> : <span className="pulse on">Live</span>}</div>
          {feed.length === 0 ? (
            <div className="empty"><strong>Nothing checked yet</strong>When an AI tool on a watched computer reads a file, runs a command or uses a tool, it shows up here.</div>
          ) : (
            <ol className="feed">
              {feed.map((a) => (
                <li key={a.id} className={`${fresh.has(a.id) ? "new" : ""} d-${a.decision}`}>
                  <div className="feed-main">
                    <span className="feed-what">{describe(a)}</span>
                    <span className="feed-meta"><strong>{a.agent_name}</strong> · <Time value={a.created_at} relativeToo />{a.is_demo && " · demonstration"}</span>
                    {a.decision !== "allow" && a.explanation && <span className="feed-why">{a.explanation}</span>}
                  </div>
                  <div className="feed-verdict">
                    <Verdict a={a} />
                    {a.decision === "require_approval" && <Link className="small" to="/approvals">Decide</Link>}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>

        <div className="stack">
          <section className="card" aria-labelledby="h-watch">
            <h2 id="h-watch">What Heimdall is watching</h2>
            {devices.length === 0 ? <p className="muted">No computer has been added yet.</p> : (
              <ul className="watch-list">
                {devices.map((d) => {
                  const on = d.last_heartbeat_at && Date.now() - new Date(d.last_heartbeat_at).getTime() < FRESH_MS;
                  const mine = tools.filter((t) => t.device_id === d.id);
                  return (
                    <li key={d.id}>
                      <div className="row between"><span className="row" style={{ gap: ".5rem" }}><span className={`dot-state ${on ? "on" : ""}`} aria-hidden="true" /><strong>{d.name}</strong></span>
                        <span className="muted small">{on ? "reporting" : <>last heard <Time value={d.last_heartbeat_at} relativeToo /></>}</span></div>
                      {mine.length === 0 ? <p className="muted small">No AI tools found on this computer yet.</p> : (
                        <ul className="tool-list">
                          {mine.map((t) => {
                            const [label, tone] = STATE[t.protection] ?? [t.protection, undefined];
                            return (
                              <li key={t.key}>
                                <div className="row between"><span>{t.product}{t.running && <span className="muted small"> · open</span>}</span><Badge tone={tone}>{label}</Badge></div>
                                <span className="muted small">{t.protectable ? (WATCHES[t.key] ?? WATCHES[t.kind]) : "Heimdall can see it, but cannot stand in front of its actions."}{t.detail ? ` (${t.detail})` : ""}</span>
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </section>

          <section className="card" aria-labelledby="h-rules">
            <h2 id="h-rules">Rules in force</h2>
            {(data?.policies ?? []).length === 0 ? <p className="muted">No agent has a policy yet.</p> : data.policies.map((p: any) => (
              <div key={p.id} className="rules">
                <p className="small muted"><Link to={`/policies/${p.id}`}>{p.name}</Link> · version {p.version} · {p.agents} {p.agents === 1 ? "tool" : "tools"}</p>
                {([["deny", "Never", "bad"], ["require_approval", "Asks you first", "warn"], ["allow", "Runs at once", "ok"]] as const).map(([eff, title, tone]) => {
                  const rs = p.rules.filter((r: any) => r.effect === eff);
                  return rs.length ? (
                    <div key={eff} className={`rule-group ${tone}`}>
                      <h3>{title}</h3>
                      <ul>{rs.map((r: any) => <li key={r.id}>{r.description ?? r.id.replace(/[-_]/g, " ")}</li>)}</ul>
                    </div>
                  ) : null;
                })}
              </div>
            ))}
          </section>
        </div>
      </div>
    </div>
  );
}
