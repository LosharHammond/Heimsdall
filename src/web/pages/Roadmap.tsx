import { Badge, PageHeader } from "../ui";

const LATER = [
  ["Linux and macOS companions", "Not available. Only a Windows companion exists, and it provides enrollment, health reporting and native notifications. It is not an antivirus and does not scan, quarantine or block malware."],
  ["Device-wide file and network control", "Not available and not planned as a claim. Heimdall controls actions routed through its executor (one protected folder, approved destinations). It cannot control other programs' file access or network traffic."],
  ["Automatic discovery of AI tools", "Not available. Heimdall only sees agents that are registered and connected with a key. An optional, consent-based process-name inventory is weak evidence and never proves software is an AI agent."],
  ["AI-model gateway / proxy", "Planned. A proxy could inspect model traffic routed through it, but it cannot stop a separate application from running a tool outside it. Enforcement needs the executor."],
  ["Email, chat and SMS alert delivery", "Not available. Incidents appear in this dashboard and as Windows notifications from an enrolled device's companion."],
  ["Web Push to closed browsers", "Not available. Browser notifications work only while the dashboard is loaded. The native companion covers closed-browser delivery."],
  ["Billing and subscriptions", "Not available."],
  ["Machine-learning detection and risk scores", "Not available. Every number in this product is counted from recorded events, never predicted."],
  ["Email invitations and password reset", "Not available. Add existing accounts from Settings."],
];

export default function Roadmap() {
  return (
    <div className="stack">
      <PageHeader title="Not yet available" subtitle="These are planned but do not exist yet. They are shown so you know exactly what is not protecting you." />
      <section className="card">
        <h2>What “protected” means here</h2>
        <dl className="kv" style={{ gridTemplateColumns: "160px 1fr" }}>
          <dt>Observation</dt><dd>An event was <em>reported</em>. It says nothing about whether anything was prevented.</dd>
          <dt>Authorization</dt><dd>The policy engine issued a decision: allow, deny, or require approval.</dd>
          <dt>Enforcement</dt><dd>An integrated executor confirmed it did, or did not, run the action. Only then do we say <strong>Blocked</strong>.</dd>
        </dl>
        <p className="muted small" style={{ marginBottom: 0 }}>Heimdall does not protect against a fully compromised application that can bypass the adapter or reach the underlying credentials directly.</p>
      </section>
      <div className="grid cols-2">
        {LATER.map(([t, d]) => (
          <section key={t} className="card disabled-card">
            <div className="row between"><h3 style={{ margin: 0 }}>{t}</h3><Badge>Not available</Badge></div>
            <p className="muted" style={{ marginBottom: 0 }}>{d}</p>
          </section>
        ))}
      </div>
    </div>
  );
}
