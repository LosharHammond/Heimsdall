import { policyDocumentSchema } from "../../shared/policy.js";
import { agentView, RECENT_MS, type AgentRow, type Ctx } from "./core.js";
import { requireRole } from "./admin.js";
import { DEVICE_DEAD_MS, DEVICE_FRESH_MS, deviceConnection, type DeviceRow } from "./devices.js";

export type LayerStatus = "enforcing" | "observing_only" | "setup_required" | "degraded" | "unsupported" | "not_protected";

export interface Layer {
  key: string;
  title: string;
  status: LayerStatus;
  summary: string;
  evidence: string[];
  last_check: string | null;
  scope: string;
  limits: string[];
  items?: Array<{ name: string; status: LayerStatus; detail: string }>;
}

const ago = (d: Date | string | null | undefined) => {
  if (!d) return "never";
  const s = Math.round((Date.now() - new Date(d).getTime()) / 1000);
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} d ago`;
};
const latest = (ds: Array<Date | string | null | undefined>) => {
  const t = ds.filter(Boolean).map((d) => new Date(d as any).getTime());
  return t.length ? new Date(Math.max(...t)).toISOString() : null;
};

/**
 * Honest, per-layer coverage. There is deliberately NO overall score or "protected" badge: each layer says what is being
 * enforced, how we know (evidence), when it was last checked and exactly what it covers and does not cover.
 */
export async function protection(ctx: Ctx, userId: string, orgId: string) {
  await requireRole(ctx.db, userId, orgId, "viewer");
  const now = Date.now();
  const agents = await ctx.db.query<AgentRow>("SELECT * FROM agents WHERE org_id = $1 AND status = 'active' ORDER BY name", [orgId]);
  const execs = await ctx.db.query<any>("SELECT * FROM executor_status WHERE org_id = $1", [orgId]);
  const devices = await ctx.db.query<DeviceRow>("SELECT * FROM devices WHERE org_id = $1 ORDER BY name", [orgId]);
  const activeDevices = devices.filter((d) => d.status === "active");
  const policies = await ctx.db.query<any>(
    `SELECT a.id AS agent_id, v.document FROM agents a JOIN policies p ON p.id = a.policy_id AND p.org_id = a.org_id
       JOIN policy_versions v ON v.policy_id = p.id AND v.version = p.current_version WHERE a.org_id = $1 AND a.status = 'active'`,
    [orgId],
  );
  const policyOf = new Map(policies.map((p) => [p.agent_id as string, policyDocumentSchema.parse(p.document)]));
  const execOf = new Map(execs.map((e) => [e.agent_id as string, e]));
  const views = agents.map((a) => ({ a, v: agentView(a) }));
  const sdk = views.filter((x) => x.a.integration_type !== "event_reporting");

  // ---- 1. connected AI tool enforcement ----
  const enforcing = sdk.filter((x) => x.v.connection.state === "enforcing");
  const enforcingFresh = enforcing.filter((x) => x.v.connection.connected_recently);
  const l1: Layer = {
    key: "ai_tool_enforcement", title: "Connected AI tool enforcement",
    status: "setup_required", summary: "", evidence: [], last_check: latest(views.map((x) => x.a.last_seen_at)),
    scope: "Tool calls an agent makes THROUGH its connected Heimdall executor. Nothing else.",
    limits: ["An agent or application that can reach files, networks or credentials directly is not controlled.", "Other tools in the same AI client (a shell, another file server) are outside Heimdall."],
    items: views.map((x) => ({
      name: `${x.a.name} (${x.a.environment})`,
      status: (x.v.connection.state === "enforcing" ? (x.v.connection.connected_recently ? "enforcing" : "degraded") : x.v.connection.state === "not_connected" ? "setup_required" : "observing_only") as LayerStatus,
      detail: x.v.connection.label + (x.v.connection.state === "not_connected" ? "" : `, last seen ${ago(x.a.last_seen_at)}`),
    })),
  };
  if (views.length === 0) {
    l1.summary = "No agent is registered.";
    l1.evidence.push("0 active agents");
  } else if (enforcingFresh.length > 0) {
    l1.status = "enforcing";
    l1.summary = `${enforcingFresh.length} agent${enforcingFresh.length === 1 ? "" : "s"} enforcing through an adapter.`;
    l1.evidence.push(...enforcingFresh.map((x) => `${x.a.name}: adapter confirmed an execution claim or refusal ${ago(x.a.last_enforced_at)}; seen ${ago(x.a.last_seen_at)}`));
  } else if (enforcing.length > 0) {
    l1.status = "degraded";
    l1.summary = "Agents previously enforced but have not been seen in the last 15 minutes.";
    l1.evidence.push(...enforcing.map((x) => `${x.a.name}: last seen ${ago(x.a.last_seen_at)}`));
  } else if (views.some((x) => x.v.connection.state !== "not_connected")) {
    l1.status = "observing_only";
    l1.summary = "Agents are connected but no enforcement has been confirmed by an adapter (monitor mode, event-only, or no action claimed yet).";
    l1.evidence.push(...views.filter((x) => x.v.connection.state !== "not_connected").map((x) => `${x.a.name}: ${x.v.connection.label}`));
  } else {
    l1.summary = "Agents are registered but none has connected yet.";
    l1.evidence.push(`${views.length} registered, 0 connected`);
  }

  // ---- 2. protected folders / resources ----
  const rootsEvidence: string[] = [];
  let freshRoots = 0, staleRoots = 0, monitorRoots = 0, noPolicyRoots = 0;
  const scopeLabels: string[] = [];
  for (const x of sdk) {
    const e = execOf.get(x.a.id);
    if (!e || !Array.isArray(e.roots) || e.roots.length === 0) continue;
    const fresh = now - new Date(e.reported_at).getTime() <= RECENT_MS;
    const labels = e.roots.map((r: any) => (r.prefix ? `${r.label} (${r.prefix})` : r.label));
    scopeLabels.push(...labels.map((l: string) => `${l} via ${x.a.name}`));
    rootsEvidence.push(`${x.a.name}: executor attested ${e.roots.length} protected root(s) ${ago(e.reported_at)}${fresh ? "" : " (stale)"}`);
    if (!fresh) staleRoots++;
    else if (x.a.enforcement_mode === "monitor") monitorRoots++;
    else if (!x.a.policy_id) noPolicyRoots++;
    else freshRoots++;
  }
  const l2: Layer = {
    key: "protected_resources", title: "Supported protected folders and resources", status: "setup_required", summary: "", evidence: rootsEvidence,
    last_check: latest(execs.map((e) => e.reported_at)),
    scope: scopeLabels.length ? `Only: ${scopeLabels.join("; ")}. Paths are checked for traversal, links/junctions, hard links, case and file replacement.` : "No folder is declared.",
    limits: ["Files outside the declared folder are not protected.", "The executor is not an operating-system sandbox: a process with direct file access can bypass it.", "A very small race remains between the last check and the file operation on Windows."],
  };
  if (rootsEvidence.length === 0) {
    l2.summary = "No executor has reported a protected folder. Start the MCP server or companion with a protected root.";
  } else if (freshRoots > 0) {
    l2.status = "enforcing";
    l2.summary = `${freshRoots} protected folder${freshRoots === 1 ? "" : "s"} enforced by a running executor.`;
  } else if (monitorRoots > 0) {
    l2.status = "observing_only";
    l2.summary = "The executor is in monitor mode: decisions are recorded but not enforced.";
  } else if (noPolicyRoots > 0) {
    l2.status = "degraded";
    l2.summary = "The executor guards the folder but no policy is assigned, so every action is denied until one is.";
  } else {
    l2.status = "degraded";
    l2.summary = "The executor has not reported in the last 15 minutes; the folder cannot be assumed protected.";
  }

  // ---- 3. outbound destinations ----
  const egressExecs = sdk.filter((x) => execOf.get(x.a.id)?.egress_enabled && now - new Date(execOf.get(x.a.id).reported_at).getTime() <= RECENT_MS);
  const anyExec = sdk.filter((x) => execOf.get(x.a.id) && now - new Date(execOf.get(x.a.id).reported_at).getTime() <= RECENT_MS);
  const domains = new Set<string>();
  for (const x of egressExecs) for (const r of policyOf.get(x.a.id)?.rules ?? []) if (r.effect === "allow") for (const d of r.match.destination_domains ?? []) domains.add(d);
  const l3: Layer = {
    key: "outbound_destinations", title: "Supported outbound destinations", status: "setup_required", summary: "", evidence: [],
    last_check: latest(execs.map((e) => e.reported_at)),
    scope: domains.size ? `Transfers made through the executor to: ${[...domains].join(", ")}. Destinations are normalized, DNS is vetted (private addresses refused), no redirects, https and port 443 only.` : "Transfers made through the executor only.",
    limits: ["Other programs' network traffic is not controlled (no device-wide firewall).", "Browser traffic and other applications' uploads are not covered.", "Unsupported: device-wide network filtering."],
  };
  if (anyExec.length === 0) l3.summary = "No running executor has reported its egress configuration.";
  else if (egressExecs.length > 0) {
    l3.status = "enforcing";
    l3.summary = `External transfers through the executor are limited to ${domains.size} approved destination${domains.size === 1 ? "" : "s"}.`;
    l3.evidence.push(...egressExecs.map((x) => `${x.a.name}: egress enabled, attested ${ago(execOf.get(x.a.id).reported_at)}`));
  } else {
    l3.status = "enforcing";
    l3.summary = "External transfers are disabled on the running executor(s): every transfer through them is refused.";
    l3.evidence.push(...anyExec.map((x) => `${x.a.name}: egress disabled`));
  }

  // ---- 4. enrolled device health ----
  const l4: Layer = {
    key: "device_health", title: "Enrolled device health", status: "setup_required", summary: "", evidence: [], last_check: latest(activeDevices.map((d) => d.last_heartbeat_at)),
    scope: "Devices where the native companion is installed and enrolled. Windows is the only supported platform today.",
    limits: ["Only reflects the last heartbeat. A powered-off laptop, a stopped companion or no network means no local enforcement or notifications until it reports again.", "Nothing runs before the user signs in: the companion starts at sign-in."],
    items: devices.map((d) => {
      const c = deviceConnection(d);
      const ex = d.health?.executor?.state;
      const st: LayerStatus = d.status !== "active" ? "not_protected" : c.state === "online" ? (ex === "running" ? "enforcing" : "degraded") : c.state === "stale" ? "degraded" : "not_protected";
      return { name: `${d.name} (${d.platform})`, status: st, detail: `${c.label}${d.last_heartbeat_at ? `, heartbeat ${ago(d.last_heartbeat_at)}` : ""}${c.state === "online" ? `; executor ${ex ?? "unknown"}` : ""}` };
    }),
  };
  const live = activeDevices.filter((d) => deviceConnection(d).state === "online");
  const healthy = live.filter((d) => d.health?.executor?.state === "running");
  if (activeDevices.length === 0) l4.summary = devices.length ? "Every enrolled device is revoked, removed or waiting for enrollment." : "No device is enrolled.";
  else if (healthy.length > 0) {
    l4.status = "enforcing";
    l4.summary = `${healthy.length} of ${activeDevices.length} active device(s) have a running companion and executor.`;
    l4.evidence.push(...healthy.map((d) => `${d.name}: heartbeat ${ago(d.last_heartbeat_at)}, companion ${d.companion_version ?? "?"}`));
  } else if (live.length > 0) {
    l4.status = "degraded";
    l4.summary = "A companion is online but its executor is missing or stale.";
    l4.evidence.push(...live.map((d) => `${d.name}: executor ${d.health?.executor?.state ?? "unknown"}`));
  } else if (activeDevices.some((d) => d.last_heartbeat_at && now - new Date(d.last_heartbeat_at).getTime() <= DEVICE_DEAD_MS)) {
    l4.status = "degraded";
    l4.summary = "The companion's heartbeat is stale. Local enforcement cannot be assumed.";
    l4.evidence.push(...activeDevices.map((d) => `${d.name}: last heartbeat ${ago(d.last_heartbeat_at)}`));
  } else {
    l4.status = "not_protected";
    l4.summary = "No enrolled device has a live companion. The laptop may be off, offline or the companion stopped. No endpoint enforcement is claimed.";
    l4.evidence.push(...activeDevices.map((d) => `${d.name}: last heartbeat ${ago(d.last_heartbeat_at)}`));
  }

  // ---- 5. desktop notification delivery ----
  const delivered = await ctx.db.query<any>("SELECT device_id, count(*)::int AS n, max(delivered_at) AS last FROM notification_deliveries WHERE org_id = $1 AND state = 'shown' GROUP BY device_id", [orgId]);
  const delivMap = new Map(delivered.map((r) => [r.device_id as string, r]));
  const l5: Layer = {
    key: "notification_delivery", title: "Desktop notification delivery", status: "setup_required", summary: "", evidence: [], last_check: latest(activeDevices.map((d) => d.notification_checked_at)),
    scope: "Windows app notifications shown by the companion for incident-class alerts (high-risk denials, argument changes, revoked-key use, execution failures).",
    limits: ["Windows decides whether a toast appears: if notifications are off or Do Not Disturb/Focus is on, the alert is still recorded in the dashboard but may not pop up.", "Focus assist cannot always be detected; delivery is reported as 'shown' only when Windows accepted the toast.", "The browser dashboard cannot notify you when it is closed; only the native companion can."],
    items: activeDevices.map((d) => {
      const s = d.notification_state ?? "unknown";
      const fresh = d.notification_checked_at && now - new Date(d.notification_checked_at).getTime() <= DEVICE_FRESH_MS * 2;
      const st: LayerStatus = !fresh ? "degraded" : s === "enabled" ? "enforcing" : s === "unsupported" ? "unsupported" : "degraded";
      return { name: d.name, status: st, detail: `Windows reports: ${s.replace(/_/g, " ")}${delivMap.get(d.id) ? `; ${delivMap.get(d.id).n} shown, last ${ago(delivMap.get(d.id).last)}` : "; none shown yet"}` };
    }),
  };
  if (activeDevices.length === 0) l5.summary = "No device is enrolled, so there is no native notification path. Alerts appear only in this dashboard.";
  else {
    const okDev = l5.items!.filter((i) => i.status === "enforcing");
    if (okDev.length === activeDevices.length) { l5.status = "enforcing"; l5.summary = "Windows accepts notifications from the companion on every active device."; }
    else if (okDev.length > 0) { l5.status = "degraded"; l5.summary = "Some devices are not currently able to show notifications."; }
    else if (l5.items!.every((i) => i.status === "unsupported")) { l5.status = "unsupported"; l5.summary = "Notifications are not supported on these devices."; }
    else { l5.status = "degraded"; l5.summary = "Notifications are blocked, suppressed or unverified on every active device. Protection is unaffected; alerts stay in the dashboard."; }
    l5.evidence.push(...l5.items!.map((i) => `${i.name}: ${i.detail}`));
  }

  // ---- 6. operating-system security status (consent-based, observation only) ----
  const consented = activeDevices.filter((d) => d.consent?.os_security === true);
  const l6: Layer = {
    key: "os_security", title: "Operating-system security status", status: "setup_required", summary: "", evidence: [], last_check: latest(consented.map((d) => d.health?.os_security?.checked_at)),
    scope: "The status Windows Security (Microsoft Defender) reports for an enrolled device, read only with the device user's consent.",
    limits: ["Heimdall observes this status; it does not scan, block malware or control Windows Security.", "Heimdall is not an antivirus replacement and has not been tested as one.", "No file contents, process arguments or browsing data are collected."],
  };
  if (activeDevices.length === 0) l6.summary = "No device is enrolled.";
  else if (activeDevices.every((d) => d.platform !== "windows")) { l6.status = "unsupported"; l6.summary = "OS security status is only available for Windows devices."; }
  else if (consented.length === 0) l6.summary = "Not enabled. The device user can opt in on the device (optional).";
  else {
    const bad = consented.filter((d) => !d.health?.os_security || d.health.os_security.realtime_protection === false || d.health.os_security.antivirus_enabled === false || (d.health.os_security.signature_age_days ?? 0) > 7);
    l6.evidence.push(...consented.map((d) => { const o = d.health?.os_security; return o ? `${d.name}: ${o.provider} real-time protection ${o.realtime_protection}, antivirus ${o.antivirus_enabled}, signatures ${o.signature_age_days ?? "?"} day(s) old (checked ${ago(o.checked_at)})` : `${d.name}: no status reported`; }));
    if (bad.length > 0) { l6.status = "degraded"; l6.summary = `${bad.length} device(s) report a weakened or missing Windows security status.`; }
    else { l6.status = "observing_only"; l6.summary = "Windows Security reports real-time protection on. Heimdall only observes this."; }
  }

  // ---- onboarding ----
  const tests = await ctx.db.query<any>("SELECT result, completed_at, status FROM device_commands WHERE org_id = $1 AND kind = 'selftest' ORDER BY created_at DESC LIMIT 1", [orgId]);
  const test = tests[0];
  const testPassed = test?.status === "done" && test.result?.passed === true;
  const steps = [
    { id: "resources", title: "Select the resources to protect", done: rootsEvidence.length > 0, detail: "Start an executor with a protected folder (the MCP server or laptop connector). Its root appears in the Protection Center once it reports." },
    { id: "agent", title: "Connect an agent", done: views.some((x) => x.v.connection.state !== "not_connected"), detail: "Register an agent and run the connection command shown after registration." },
    { id: "executor", title: "Verify its executor", done: enforcing.length > 0, detail: "Run any action through the executor. The agent becomes 'Enforcing' once the adapter confirms a claim or refusal." },
    { id: "device", title: "Enroll a device", done: activeDevices.some((d) => deviceConnection(d).state === "online"), detail: "Answer “Yes” to “Add this device?” in a browser, or start the Heimdall app on a computer and confirm its code here." },
    { id: "notifications", title: "Enable desktop notifications", done: activeDevices.some((d) => d.notification_state === "enabled"), detail: "Windows must allow notifications for Kenuxa Heimdall. Send a test notification to confirm." },
    { id: "test", title: "Run a safe protection test", done: testPassed, detail: "The companion checks its executor against disposable fixtures: denied deletion, blocked upload, refused command. It touches no real files." },
  ];

  return {
    generated_at: new Date().toISOString(),
    notice: "There is no single 'protected' rating. Each layer below states what is enforced, the evidence, when it was last checked and what it does not cover.",
    layers: [l1, l2, l3, l4, l5, l6],
    onboarding: steps,
    last_selftest: test ? { status: test.status, completed_at: test.completed_at, result: test.result } : null,
  };
}

export { DEVICE_FRESH_MS };
