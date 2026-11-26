import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { BrowserRouter, NavLink, Navigate, Route, Routes, useLocation } from "react-router";
import { DevicePrompt, PairPage, usePushRefresh } from "./device-setup";
import { ApiError, api, useLoad } from "./api";
import { AppContext, Badge, ErrorBox, Field, Loading, ROLE_LABEL, ToastProvider, allowed, fieldErrors, useApp, type AppState, type OrgInfo } from "./ui";
import Security from "./pages/Security";
import Overview from "./pages/Overview";
import { AgentDetail, Agents } from "./pages/Agents";
import { PolicyPage } from "./pages/Policies";
import Activity from "./pages/Activity";
import { Alerts, Approvals } from "./pages/Queues";
import { Audit, Credentials } from "./pages/Credentials";
import Settings from "./pages/Settings";
import Roadmap from "./pages/Roadmap";
import Protection from "./pages/Protection";
import { useIncidentNotifier } from "./notifier";
import { Icon } from "./icons";
import { AppsMenu } from "./apps-menu";
import Live from "./pages/Live";

const Logo = () => (
  <span className="logo"><svg width="20" height="20" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 3l11 4v8c0 7-5 12-11 14C10 27 5 22 5 15V7z" fill="#E0B23D" /><path d="M11 16l4 4 7-8" stroke="#1F2547" strokeWidth="3" fill="none" strokeLinecap="round" strokeLinejoin="round" /></svg></span>
);

function AuthArt() {
  const pts = [
    ["Decide before it runs", "Every proposed tool call gets a deterministic allow, deny or approval decision from your policy."],
    ["Approve the exact action", "A human approves one specific action, once. Never a blanket permission."],
    ["Honest about protection", "We only say Blocked when your executor confirms it did not run the action."],
  ];
  return (
    <div className="auth-art">
      <div className="brand"><Logo /><span>Kenuxa Heimdall<small>Agent permission firewall</small></span></div>
      <h2>Control what your AI agents are allowed to do.</h2>
      <ul>{pts.map(([t, d]) => <li key={t}><Icon name="check" size={20} /><span><strong style={{ color: "#fff" }}>{t}.</strong> {d}</span></li>)}</ul>
    </div>
  );
}

const SSO_ERRORS: Record<string, string> = {
  SSO_CANCELLED: "Sign-in was cancelled.",
  SSO_STATE: "That sign-in expired or was already used. Please try again.",
  SSO_EMAIL_UNVERIFIED: "Your email address is not verified with that sign-in provider yet.",
  SSO_DOMAIN: "That account's email domain cannot sign in to this organization.",
  SSO_PROVIDER_UNREACHABLE: "The sign-in provider could not be reached. Please try again.",
  SSO_PROVIDER_ERROR: "The sign-in provider returned an error. Please try again.",
  NOT_FOUND: "No single sign-on is set up for that email address or organization.",
  EMAIL_REQUIRED: "Enter your work email to find your organization's sign-in.",
  RATE_LIMITED: "Too many sign-in attempts. Please wait a few minutes.",
};

const GoogleMark = () => (
  <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true"><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z" /><path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z" /><path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z" /><path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z" /></svg>
);

function startSso(provider: "google" | "kenuxa" | "oidc", extra: Record<string, string> = {}) {
  const returnTo = new URLSearchParams(location.search).get("return_to") ?? (location.pathname.startsWith("/login") ? "/" : location.pathname);
  location.href = `/api/auth/sso/start?${new URLSearchParams({ provider, return_to: returnTo, ...extra })}`;
}

function MfaStep({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [err, setErr] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <>
      <h1>Two-step verification</h1>
      <p className="muted">{useRecovery ? "Enter one of the recovery codes you saved when you set this up." : "Enter the 6-digit code from your authenticator app."}</p>
      <form className="form" onSubmit={async (e) => {
        e.preventDefault(); setBusy(true); setErr(null);
        try {
          await api("POST", "/api/auth/mfa/verify", useRecovery ? { recovery_code: code } : { code });
          const rt = new URLSearchParams(location.search).get("return_to");
          if (rt && rt.startsWith("/") && !rt.startsWith("//")) history.replaceState(null, "", rt);
          onDone();
        } catch (x) { setErr(x as Error); setBusy(false); if ((x as ApiError).status === 401 && /sign in again/i.test((x as Error).message)) onCancel(); }
      }}>
        <Field label={useRecovery ? "Recovery code" : "6-digit code"}>
          {useRecovery
            ? <input required autoComplete="off" placeholder="xxxx-xxxx-xxxx" value={code} onChange={(e) => setCode(e.target.value)} />
            : <input required autoFocus inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />}
        </Field>
        <ErrorBox error={err} />
        <button className="primary" disabled={busy}>{busy ? "Checking…" : "Verify"}</button>
      </form>
      <p className="small" style={{ marginTop: "1rem" }}>
        <button className="link" onClick={() => { setUseRecovery(!useRecovery); setCode(""); setErr(null); }}>{useRecovery ? "Use my authenticator app" : "Lost your phone? Use a recovery code"}</button>
        {" · "}<button className="link" onClick={onCancel}>Start again</button>
      </p>
    </>
  );
}

function AuthScreen({ onDone }: { onDone: () => void }) {
  const params = new URLSearchParams(location.search);
  const [mode, setMode] = useState<"login" | "register" | "mfa" | "org">(params.get("mfa") === "1" ? "mfa" : "login");
  const [f, setF] = useState({ email: "", name: "", password: "" });
  const [err, setErr] = useState<Error | null>(() => {
    const code = params.get("sso_error");
    return code ? new ApiError(401, code, SSO_ERRORS[code] ?? "Single sign-on did not complete. Please try again.") : null;
  });
  const [busy, setBusy] = useState(false);
  const providers = useLoad<{ google: boolean; kenuxa: boolean }>("/api/auth/sso/providers");
  const fe = fieldErrors(err);
  const restart = () => { history.replaceState(null, "", "/"); setMode("login"); setErr(null); setBusy(false); };
  return (
    <main className="auth" id="main">
      <AuthArt />
      <div className="auth-form"><div className="card">
        {mode === "mfa" ? <MfaStep onDone={onDone} onCancel={restart} /> : mode === "org" ? (
          <>
            <h1>Sign in with your organization</h1>
            <p className="muted">Enter your work email. We will send you to your organization's sign-in page.</p>
            <form className="form" onSubmit={(e) => { e.preventDefault(); startSso("oidc", { email: f.email }); }}>
              <Field label="Work email"><input required type="email" autoComplete="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></Field>
              <button className="primary">Continue</button>
            </form>
            <p className="small" style={{ marginTop: "1rem" }}><button className="link" onClick={() => setMode("login")}>Back</button></p>
          </>
        ) : (
        <>
        <h1>{mode === "login" ? "Sign in" : "Create your account"}</h1>
        <p className="muted">Control what your AI agents are allowed to do, and review every decision.</p>
        <div className="stack" style={{ gap: ".5rem", margin: "1rem 0" }}>
          {providers.data?.google && <button className="sso" onClick={() => startSso("google")}><GoogleMark /> Continue with Google</button>}
          {providers.data?.kenuxa && <button className="sso" onClick={() => startSso("kenuxa")}><span className="kx" aria-hidden="true">K</span> Continue with Kenuxa Account</button>}
          <button className="sso" onClick={() => { setMode("org"); setErr(null); }}><Icon name="shield" size={18} /> Sign in with your organization (SSO)</button>
        </div>
        <div className="or"><span>or with email</span></div>
        <form
          className="form"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setErr(null);
            try {
              if (mode === "register") await api("POST", "/api/auth/register", f);
              const r = await api("POST", "/api/auth/login", { email: f.email, password: f.password });
              if (r?.mfa_required) { setMode("mfa"); setBusy(false); return; }
              onDone();
            } catch (x) {
              setErr(x as Error);
              setBusy(false);
            }
          }}
        >
          {mode === "register" && (
            <Field label="Your name" error={fe.name}><input required autoComplete="name" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          )}
          <Field label="Email" error={fe.email}><input required type="email" autoComplete="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></Field>
          <Field label="Password" hint={mode === "register" ? "At least 12 characters." : undefined} error={fe.password}>
            <input required type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} minLength={mode === "register" ? 12 : undefined} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} />
          </Field>
          {err && Object.keys(fe).length === 0 && <ErrorBox error={err} />}
          <button className="primary" disabled={busy}>{busy ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}</button>
        </form>
        <p className="small" style={{ marginTop: "1rem" }}>
          {mode === "login" ? "New here? " : "Already registered? "}
          <button className="link" onClick={() => { setMode(mode === "login" ? "register" : "login"); setErr(null); }}>{mode === "login" ? "Create an account" : "Sign in"}</button>
        </p>
        <p className="muted small">Password reset by email is not available yet. Keep your password safe{providers.data?.google || providers.data?.kenuxa ? `, or sign in with ${[providers.data?.google && "Google", providers.data?.kenuxa && "your Kenuxa Account"].filter(Boolean).join(" or ")}` : ""}.</p>
        </>
        )}
      </div></div>
    </main>
  );
}

/** Shown instead of the organization when its sign-in rules are not met by this session. */
function OrgGate({ children }: { children: ReactNode }) {
  const { org } = useApp();
  const probe = useLoad<any>(`/api/orgs/${org.id}`);
  const mfa = useLoad<any>(probe.error?.code === "MFA_REQUIRED" ? "/api/auth/mfa" : null);
  const [code, setCode] = useState("");
  const [err, setErr] = useState<Error | null>(null);
  if (probe.loading && !probe.data) return <Loading kind="dashboard" />;
  if (probe.error?.code === "SSO_REQUIRED") {
    return (
      <section className="card" style={{ maxWidth: 560 }}>
        <h1>Sign in with {org.name}'s single sign-on</h1>
        <p>This organization requires its members to sign in through its identity provider.</p>
        <button className="primary" onClick={() => startSso("oidc", { org: org.id })}>Continue to single sign-on</button>
      </section>
    );
  }
  if (probe.error?.code === "MFA_REQUIRED") {
    return (
      <section className="card" style={{ maxWidth: 560 }}>
        <h1>Two-step verification required</h1>
        <p>{org.name} requires two-step verification.</p>
        {mfa.data && !mfa.data.enabled && <p>Turn it on for your account first: <NavLink to="/security">Security</NavLink>.</p>}
        {mfa.data?.enabled && (
          <form className="form" onSubmit={async (e) => {
            e.preventDefault(); setErr(null);
            try { await api("POST", "/api/auth/mfa/step-up", { code }); probe.reload(); } catch (x) { setErr(x as Error); }
          }}>
            <Field label="6-digit code from your authenticator app"><input required autoFocus inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} /></Field>
            <ErrorBox error={err} />
            <div><button className="primary">Verify</button></div>
          </form>
        )}
      </section>
    );
  }
  return <>{children}</>;
}

function CreateOrg({ onDone, first }: { onDone: (id: string) => void; first: boolean }) {
  const [name, setName] = useState("");
  const [err, setErr] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <main className="auth" id="main">
      <AuthArt />
      <div className="auth-form"><div className="card">
        <h1>{first ? "Create your organization" : "New organization"}</h1>
        <p className="muted">An organization holds your agents, policies, approvals and history. Only its members can see them.</p>
        <form className="form" onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          try { const o = await api("POST", "/api/orgs", { name }); onDone(o.id); } catch (x) { setErr(x as Error); setBusy(false); }
        }}>
          <Field label="Organization name" error={fieldErrors(err).name}><input required minLength={2} value={name} onChange={(e) => setName(e.target.value)} /></Field>
          {err && !fieldErrors(err).name && <ErrorBox error={err} />}
          <button className="primary" disabled={busy}>{busy ? "Creating…" : "Create organization"}</button>
        </form>
      </div></div>
    </main>
  );
}

function Shell({ state }: { state: AppState }) {
  const { org, user, orgs, setOrgId } = state;
  const counts = useLoad<any>(`/api/orgs/${org.id}/overview?hours=24`);
  const canAudit = allowed(org.role, "audit.read");
  const [open, setOpen] = useState(false);
  useIncidentNotifier(org.id);
  usePushRefresh();
  const loc = useLocation();
  useEffect(() => setOpen(false), [loc.pathname]);
  const link = (to: string, label: string, icon: string, badge?: number, red?: boolean) => (
    <NavLink to={to} end={to === "/"}><Icon name={icon} /><span className="grow">{label}</span>{badge ? <span className={`count ${red ? "red" : ""}`} aria-label={`${badge} waiting`}>{badge}</span> : null}</NavLink>
  );
  const initials = user.name.split(" ").map((p) => p[0]).slice(0, 2).join("").toUpperCase();
  return (
    <div className="shell">
      <a className="skip" href="#main">Skip to content</a>
      <aside className={`side ${open ? "open" : ""}`}>
        <div className="row between" style={{ flexWrap: "nowrap" }}>
          <div className="brand"><Logo /><span>Kenuxa Heimdall<small>Agent permission firewall</small></span></div>
          <button className="menu-btn" aria-expanded={open} aria-controls="side-body" onClick={() => setOpen(!open)}><Icon name={open ? "x" : "overview"} /><span className="skip">Menu</span></button>
        </div>
        <div id="side-body" className="side-body">
        <label>
          <span className="small muted">Organization</span>
          <select value={org.id} onChange={(e) => (e.target.value === "__new" ? (location.href = "/new-org") : setOrgId(e.target.value))} aria-label="Organization">
            {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            <option value="__new">+ New organization…</option>
          </select>
        </label>
        <nav className="nav" aria-label="Main">
          {link("/", "Overview", "overview")}
          <NavLink to="/live"><Icon name="activity" /><span className="grow">Live</span><span className="live-dot" aria-label="live" /></NavLink>
          <div className="nav-sec">Protect</div>
          {link("/protection", "Protection Center", "shield")}
          {link("/agents", "Agents", "agents")}
          {link("/policies", "Policies", "policies")}
          {link("/credentials", "Credentials", "credentials")}
          <div className="nav-sec">Investigate</div>
          {link("/activity", "Activity", "activity")}
          {link("/approvals", "Approvals", "approvals", counts.data?.pending_approvals)}
          {link("/alerts", "Alerts", "alerts", counts.data?.open_alerts, true)}
          {canAudit && link("/audit", "Audit log", "audit")}
          <div className="nav-sec">Organization</div>
          {link("/settings", "Settings", "settings")}
          {link("/security", "Security", "shield")}
          {link("/roadmap", "Not yet available", "roadmap")}
        </nav>
        <div className="me">
          <div className="row" style={{ flexWrap: "nowrap", gap: ".65rem" }}>
            <span className="avatar" aria-hidden="true">{initials}</span>
            <div style={{ minWidth: 0 }}><strong>{user.name}</strong><div className="muted" style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{user.email}</div></div>
          </div>
          <div className="row between" style={{ marginTop: ".7rem" }}>
            <Badge>{ROLE_LABEL[org.role]}</Badge>
            <button onClick={async () => { await api("POST", "/api/auth/logout"); location.href = "/"; }}>Sign out</button>
          </div>
          <div className="muted" style={{ marginTop: ".6rem" }}>Times shown in {org.timezone}</div>
        </div>
        </div>
      </aside>
      <main className="main" id="main" key={org.id}>
        <header className="topbar">
          <AppsMenu />
          <span className="avatar topbar-avatar" title={`${user.name} (${user.email})`} aria-label={`Signed in as ${user.name}`}>{initials}</span>
        </header>
        <Routes>
          {/* reachable even when the organization's sign-in rules block everything else, so people can turn MFA on */}
          <Route path="/security" element={<Security />} />
          <Route path="/pair" element={<PairPage />} />
          <Route path="*" element={<OrgGate><DevicePrompt />
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/live" element={<Live />} />
            <Route path="/protection" element={<Protection />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/agents/:id" element={<AgentDetail />} />
            <Route path="/policies" element={<PolicyPage />} />
            <Route path="/policies/:id" element={<PolicyPage />} />
            <Route path="/activity" element={<Activity />} />
            <Route path="/approvals" element={<Approvals />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/credentials" element={<Credentials />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/roadmap" element={<Roadmap />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          </OrgGate>} />
        </Routes>
      </main>
    </div>
  );
}

function Root() {
  const me = useLoad<{ user: AppState["user"]; orgs: OrgInfo[] }>("/api/auth/me");
  const [orgId, setOrgIdState] = useState<string | null>(() => {
    try { return localStorage.getItem("asg_org"); } catch { return null; }
  });
  const setOrgId = useCallback((id: string) => {
    try { localStorage.setItem("asg_org", id); } catch { /* storage unavailable */ }
    setOrgIdState(id);
  }, []);
  const [creating, setCreating] = useState(() => location.pathname === "/new-org");
  useEffect(() => { if (location.pathname === "/new-org") history.replaceState(null, "", "/"); }, []);

  const state = useMemo<AppState | null>(() => {
    if (!me.data || me.data.orgs.length === 0) return null;
    const org = me.data.orgs.find((o) => o.id === orgId) ?? me.data.orgs[0];
    return { user: me.data.user, orgs: me.data.orgs, org, setOrgId, refresh: me.reload };
  }, [me.data, orgId, setOrgId, me.reload]);

  if (me.loading && !me.data) return <main className="auth" style={{ gridTemplateColumns: "1fr", padding: "2rem" }}><Loading kind="dashboard" /></main>;
  if (me.error?.status === 401) return <AuthScreen onDone={me.reload} />;
  if (me.error) return <main className="auth"><div className="card"><ErrorBox error={me.error} retry={me.reload} /></div></main>;
  if (!state || creating) return <CreateOrg first={!state} onDone={(id) => { setOrgId(id); setCreating(false); me.reload(); }} />;
  return <AppContext.Provider value={state}><Shell state={state} /></AppContext.Provider>;
}

export default function App() {
  return (
    <ToastProvider>
      <BrowserRouter>
        <Root />
      </BrowserRouter>
    </ToastProvider>
  );
}

export { useApp, ApiError };
