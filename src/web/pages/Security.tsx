import QRCode from "qrcode";
import { useEffect, useState } from "react";
import { api, useLoad } from "../api";
import { Badge, Confirm, ErrorBox, Field, Loading, PageHeader, ROLE_LABEL, Time, fieldErrors, useApp, useCan, useToast } from "../ui";

const METHOD: Record<string, string> = { password: "Password", google: "Google", kenuxa: "Kenuxa Account", oidc: "Organization SSO" };

export default function Security() {
  const owner = useCan("owner");
  return (
    <div className="stack">
      <PageHeader title="Security" subtitle="Two-step verification, where you are signed in, and how people sign in to this organization." />
      <MfaCard />
      <SessionsCard />
      <OrgSecurityCard owner={owner} />
      {owner && <DomainsCard />}
      {owner && <SsoCard />}
    </div>
  );
}

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  return (
    <div className="callout">
      <h3>Save your recovery codes</h3>
      <p className="small">Each code works once if you lose your phone. They will not be shown again. Store them in a password manager or print them.</p>
      <pre style={{ columns: 2, fontSize: "1rem" }}>{codes.join("\n")}</pre>
      <div className="row">
        <button onClick={() => navigator.clipboard?.writeText(codes.join("\n"))}>Copy codes</button>
        <button className="primary" onClick={onDone}>I have saved them</button>
      </div>
    </div>
  );
}

function MfaCard() {
  const toast = useToast();
  const st = useLoad<any>("/api/auth/mfa");
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [change, setChange] = useState<"disable" | "regenerate" | null>(null);
  const [err, setErr] = useState<Error | null>(null);
  useEffect(() => {
    if (setup) void QRCode.toDataURL(setup.otpauth_uri, { margin: 1, width: 200 }).then(setQr).catch(() => setQr(null));
  }, [setup]);
  if (st.loading && !st.data) return <section className="card"><Loading /></section>;
  const s = st.data;
  return (
    <section className="card">
      <div className="row between">
        <h2>Two-step verification</h2>
        {s && (s.enabled ? <Badge tone="ok">On</Badge> : <Badge tone="warn">Off</Badge>)}
      </div>
      <ErrorBox error={st.error} retry={st.reload} />
      {codes && <RecoveryCodes codes={codes} onDone={() => { setCodes(null); st.reload(); }} />}
      {s && !s.enabled && !setup && (
        <form className="form" onSubmit={async (e) => {
          e.preventDefault(); setErr(null);
          try { setSetup(await api("POST", "/api/auth/mfa/setup", s.has_password ? { password } : {})); setPassword(""); } catch (x) { setErr(x as Error); }
        }}>
          <p className="muted">After your password, you will also enter a 6-digit code from an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Authy…).</p>
          {s.has_password && <Field label="Confirm your password"><input type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>}
          <ErrorBox error={err} />
          <div><button className="primary">Set up an authenticator app</button></div>
        </form>
      )}
      {setup && (
        <form className="form" onSubmit={async (e) => {
          e.preventDefault(); setErr(null);
          try { const r = await api("POST", "/api/auth/mfa/enable", { code }); setCodes(r.recovery_codes); setSetup(null); setCode(""); toast("Two-step verification is on"); } catch (x) { setErr(x as Error); }
        }}>
          <ol>
            <li>Scan this code with your authenticator app{qr ? "" : " (or enter the key below)"}.</li>
            <li>Enter the 6-digit code it shows.</li>
          </ol>
          {qr && <img src={qr} width={200} height={200} alt="QR code for your authenticator app" />}
          <p className="small">Key: <code style={{ wordBreak: "break-all" }}>{setup.secret}</code></p>
          <Field label="6-digit code"><input inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} required value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} /></Field>
          <ErrorBox error={err} />
          <div className="row"><button className="primary">Turn on</button><button type="button" onClick={() => setSetup(null)}>Cancel</button></div>
        </form>
      )}
      {s?.enabled && !codes && (
        <>
          <p>On since <Time value={s.enabled_at} />. {s.recovery_codes_left} recovery code{s.recovery_codes_left === 1 ? "" : "s"} left.{s.recovery_codes_left < 3 && <> <Badge tone="warn">Make new codes</Badge></>}</p>
          {!change && <div className="row"><button onClick={() => setChange("regenerate")}>New recovery codes</button><button className="danger" onClick={() => setChange("disable")}>Turn off</button></div>}
          {change && (
            <form className="form" onSubmit={async (e) => {
              e.preventDefault(); setErr(null);
              try {
                if (change === "disable") { await api("POST", "/api/auth/mfa/disable", { password: s.has_password ? password : undefined, code }); toast("Two-step verification is off"); }
                else setCodes((await api("POST", "/api/auth/mfa/recovery-codes", { password: s.has_password ? password : undefined, code })).recovery_codes);
                setChange(null); setPassword(""); setCode(""); st.reload();
              } catch (x) { setErr(x as Error); }
            }}>
              {s.has_password && <Field label="Your password"><input type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>}
              <Field label="Current 6-digit code"><input inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} required value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} /></Field>
              <ErrorBox error={err} />
              <div className="row"><button className={change === "disable" ? "danger" : "primary"}>{change === "disable" ? "Turn off" : "Make new codes"}</button><button type="button" onClick={() => { setChange(null); setErr(null); }}>Cancel</button></div>
            </form>
          )}
        </>
      )}
    </section>
  );
}

function SessionsCard() {
  const toast = useToast();
  const s = useLoad<any>("/api/auth/sessions");
  return (
    <section className="card">
      <div className="row between">
        <h2>Where you are signed in</h2>
        {s.data?.items.length > 1 && <button onClick={async () => { const r = await api("POST", "/api/auth/sessions/revoke-others"); toast(`Signed out ${r.revoked} other session${r.revoked === 1 ? "" : "s"}`); s.reload(); }}>Sign out everywhere else</button>}
      </div>
      <ErrorBox error={s.error} retry={s.reload} />
      {s.data && (
        <div className="table-wrap"><table>
          <caption className="skip">Your sessions</caption>
          <thead><tr><th>Device</th><th>Signed in with</th><th>Started</th><th>Last active</th><th><span className="skip">Actions</span></th></tr></thead>
          <tbody>{s.data.items.map((x: any) => (
            <tr key={x.id}>
              <td>{deviceName(x.user_agent)}{x.current && <> <Badge tone="info">this device</Badge></>}<div className="muted small">{x.ip ?? ""}</div></td>
              <td>{METHOD[x.auth_method] ?? x.auth_method}{x.mfa_verified && <> <Badge tone="ok">2-step</Badge></>}</td>
              <td><Time value={x.created_at} /></td>
              <td><Time value={x.last_seen_at} relativeToo /></td>
              <td>{!x.current && <button onClick={async () => { await api("DELETE", `/api/auth/sessions/${x.id}`); toast("Signed out"); s.reload(); }}>Sign out</button>}</td>
            </tr>))}</tbody>
        </table></div>
      )}
    </section>
  );
}

function deviceName(ua: string | null) {
  if (!ua) return "Unknown device";
  const os = /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "Mac" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iPhone/iPad" : /Linux/.test(ua) ? "Linux" : "";
  const br = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "Browser";
  return [br, os].filter(Boolean).join(" on ");
}

function OrgSecurityCard({ owner }: { owner: boolean }) {
  const { org } = useApp();
  const toast = useToast();
  const s = useLoad<any>(`/api/orgs/${org.id}/security`);
  const [confirm, setConfirm] = useState<null | { key: "require_mfa" | "sso_enforced"; value: boolean }>(null);
  const [err, setErr] = useState<Error | null>(null);
  if (s.loading && !s.data) return <section className="card"><Loading /></section>;
  const d = s.data;
  return (
    <section className="card">
      <h2>Sign-in rules for {org.name}</h2>
      <ErrorBox error={s.error} retry={s.reload} />
      {d && (
        <ul className="plain stack">
          <li className="row between">
            <span><strong>Require two-step verification</strong><div className="muted small">{d.members_with_mfa} of {d.members} members have it on. Members without it cannot open this organization until they turn it on.</div></span>
            {owner ? <button className={d.require_mfa ? "" : "primary"} onClick={() => setConfirm({ key: "require_mfa", value: !d.require_mfa })}>{d.require_mfa ? "Stop requiring" : "Require"}</button> : <Badge tone={d.require_mfa ? "ok" : undefined}>{d.require_mfa ? "Required" : "Optional"}</Badge>}
          </li>
          <li className="row between">
            <span><strong>Require single sign-on</strong><div className="muted small">{d.sso ? `Members must sign in through ${new URL(d.sso.issuer).host}. Owners can still use their password (and two-step verification) in case the provider fails.` : "Set up single sign-on below first."}</div></span>
            {owner ? <button disabled={!d.sso?.enabled} onClick={() => setConfirm({ key: "sso_enforced", value: !d.sso_enforced })}>{d.sso_enforced ? "Stop requiring" : "Require"}</button> : <Badge tone={d.sso_enforced ? "ok" : undefined}>{d.sso_enforced ? "Required" : "Optional"}</Badge>}
          </li>
        </ul>
      )}
      <ErrorBox error={err} />
      {confirm && (
        <Confirm
          title={confirm.value ? "Turn this rule on?" : "Turn this rule off?"}
          confirmLabel={confirm.value ? "Turn on" : "Turn off"}
          body={confirm.key === "require_mfa" ? (confirm.value ? "Everyone in this organization will need two-step verification to open it." : "Members will be able to open this organization with a password alone.") : confirm.value ? "Members will have to sign in through your identity provider." : "Members will be able to sign in with a password again."}
          onClose={() => setConfirm(null)}
          onConfirm={async () => {
            setErr(null);
            try { await api("PATCH", `/api/orgs/${org.id}/security`, { [confirm.key]: confirm.value }); toast("Saved"); s.reload(); } catch (x) { setErr(x as Error); }
          }}
        />
      )}
    </section>
  );
}

function DomainsCard() {
  const { org } = useApp();
  const toast = useToast();
  const list = useLoad<any>(`/api/orgs/${org.id}/domains`);
  const [domain, setDomain] = useState("");
  const [err, setErr] = useState<Error | null>(null);
  return (
    <section className="card">
      <h2>Email domains</h2>
      <p className="muted small">Single sign-on can only sign in addresses at domains you have proved you own. Add a DNS TXT record, then select Verify.</p>
      <ErrorBox error={list.error} retry={list.reload} />
      {list.data?.items.map((d: any) => (
        <div key={d.domain} className="row between" style={{ padding: ".5rem 0", borderTop: "1px solid var(--line, #e5e7eb)" }}>
          <span>
            <strong>{d.domain}</strong> {d.verified_at ? <Badge tone="ok">Verified</Badge> : <Badge tone="warn">Not verified</Badge>}
            {!d.verified_at && <div className="small">TXT record name <code>{d.dns.name}</code>, value <code style={{ wordBreak: "break-all" }}>{d.dns.value}</code></div>}
          </span>
          <span className="row">
            {!d.verified_at && <button className="primary" onClick={async () => { setErr(null); try { await api("POST", `/api/orgs/${org.id}/domains/${d.domain}/verify`); toast(`${d.domain} verified`); list.reload(); } catch (x) { setErr(x as Error); } }}>Verify</button>}
            <button onClick={async () => { setErr(null); try { await api("DELETE", `/api/orgs/${org.id}/domains/${d.domain}`); list.reload(); } catch (x) { setErr(x as Error); } }}>Remove</button>
          </span>
        </div>
      ))}
      <form className="row" style={{ alignItems: "end", marginTop: ".75rem" }} onSubmit={async (e) => {
        e.preventDefault(); setErr(null);
        try { await api("POST", `/api/orgs/${org.id}/domains`, { domain }); setDomain(""); list.reload(); } catch (x) { setErr(x as Error); }
      }}>
        <Field label="Add a domain"><input required placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value.trim().toLowerCase())} /></Field>
        <button>Add</button>
      </form>
      <ErrorBox error={err} />
    </section>
  );
}

function SsoCard() {
  const { org } = useApp();
  const toast = useToast();
  const s = useLoad<any>(`/api/orgs/${org.id}/security`);
  const domains = useLoad<any>(`/api/orgs/${org.id}/domains`);
  const [f, setF] = useState<any>(null);
  const [err, setErr] = useState<Error | null>(null);
  const [remove, setRemove] = useState(false);
  const cur = s.data?.sso;
  const form = f ?? { issuer: cur?.issuer ?? "", client_id: cur?.client_id ?? "", client_secret: "", allowed_domains: cur?.allowed_domains ?? [], default_role: cur?.default_role ?? "viewer", enabled: cur?.enabled ?? true };
  const verified: string[] = (domains.data?.items ?? []).filter((d: any) => d.verified_at).map((d: any) => d.domain);
  const fe = fieldErrors(err);
  const redirect = `${location.origin}/api/auth/sso/callback`;
  return (
    <section className="card">
      <div className="row between"><h2>Single sign-on (OpenID Connect)</h2>{cur && <Badge tone={cur.enabled ? "ok" : undefined}>{cur.enabled ? "On" : "Off"}</Badge>}</div>
      <p className="muted small">Works with Okta, Microsoft Entra ID, Google Workspace, Auth0, Keycloak and any OpenID Connect provider. In your provider, create a web application with this sign-in redirect address: <code>{redirect}</code></p>
      <form className="form" onSubmit={async (e) => {
        e.preventDefault(); setErr(null);
        try {
          await api("PUT", `/api/orgs/${org.id}/sso`, { ...form, client_secret: form.client_secret || undefined });
          toast("Single sign-on saved"); setF(null); s.reload();
        } catch (x) { setErr(x as Error); }
      }}>
        <Field label="Issuer URL" hint="For example https://yourcompany.okta.com or https://login.microsoftonline.com/<tenant id>/v2.0" error={fe.issuer}><input required type="url" value={form.issuer} onChange={(e) => setF({ ...form, issuer: e.target.value })} /></Field>
        <div className="grid cols-2">
          <Field label="Client ID" error={fe.client_id}><input required value={form.client_id} onChange={(e) => setF({ ...form, client_id: e.target.value })} /></Field>
          <Field label="Client secret" hint={cur ? "Leave empty to keep the saved secret." : "Stored encrypted."} error={fe.client_secret}><input type="password" autoComplete="off" required={!cur} value={form.client_secret} onChange={(e) => setF({ ...form, client_secret: e.target.value })} /></Field>
        </div>
        <fieldset>
          <legend>Email domains that sign in here</legend>
          {verified.length === 0 && <p className="small muted">Verify a domain above first.</p>}
          {verified.map((d) => (
            <label key={d} className="row" style={{ gap: ".4rem" }}>
              <input type="checkbox" checked={form.allowed_domains.includes(d)} onChange={(e) => setF({ ...form, allowed_domains: e.target.checked ? [...form.allowed_domains, d] : form.allowed_domains.filter((x: string) => x !== d) })} />{d}
            </label>
          ))}
        </fieldset>
        <div className="grid cols-2">
          <Field label="Role for people who sign in for the first time"><select value={form.default_role} onChange={(e) => setF({ ...form, default_role: e.target.value })}>{(["viewer", "auditor", "approver", "admin"] as const).map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}</select></Field>
          <Field label="Status"><select value={form.enabled ? "on" : "off"} onChange={(e) => setF({ ...form, enabled: e.target.value === "on" })}><option value="on">On</option><option value="off">Off</option></select></Field>
        </div>
        {err && !Object.keys(fe).length && <ErrorBox error={err} />}
        <div className="row"><button className="primary">Save single sign-on</button>{cur && <button type="button" className="danger" onClick={() => setRemove(true)}>Remove</button>}</div>
      </form>
      {cur && <p className="small muted">People sign in from the sign-in page with “Sign in with your organization”, or with this link: <code>{`${location.origin}/api/auth/sso/start?provider=oidc&org=${org.id}`}</code></p>}
      {remove && <Confirm title="Remove single sign-on?" confirmLabel="Remove" body="Members who only sign in through it will not be able to sign in until you set it up again." onClose={() => setRemove(false)} onConfirm={async () => { await api("DELETE", `/api/orgs/${org.id}/sso`); toast("Single sign-on removed"); setF(null); s.reload(); }} />}
    </section>
  );
}
