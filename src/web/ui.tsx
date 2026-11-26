import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError } from "./api";
import { Icon } from "./icons";

// ---------- app context ----------
export type Role = "owner" | "admin" | "approver" | "auditor" | "viewer";
export interface OrgInfo { id: string; name: string; timezone: string; role: Role }
export interface AppState {
  user: { id: string; email: string; name: string };
  orgs: OrgInfo[];
  org: OrgInfo;
  setOrgId: (id: string) => void;
  refresh: () => void;
}
export const AppContext = createContext<AppState | null>(null);
export const useApp = () => {
  const c = useContext(AppContext);
  if (!c) throw new Error("outside app");
  return c;
};
// Mirrors src/server/services/core.ts: approver and auditor read like a viewer and get one extra permission each.
const RANK: Record<Role, number> = { viewer: 1, auditor: 1, approver: 1, admin: 2, owner: 3 };
export const useCan = (min: Role) => RANK[useApp().org.role] >= RANK[min];
const PERMS = {
  "approvals.decide": ["owner", "admin", "approver"],
  "alerts.manage": ["owner", "admin", "approver"],
  "audit.read": ["owner", "admin", "auditor"],
} as const;
export const allowed = (role: Role, perm: keyof typeof PERMS) => (PERMS[perm] as readonly Role[]).includes(role);
export const useAllowed = (perm: keyof typeof PERMS) => allowed(useApp().org.role, perm);
export const ROLE_LABEL: Record<Role, string> = { owner: "Owner", admin: "Administrator", approver: "Approver", auditor: "Auditor", viewer: "Viewer" };

// ---------- toasts ----------
const ToastContext = createContext<(msg: string) => void>(() => undefined);
export const useToast = () => useContext(ToastContext);
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Array<{ id: number; msg: string }>>([]);
  const push = useCallback((msg: string) => {
    const id = Date.now() + Math.random();
    setItems((x) => [...x, { id, msg }]);
    setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), 4500);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toast-area" role="status" aria-live="polite">
        {items.map((i) => (
          <div key={i.id} className="toast">{i.msg}</div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

// ---------- time ----------
export function formatTime(value: string | Date | null | undefined, tz: string) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  try {
    return new Intl.DateTimeFormat("en-GB", { timeZone: tz, dateStyle: "medium", timeStyle: "short" }).format(d);
  } catch {
    return d.toISOString();
  }
}
export function relative(value: string | Date | null | undefined) {
  if (!value) return "never";
  const s = Math.round((Date.now() - new Date(value).getTime()) / 1000);
  if (s < 0) return `in ${rel(-s)}`;
  if (s < 10) return "just now";
  return `${rel(s)} ago`;
}
const rel = (s: number) => (s < 60 ? `${s}s` : s < 3600 ? `${Math.round(s / 60)}m` : s < 86400 ? `${Math.round(s / 3600)}h` : `${Math.round(s / 86400)}d`);

export function Time({ value, relativeToo }: { value: string | Date | null | undefined; relativeToo?: boolean }) {
  const { org } = useApp();
  if (!value) return <span className="muted">never</span>;
  return (
    <time dateTime={new Date(value).toISOString()} title={`${new Date(value).toISOString()} (UTC)`}>
      {formatTime(value, org.timezone)}
      {relativeToo && <span className="muted small"> · {relative(value)}</span>}
    </time>
  );
}

// ---------- states ----------
export function Spinner({ label = "Loading" }: { label?: string }) {
  return <span className="row muted" role="status"><span className="spinner" aria-hidden /> {label}…</span>;
}
export function Loading({ kind = "list" }: { kind?: "list" | "dashboard" }) {
  return kind === "dashboard" ? (
    <div className="stack" role="status" aria-label="Loading">
      <div className="grid cols-4">{[0, 1, 2, 3].map((i) => <div key={i} className="skeleton" style={{ height: 96 }} />)}</div>
      <div className="skeleton" style={{ height: 200 }} />
    </div>
  ) : (
    <div className="card" role="status" aria-label="Loading" style={{ display: "grid", gap: ".8rem" }}>
      {[0, 1, 2, 3, 4].map((i) => <div key={i} className="skeleton" style={{ height: 38, opacity: 1 - i * 0.14 }} />)}
    </div>
  );
}
export function ErrorBox({ error, retry }: { error: ApiError | Error | null; retry?: () => void }) {
  if (!error) return null;
  return (
    <div className="alert bad" role="alert">
      <strong>That didn’t work.</strong> {error.message}{" "}
      {retry && <button className="link" onClick={retry}>Try again</button>}
    </div>
  );
}
export function Empty({ title, children, icon }: { title: string; children?: ReactNode; icon?: string }) {
  return <div className="empty"><div className="art"><Icon name={icon ?? "inbox"} size={26} /></div><strong>{title}</strong>{children}</div>;
}
export function Badge({ tone, children, title }: { tone?: "ok" | "bad" | "warn" | "info" | "demo"; children: ReactNode; title?: string }) {
  return <span className={`badge ${tone ?? ""}`} title={title}>{children}</span>;
}
export const DemoBadge = () => <Badge tone="demo" title="Self-labelled demonstration activity, not production traffic">Demonstration</Badge>;

export function ConnBadge({ c }: { c: { state: string; label: string; connected_recently: boolean } }) {
  const tone = c.state === "enforcing" ? "ok" : c.state === "connected" || c.state === "monitoring" || c.state === "reporting_only" ? "info" : c.state === "revoked" ? "bad" : undefined;
  const live = c.state !== "not_connected" && c.state !== "revoked";
  return (
    <span className="row" style={{ gap: ".4rem" }}>
      <Badge tone={tone}><span className="dot" aria-hidden />{c.label}</Badge>
      {live && <span className={`pulse ${c.connected_recently ? "on" : ""}`} title={c.connected_recently ? "Seen in the last 15 minutes" : "Not seen in the last 15 minutes"}>{c.connected_recently ? "online" : "idle"}</span>}
    </span>
  );
}
export function DecisionBadge({ d, policyDecision }: { d: string; policyDecision?: string }) {
  const label = d === "allow" ? "Allowed" : d === "deny" ? "Denied" : "Needs approval";
  const mon = policyDecision && policyDecision !== d ? ` (policy would ${policyDecision === "deny" ? "deny" : "require approval"}; monitor mode)` : "";
  return <Badge tone={d === "allow" ? (mon ? "warn" : "ok") : d === "deny" ? "bad" : "warn"} title={mon || undefined}>{label}{mon && " · monitor"}</Badge>;
}
export const STATE_LABEL: Record<string, [string, "ok" | "bad" | "warn" | "info" | undefined, string]> = {
  blocked_confirmed: ["Blocked", "ok", "The integrated executor confirmed it did not run this action."],
  executed: ["Executed", "info", "The executor reported the action ran successfully."],
  execution_failed: ["Execution failed", "bad", "The action was permitted but failed while running."],
  claimed: ["Running", "info", "Permission to execute was used; waiting for the outcome report."],
  claimed_no_outcome: ["Outcome missing", "warn", "Execution was permitted over 10 minutes ago but no outcome was reported."],
  denied_unconfirmed: ["Denied (not confirmed)", "warn", "A denial was issued, but the executor has not confirmed it prevented execution."],
  awaiting_approval: ["Waiting for approval", "warn", "A human must approve this exact action before it can run."],
  approved_unused: ["Approved, not run", "info", "Approved by a human; the executor has not used the one-time approval yet."],
  approval_rejected: ["Approval rejected", "bad", "A human rejected this action."],
  approval_expired: ["Approval expired", "warn", "The approval window ended without the action running."],
  authorized_not_executed: ["Authorized, no run reported", "warn", "Allowed by policy, but no execution has been reported."],
};
export function StateBadge({ s }: { s: string }) {
  const [label, tone, help] = STATE_LABEL[s] ?? [s, undefined, ""];
  return <Badge tone={tone} title={help}>{label}</Badge>;
}
export const SeverityBadge = ({ s }: { s: string }) => <Badge tone={s === "high" ? "bad" : s === "medium" ? "warn" : undefined}>{s[0].toUpperCase() + s.slice(1)}</Badge>;
export const OP_LABEL: Record<string, string> = { read: "Read", create: "Create", update: "Update", delete: "Delete", external_transfer: "External transfer", command_execution: "Command execution" };

// ---------- layout bits ----------
export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

export function Modal({ title, onClose, children, drawer }: { title: string; onClose: () => void; children: ReactNode; drawer?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const prev = useRef<Element | null>(null);
  useEffect(() => {
    prev.current = document.activeElement;
    const el = ref.current!;
    (el.querySelector<HTMLElement>("input, select, textarea, button.primary, button") ?? el).focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab") {
        const f = Array.from(el.querySelectorAll<HTMLElement>("a[href], button:not(:disabled), input, select, textarea, [tabindex]:not([tabindex='-1'])"));
        if (!f.length) return;
        const first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      (prev.current as HTMLElement | null)?.focus?.();
    };
  }, [onClose]);
  return (
    <div className={`modal-back ${drawer ? "drawer" : ""}`} onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} ref={ref} tabIndex={-1}>
        <div className="row between" style={{ marginBottom: ".75rem" }}>
          <h2 style={{ margin: 0 }}>{title}</h2>
          <button onClick={onClose} aria-label="Close">✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Pager({ total, limit, offset, onPage }: { total: number; limit: number; offset: number; onPage: (page: number) => void }) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  if (total <= limit) return <div className="muted small" style={{ marginTop: ".6rem" }}>{total} result{total === 1 ? "" : "s"}</div>;
  return (
    <nav className="pager" aria-label="Pagination">
      <span className="muted small">{offset + 1}–{Math.min(total, offset + limit)} of {total}</span>
      <span className="row">
        <button disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
        <span className="small">Page {page} of {pages}</span>
        <button disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
      </span>
    </nav>
  );
}

export function Field({ label, hint, error, children }: { label: string; hint?: string; error?: string; children: ReactNode }) {
  return (
    <label>
      {label}
      {children}
      {hint && <span className="hint">{hint}</span>}
      {error && <span className="err" role="alert">{error}</span>}
    </label>
  );
}

export function fieldErrors(e: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (e instanceof ApiError && e.details) for (const d of e.details) out[d.path || "_"] = d.message;
  return out;
}

export function Confirm({ title, body, confirmLabel, onConfirm, onClose }: { title: string; body: ReactNode; confirmLabel: string; onConfirm: () => Promise<void>; onClose: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<Error | null>(null);
  return (
    <Modal title={title} onClose={onClose}>
      <div className="stack">
        <div>{body}</div>
        <ErrorBox error={err} />
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button onClick={onClose}>Cancel</button>
          <button className="danger solid" disabled={busy} onClick={async () => { setBusy(true); try { await onConfirm(); onClose(); } catch (e) { setErr(e as Error); setBusy(false); } }}>{busy ? "Working…" : confirmLabel}</button>
        </div>
      </div>
    </Modal>
  );
}

export function SecretModal({ secret, onClose }: { secret: string; onClose: () => void }) {
  const toast = useToast();
  return (
    <Modal title="Copy your integration key now" onClose={onClose}>
      <div className="stack">
        <div className="alert warn">This is the only time the full key is shown. We store only a one-way hash, so it cannot be recovered. Treat it like a password.</div>
        <div className="secret" data-testid="secret">{secret}</div>
        <div className="row">
          <button className="primary" onClick={() => navigator.clipboard?.writeText(secret).then(() => toast("Key copied"), () => toast("Copy failed — select the text and copy it manually"))}>Copy key</button>
          <button onClick={onClose}>I’ve stored it safely</button>
        </div>
      </div>
    </Modal>
  );
}
