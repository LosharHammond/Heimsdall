/** The Kenuxa app menu (nine dots), the same list Kenuxa Accounts and Bask show. */
import { useEffect, useRef, useState, type ReactElement } from "react";

interface KxApp { client_id: string; name: string; home_url: string; icon_url: string | null }

const MARKS: Record<string, ReactElement> = {
  bask: <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true"><path d="M8.8 3.4L23 9L8.8 14.6Z" fill="#f5a524" stroke="#f5a524" strokeWidth="1.6" strokeLinejoin="round" /><path d="M8.8 17.6L23 23.2L8.8 28.8Z" fill="#d9831a" stroke="#d9831a" strokeWidth="1.6" strokeLinejoin="round" /></svg>,
  heimdall: <img src="/heimdall.svg" alt="" />,
  sourcebook: <svg width="40" height="40" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="#1F2547" /><path d="M9 8h10a4 4 0 0 1 4 4v12H13a4 4 0 0 1-4-4z" fill="none" stroke="#E0B23D" strokeWidth="2.2" strokeLinejoin="round" /><path d="M13 13h6M13 17h6" stroke="#F3F4F8" strokeWidth="2" strokeLinecap="round" /></svg>,
};
const short = (a: KxApp) => (a.client_id === "accounts" ? "Account" : a.name.replace(/^Kenuxa\s+/i, ""));

export function AppsMenu() {
  const [open, setOpen] = useState(false);
  const [apps, setApps] = useState<KxApp[] | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (open && !apps) fetch("/api/kenuxa/apps").then((r) => r.json()).then(setApps, () => setApps([]));
  }, [open, apps]);
  useEffect(() => {
    if (!open) return;
    const down = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    const key = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", down); document.addEventListener("keydown", key);
    return () => { document.removeEventListener("mousedown", down); document.removeEventListener("keydown", key); };
  }, [open]);
  return (
    <div className="kx-apps" ref={ref}>
      <button type="button" className="kx-trigger" aria-label="Kenuxa apps" aria-haspopup="menu" aria-expanded={open} title="Kenuxa apps" onClick={() => setOpen(!open)}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">{[4, 12, 20].flatMap((y) => [4, 12, 20].map((x) => <circle key={`${x}${y}`} cx={x} cy={y} r="2.2" />))}</svg>
      </button>
      {open && (
        <div className="kx-menu" role="menu" aria-label="Kenuxa apps">
          <p>Kenuxa apps</p>
          {!apps ? <div className="kx-loading"><span className="spinner" /></div> : (
            <ul>
              {apps.map((a) => {
                const here = a.client_id === "heimdall";
                return (
                  <li key={a.client_id}>
                    <a role="menuitem" href={here ? "/" : a.home_url} target={here ? undefined : "_blank"} rel={here ? undefined : "noreferrer"} onClick={() => setOpen(false)}>
                      <span className={`kx-ic kx-${a.client_id}`}>{MARKS[a.client_id] ?? (a.icon_url ? <img src={a.icon_url} alt="" /> : short(a).slice(0, 1))}</span>
                      {short(a)}
                    </a>
                  </li>
                );
              })}
            </ul>
          )}
          <small>One Kenuxa Account works in every app.</small>
        </div>
      )}
    </div>
  );
}
