import { useMemo, useState } from "react";
import { useApp } from "./ui";

export interface Bucket { t: string; allowed: number; denied: number; approval: number }

/** Stacked column chart of recorded decisions. Pure SVG, accessible via a data table fallback and per-column titles. */
export function DecisionChart({ data, unit }: { data: Bucket[]; unit: "hour" | "day" }) {
  const { org } = useApp();
  const [hover, setHover] = useState<number | null>(null);
  const W = 720, H = 220, L = 34, B = 26, T = 10;
  const max = Math.max(4, ...data.map((d) => d.allowed + d.denied + d.approval));
  const nice = useMemo(() => { const m = Math.ceil(max / 4) * 4; return m; }, [max]);
  const bw = (W - L) / Math.max(1, data.length);
  const y = (v: number) => T + (H - T - B) * (1 - v / nice);
  const fmt = (iso: string, long = false) =>
    new Intl.DateTimeFormat("en-GB", unit === "hour" ? { timeZone: org.timezone, hour: "2-digit", minute: "2-digit", ...(long ? { day: "numeric", month: "short" } : {}) } : { timeZone: org.timezone, day: "numeric", month: "short" }).format(new Date(iso));
  const total = data.reduce((a, d) => a + d.allowed + d.denied + d.approval, 0);
  const every = Math.ceil(data.length / 8);
  const h = hover !== null ? data[hover] : null;
  return (
    <div>
      <div className="row between" style={{ marginBottom: ".5rem" }}>
        <div className="legend" aria-hidden="true">
          <span><i style={{ background: "var(--c-allow)" }} />Allowed</span><span><i style={{ background: "var(--c-appr)" }} />Needs approval</span><span><i style={{ background: "var(--c-deny)" }} />Denied</span>
        </div>
        <div className="small muted" aria-live="polite">
          {h ? <><strong style={{ color: "var(--text)" }}>{fmt(h.t, true)}</strong> · {h.allowed} allowed · {h.approval} approval · {h.denied} denied</> : `${total} decisions in this period`}
        </div>
      </div>
      <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Decisions per ${unit}: ${total} in total`}>
        {[0, 1, 2, 3, 4].map((i) => { const v = (nice / 4) * i; return (
          <g key={i}><line className="grid" x1={L} x2={W} y1={y(v)} y2={y(v)} /><text x={L - 6} y={y(v) + 4} textAnchor="end">{v}</text></g>
        ); })}
        {data.map((d, i) => {
          const x = L + i * bw + bw * 0.14, w = bw * 0.72;
          let base = H - B;
          const seg = (v: number, color: string) => { if (!v) return null; const hh = (H - T - B) * (v / nice); base -= hh; return <rect className="bar" x={x} y={base} width={w} height={hh} rx={Math.min(3, w / 3)} fill={color} />; };
          return (
            <g key={d.t} className="col" onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
              <rect x={L + i * bw} y={T} width={bw} height={H - T - B} fill="transparent"><title>{`${fmt(d.t, true)}: ${d.allowed} allowed, ${d.approval} needing approval, ${d.denied} denied`}</title></rect>
              {seg(d.allowed, "var(--c-allow)")}{seg(d.approval, "var(--c-appr)")}{seg(d.denied, "var(--c-deny)")}
              {i % every === 0 && <text x={x + w / 2} y={H - 8} textAnchor="middle">{fmt(d.t)}</text>}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export function ReasonBars({ items }: { items: Array<{ reason_code: string; n: number }> }) {
  const max = Math.max(1, ...items.map((i) => i.n));
  const label: Record<string, string> = {
    EXPLICIT_DENY: "Explicit deny rule", NO_MATCHING_RULE: "No rule allows it (default)", DESTINATION_NOT_APPROVED: "Destination not approved",
    INVALID_DESTINATION: "Invalid destination", INVALID_RESOURCE: "Invalid resource path", BUDGET_EXCEEDED: "Action budget used up", NO_POLICY_ASSIGNED: "No policy assigned",
  };
  return (
    <div className="hbar">
      {items.map((i) => (
        <div className="r" key={i.reason_code}>
          <span title={i.reason_code}>{label[i.reason_code] ?? i.reason_code}</span>
          <span className="track"><span className="fill" style={{ display: "block", width: `${(i.n / max) * 100}%` }} /></span>
          <strong>{i.n}</strong>
        </div>
      ))}
    </div>
  );
}
