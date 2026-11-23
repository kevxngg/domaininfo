import { useEffect, useState, type ReactNode } from "react";
import { t } from "./i18n";
import type { Counts, ReviewStatus, SectionId, Severity, TrendPoint } from "./types";

export const SEVERITIES: Severity[] = ["high", "medium", "low", "info"];
export const REVIEW: ReviewStatus[] = ["open", "fixed", "accepted_risk", "false_positive"];

export function severityLabel(s: string) {
  return ({ high: t("High"), medium: t("Medium"), low: t("Low"), info: t("Info") } as Record<string, string>)[s] ?? s;
}

export function reviewLabel(s: string | null | undefined) {
  return (
    ({ open: t("Open"), fixed: t("Fixed"), accepted_risk: t("Accepted risk"), false_positive: t("False positive") } as Record<string, string>)[
      s ?? ""
    ] ?? (s || "—")
  );
}

export function evidenceLabel(s: string) {
  return (
    ({
      confirmed: t("Confirmed"),
      likely: t("Likely"),
      informational: t("Informational"),
      pending: t("Pending verification"),
      not_applicable: t("Not applicable"),
      not_evaluated: t("Not evaluated"),
      error: t("Check error"),
    } as Record<string, string>)[s] ?? s
  );
}

export function sectionLabel(s: SectionId) {
  return {
    web: t("Web security"),
    auth: t("Authentication & sessions"),
    infra: t("Infrastructure & ports"),
    tls: t("Certificates & TLS"),
    maildns: t("Mail & DNS"),
    vulns: t("Vulnerabilities & evidence"),
  }[s];
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`sev sev-${severity}`}>{severityLabel(severity)}</span>;
}

export function ReviewBadge({ status }: { status: string }) {
  return <span className={`review review-${status}`}>{reviewLabel(status)}</span>;
}

export function SeverityStrip({ counts }: { counts: Counts }) {
  const total = SEVERITIES.reduce((sum, s) => sum + (counts[s] || 0), 0);
  return (
    <div className="strip">
      <div className="strip-bar" role="img" aria-label={t("Open findings: {high} high, {medium} medium, {low} low, {info} info", counts)}>
        {total === 0 ? <span className="strip-empty" /> : null}
        {SEVERITIES.map((s) =>
          counts[s] ? <span key={s} className={`strip-seg bg-${s}`} style={{ flexGrow: counts[s] }} /> : null,
        )}
      </div>
      <dl className="strip-legend">
        {SEVERITIES.map((s) => (
          <div key={s}>
            <dt>
              <span className={`dot bg-${s}`} aria-hidden="true" />
              {severityLabel(s)}
            </dt>
            <dd>{counts[s] || 0}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

/** Instrument-style horizontal gauge with ticks every 10 points. */
export function Gauge({ label, value, hint }: { label: string; value: number | null | undefined; hint?: string }) {
  const v = typeof value === "number" ? Math.max(0, Math.min(100, value)) : null;
  const tone = v === null ? "none" : v >= 80 ? "good" : v >= 50 ? "warn" : "bad";
  return (
    <div className="gauge" title={hint}>
      <div className="gauge-head">
        <span>{label}</span>
        <span className="num">{v === null ? "—" : v}</span>
      </div>
      <div
        className={`gauge-track tone-${tone}`}
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={v ?? undefined}
      >
        <span className="gauge-fill" style={{ width: `${v ?? 0}%` }} />
      </div>
    </div>
  );
}

export function Sparkline({ points, label }: { points: TrendPoint[]; label: string }) {
  const values = points.map((p) => p.security ?? p.score).filter((v): v is number => typeof v === "number");
  if (values.length < 2) return <span className="muted small">{t("Not enough audits for a trend")}</span>;
  const w = 120;
  const h = 28;
  const step = w / (values.length - 1);
  const y = (v: number) => h - 2 - (v / 100) * (h - 4);
  const d = values.map((v, i) => `${i ? "L" : "M"}${(i * step).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const last = values[values.length - 1];
  const first = values[0];
  return (
    <svg className="spark" width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={t("{label}: from {first} to {last}", { label, first, last })}>
      <path d={d} fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
      <circle cx={w} cy={y(last)} r="2.6" fill="currentColor" />
    </svg>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {children}
    </div>
  );
}

export function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <p className="error" role="alert">
      {error}
    </p>
  );
}

export function PageHeader({ title, intro, children }: { title: string; intro?: string; children?: ReactNode }) {
  return (
    <header className="page-head">
      <div>
        <h1 tabIndex={-1}>{title}</h1>
        {intro ? <p className="intro">{intro}</p> : null}
      </div>
      {children ? <div className="page-actions">{children}</div> : null}
    </header>
  );
}

/** Small data loader: re-runs when `deps` change; exposes reload. */
export function useLoad<T>(loader: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    setError(null);
    loader()
      .then((value) => alive && setData(value))
      .catch((err: Error) => alive && setError(err.message));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { data, error, reload: () => setTick((n) => n + 1), setData };
}

export function gradeTone(grade: string | null | undefined) {
  if (!grade) return "none";
  return grade === "A" || grade === "B" ? "good" : grade === "C" ? "warn" : "bad";
}
