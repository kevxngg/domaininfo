import { useEffect, useState } from "react";
import { api } from "../api";
import type { Ctx } from "../App";
import { formatDate, t } from "../i18n";
import type { Audit, Comparison } from "../types";
import { ErrorNote, PageHeader, useLoad } from "../ui";
import { FindingList } from "./Findings";
import { NeedProject } from "./common";

export function CompareView({ ctx }: { ctx: Ctx }) {
  const pid = ctx.project?.id;
  const audits = useLoad(() => (pid ? api<Audit[]>(`/projects/${pid}/audits`) : Promise.resolve([])), [pid]);
  const [base, setBase] = useState(ctx.query.get("base") ?? "");
  const [head, setHead] = useState(ctx.query.get("head") ?? "");
  const [result, setResult] = useState<Comparison | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const list = audits.data;
    if (!list?.length || (base && head)) return;
    // Newest audit that has an earlier audit of the same target (the list is newest first)
    const newest = list.find((a, i) => list.slice(i + 1).some((b) => b.target === a.target));
    const previous = newest && list.find((b) => b.target === newest.target && b.id < newest.id);
    if (newest && previous) {
      setHead(String(newest.id));
      setBase(String(previous.id));
    }
  }, [audits.data, base, head]);

  useEffect(() => {
    if (!base || !head) return;
    setError(null);
    api<Comparison>(`/compare?base=${Number(base)}&head=${Number(head)}`)
      .then(setResult)
      .catch((err: Error) => {
        setResult(null);
        setError(err.message);
      });
  }, [base, head]);

  if (!ctx.project) return <NeedProject ctx={ctx} title={t("Compare results")} />;

  const option = (a: Audit) => (
    <option key={a.id} value={a.id}>
      {`#${a.id} · ${a.target} · ${a.mode} · ${formatDate(a.created_at)}`}
    </option>
  );

  return (
    <>
      <PageHeader title={t("Compare results")} intro={t("What changed between two audits of the same target.")} />
      <div className="panel form-row">
        <label className="grow">
          <span>{t("Earlier audit")}</span>
          <select value={base} onChange={(e) => setBase(e.target.value)}>
            <option value="">{t("Choose an audit")}</option>
            {audits.data?.map(option)}
          </select>
        </label>
        <label className="grow">
          <span>{t("Later audit")}</span>
          <select value={head} onChange={(e) => setHead(e.target.value)}>
            <option value="">{t("Choose an audit")}</option>
            {audits.data?.map(option)}
          </select>
        </label>
      </div>
      <ErrorNote error={error || audits.error} />
      {result ? (
        <>
          <div className={`banner ${result.comparable ? "ok" : "warn"}`} role="note">
            {result.comparable
              ? t("Comparable: both audits ran the same checks with similar coverage.")
              : t("Not comparable: {reason}. New and fixed counts may reflect a different scope rather than a real change.", { reason: result.reason })}
            {result.security_delta !== null ? (
              <span className="delta">
                {t("Security change: {delta}", { delta: (result.security_delta > 0 ? "+" : "") + result.security_delta })}
              </span>
            ) : null}
          </div>
          <div className="compare-cols">
            {(
              [
                ["new", t("New"), result.new],
                ["fixed", t("Fixed"), result.fixed],
                ["unchanged", t("Unchanged"), result.unchanged],
              ] as const
            ).map(([key, label, list]) => (
              <section key={key} className={`compare-col col-${key}`} aria-label={label}>
                <h2>
                  {label} <span className="num">{list.length}</span>
                </h2>
                {list.length ? <FindingList findings={list} compact /> : <p className="muted small">{t("None")}</p>}
              </section>
            ))}
          </div>
        </>
      ) : null}
    </>
  );
}
