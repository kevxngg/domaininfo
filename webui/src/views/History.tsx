import { useState } from "react";
import { api } from "../api";
import type { Ctx } from "../App";
import { formatDate, t } from "../i18n";
import type { Audit, HistoryEvent, Target } from "../types";
import { ErrorNote, PageHeader, SEVERITIES, Sparkline, gradeTone, reviewLabel, useLoad } from "../ui";
import { NeedProject } from "./common";

export function HistoryView({ ctx }: { ctx: Ctx }) {
  const pid = ctx.project?.id;
  const [targetId, setTargetId] = useState(ctx.query.get("target") ?? "");
  const targets = useLoad(() => (pid ? api<Target[]>(`/projects/${pid}/targets`) : Promise.resolve([])), [pid]);
  const audits = useLoad(() => (pid ? api<Audit[]>(`/projects/${pid}/audits`) : Promise.resolve([])), [pid]);
  const events = useLoad(() => (pid ? api<HistoryEvent[]>(`/projects/${pid}/history`) : Promise.resolve([])), [pid]);

  if (!ctx.project) return <NeedProject ctx={ctx} title={t("Audit history")} />;

  const rows = (audits.data ?? []).filter((a) => !targetId || String(a.target_id) === targetId);
  const trend = [...rows].reverse().map((a) => ({ id: a.id, date: a.created_at, score: a.score, security: a.security }));

  return (
    <>
      <PageHeader title={t("Audit history")} intro={t("Every stored audit, newest first, and every change of review status.")}>
        <label className="field-inline">
          <span>{t("Target")}</span>
          <select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
            <option value="">{t("All targets")}</option>
            {targets.data?.map((target) => (
              <option key={target.id} value={target.id}>{target.value}</option>
            ))}
          </select>
        </label>
      </PageHeader>
      <ErrorNote error={audits.error || events.error} />
      {targetId && trend.length > 1 ? (
        <section className="panel trend-panel">
          <h2>{t("Security trend")}</h2>
          <Sparkline points={trend} label={t("Security trend")} />
        </section>
      ) : null}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">{t("Date")}</th>
              <th scope="col">{t("Target")}</th>
              <th scope="col">{t("Mode")}</th>
              <th scope="col">{t("Grade")}</th>
              <th scope="col" className="num">{t("Security")}</th>
              <th scope="col" className="num">{t("Coverage")}</th>
              <th scope="col" className="num">{t("Confidence")}</th>
              <th scope="col">{t("Open findings")}</th>
              <th scope="col"><span className="sr-only">{t("Actions")}</span></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a, index) => {
              const previous = rows.slice(index + 1).find((b) => b.target === a.target);
              return (
                <tr key={a.id}>
                  <td>{formatDate(a.created_at)}</td>
                  <td className="strong">{a.target}</td>
                  <td>{a.mode}</td>
                  <td><span className={`grade-chip tone-${gradeTone(a.grade)}`}>{a.grade ?? "—"}</span></td>
                  <td className="num">{a.security ?? "—"}</td>
                  <td className="num">{a.coverage ?? "—"}</td>
                  <td className="num">{a.confidence ?? "—"}</td>
                  <td>
                    <span className="mini-counts">
                      {SEVERITIES.map((s) => (
                        <span key={s} className={`mini c-${s}`} title={s}>{a.counts?.[s] ?? 0}</span>
                      ))}
                    </span>
                  </td>
                  <td className="actions">
                    {previous ? (
                      <button onClick={() => ctx.go("compare", `base=${previous.id}&head=${a.id}`)}>{t("Compare")}</button>
                    ) : null}
                  </td>
                </tr>
              );
            })}
            {!rows.length ? (
              <tr><td colSpan={9} className="muted">{t("No audits stored yet.")}</td></tr>
            ) : null}
          </tbody>
        </table>
      </div>

      <section aria-labelledby="changes-heading">
        <h2 id="changes-heading" className="section-title">{t("Review changes")}</h2>
        {events.data?.length ? (
          <ol className="timeline wide">
            {events.data.slice(0, 200).map((h) => (
              <li key={h.id}>
                <span className="muted small">{formatDate(h.created_at)}</span>{" "}
                <span className="strong">{h.title ?? h.key}</span>{" "}
                <span className="muted">({h.target ?? ""})</span>{" "}
                {h.old_status ? `${reviewLabel(h.old_status)} → ` : ""}
                <strong>{reviewLabel(h.new_status)}</strong>
                {h.note ? <span> — {h.note}</span> : null}
              </li>
            ))}
          </ol>
        ) : (
          <p className="muted">{t("No changes recorded.")}</p>
        )}
      </section>
    </>
  );
}
