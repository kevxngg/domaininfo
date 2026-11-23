import { api } from "../api";
import type { Ctx } from "../App";
import { formatDate, t } from "../i18n";
import type { Overview, SectionId } from "../types";
import { Empty, ErrorNote, Gauge, PageHeader, REVIEW, SeverityStrip, Sparkline, gradeTone, reviewLabel, sectionLabel, useLoad } from "../ui";

const SECTIONS: SectionId[] = ["web", "auth", "infra", "tls", "maildns", "vulns"];

export function OverviewView({ ctx }: { ctx: Ctx }) {
  const pid = ctx.project?.id;
  const { data, error } = useLoad(() => api<Overview>("/overview" + (pid ? `?project_id=${pid}` : "")), [pid]);

  if (!ctx.projects.length) {
    return (
      <>
        <PageHeader title={t("Overview")} />
        <Empty title={t("Nothing audited yet")}>
          <p>{t("Create a project, add the domains you are authorized to review, then launch a passive audit.")}</p>
          <button className="primary" onClick={() => ctx.go("projects")}>
            {t("Create a project")}
          </button>
        </Empty>
      </>
    );
  }

  const maxSection = data ? Math.max(1, ...SECTIONS.map((s) => data.open_by_section[s] || 0)) : 1;
  const trend = new Map((data?.trend ?? []).map((row) => [row.audit_id, row]));

  return (
    <>
      <PageHeader
        title={t("Overview")}
        intro={ctx.project ? t("Latest audit of each target in {project}.", { project: ctx.project.name }) : undefined}
      >
        <button className="primary" onClick={() => ctx.go("audits")}>
          {t("Launch an audit")}
        </button>
      </PageHeader>
      <ErrorNote error={error} />
      {data ? (
        <>
          <section className="panel" aria-labelledby="open-heading">
            <h2 id="open-heading">{t("Open findings")}</h2>
            <SeverityStrip counts={data.open_by_severity} />
            <p className="muted small">
              {REVIEW.filter((s) => s !== "open")
                .map((s) => `${reviewLabel(s)}: ${data.by_review_status[s] || 0}`)
                .join("   ")}
            </p>
          </section>

          <section aria-labelledby="targets-heading">
            <h2 id="targets-heading" className="section-title">
              {t("Targets")}
            </h2>
            {data.latest.length === 0 ? (
              <Empty title={t("No audits in this project yet")}>
                <button onClick={() => ctx.go("audits")}>{t("Launch an audit")}</button>
              </Empty>
            ) : (
              <div className="readouts">
                {data.latest.map((audit) => {
                  const row = trend.get(audit.id);
                  return (
                    <article className="readout" key={audit.id}>
                      <div className={`grade tone-${gradeTone(audit.grade)}`} aria-label={t("Grade {grade}", { grade: audit.grade ?? "—" })}>
                        {audit.grade ?? "–"}
                      </div>
                      <div className="readout-body">
                        <h3 title={audit.target}>{audit.target}</h3>
                        <p className="muted small">
                          {t("{mode} audit · {date}", { mode: audit.mode, date: formatDate(audit.created_at) })}
                        </p>
                        <Gauge label={t("Security")} value={audit.security} hint={t("Risk of what was checked")} />
                        <Gauge label={t("Coverage")} value={audit.coverage} hint={t("Share of applicable checks that ran")} />
                        <Gauge label={t("Confidence")} value={audit.confidence} hint={t("Share of checks with direct evidence")} />
                        <div className="readout-foot">
                          <span className="trend">
                            {row ? <Sparkline points={row.history} label={t("Security trend")} /> : null}
                          </span>
                          {row?.previous_id ? (
                            <button className="link" onClick={() => ctx.go("compare", `base=${row.previous_id}&head=${audit.id}`)}>
                              {t("Compare with previous")}
                            </button>
                          ) : null}
                        </div>
                      </div>
                    </article>
                  );
                })}
              </div>
            )}
          </section>

          <section className="panel" aria-labelledby="areas-heading">
            <h2 id="areas-heading">{t("Open findings by area")}</h2>
            <ul className="bars">
              {SECTIONS.map((s) => (
                <li key={s}>
                  <a href={"#/" + s}>{sectionLabel(s)}</a>
                  <span className="bar" aria-hidden="true">
                    <span style={{ width: `${((data.open_by_section[s] || 0) / maxSection) * 100}%` }} />
                  </span>
                  <span className="num">{data.open_by_section[s] || 0}</span>
                </li>
              ))}
            </ul>
          </section>
        </>
      ) : null}
    </>
  );
}
