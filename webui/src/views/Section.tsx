import { useState } from "react";
import { api } from "../api";
import type { Ctx } from "../App";
import { formatDate, t } from "../i18n";
import type { Finding, SectionData, SectionId } from "../types";
import { Empty, ErrorNote, PageHeader, REVIEW, SEVERITIES, reviewLabel, sectionLabel, severityLabel, useLoad } from "../ui";
import { FindingList } from "./Findings";
import { NeedProject } from "./common";

const INTRO: Record<SectionId, string> = {
  web: "Security headers, CSP, redirects, CORS and error pages of the audited sites.",
  auth: "Session cookies, forms and CSRF protection observed without logging in.",
  infra: "Addresses, network owners and reachable TCP services.",
  tls: "Certificate validity, expiry and accepted TLS versions.",
  maildns: "SPF, DMARC, DKIM, MX, DNSSEC, CAA and subdomains.",
  vulns: "Every finding with its evidence, across all areas.",
};

export function SectionView({ ctx, section }: { ctx: Ctx; section: SectionId }) {
  const pid = ctx.project?.id;
  const { data, error, setData } = useLoad(
    () => (pid ? api<SectionData>(`/projects/${pid}/sections/${section}`) : Promise.resolve(null)),
    [pid, section],
  );
  const all = useLoad(
    () => (pid && section === "vulns" ? api<Finding[]>(`/projects/${pid}/findings`) : Promise.resolve(null)),
    [pid, section],
  );
  const [severity, setSeverity] = useState("");
  const [review, setReview] = useState("open");

  if (!ctx.project) return <NeedProject ctx={ctx} title={sectionLabel(section)} />;

  const source = section === "vulns" ? all.data ?? [] : data?.findings ?? [];
  const findings = source.filter((f) => (!severity || f.severity === severity) && (!review || f.review_status === review));

  function changed(updated: Finding) {
    const swap = (list: Finding[]) => list.map((f) => (f.id === updated.id ? updated : f));
    if (section === "vulns") all.setData((list) => (list ? swap(list) : list));
    else setData((current) => (current ? { ...current, findings: swap(current.findings) } : current));
  }

  return (
    <>
      <PageHeader title={sectionLabel(section)} intro={t(INTRO[section])} />
      <ErrorNote error={error || all.error} />
      {data?.facts.length ? (
        <div className="fact-cards">
          {data.facts.map((entry) =>
            entry.facts.length ? (
              <section className="panel" key={entry.audit_id} aria-label={entry.target}>
                <h2 className="fact-target">{entry.target}</h2>
                <p className="muted small">{t("{mode} audit · {date}", { mode: entry.mode, date: formatDate(entry.date) })}</p>
                <dl className="facts">
                  {entry.facts.map((fact, i) => (
                    <div key={i} className={`fact tone-${fact.tone}`}>
                      <dt>{fact.label}</dt>
                      <dd>{fact.value}</dd>
                    </div>
                  ))}
                </dl>
              </section>
            ) : null,
          )}
        </div>
      ) : null}

      <section aria-labelledby="findings-heading">
        <div className="list-head">
          <h2 id="findings-heading" className="section-title">
            {t("Findings ({count})", { count: findings.length })}
          </h2>
          <div className="filters">
            <label className="field-inline">
              <span>{t("Severity")}</span>
              <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="">{t("All")}</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>{severityLabel(s)}</option>
                ))}
              </select>
            </label>
            <label className="field-inline">
              <span>{t("Review")}</span>
              <select value={review} onChange={(e) => setReview(e.target.value)}>
                <option value="">{t("All")}</option>
                {REVIEW.map((s) => (
                  <option key={s} value={s}>{reviewLabel(s)}</option>
                ))}
              </select>
            </label>
          </div>
        </div>
        {data && !data.facts.length && !source.length ? (
          <Empty title={t("No audit has covered this area yet")}>
            <button onClick={() => ctx.go("audits")}>{t("Launch an audit")}</button>
          </Empty>
        ) : findings.length === 0 ? (
          <p className="muted">{t("No findings match these filters.")}</p>
        ) : (
          <FindingList findings={findings} onChange={changed} />
        )}
      </section>
    </>
  );
}
