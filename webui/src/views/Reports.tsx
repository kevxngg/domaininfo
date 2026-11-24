import { useState } from "react";
import { api, download } from "../api";
import type { Ctx } from "../App";
import { formatDate, t } from "../i18n";
import type { Audit } from "../types";
import { ErrorNote, PageHeader, useLoad } from "../ui";
import { NeedProject } from "./common";

export function ReportsView({ ctx }: { ctx: Ctx }) {
  const pid = ctx.project?.id;
  const audits = useLoad(() => (pid ? api<Audit[]>(`/projects/${pid}/audits`) : Promise.resolve([])), [pid]);
  const [auditId, setAuditId] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState<string | null>(null);

  if (!ctx.project) return <NeedProject ctx={ctx} title={t("Reports & export")} />;

  async function get(kind: "csv" | "executive" | "technical") {
    setBusy(kind);
    setError(null);
    const query = auditId ? `?audit_id=${Number(auditId)}` : "";
    const path = kind === "csv" ? `/projects/${pid}/export/findings.csv${query}` : `/projects/${pid}/export/${kind}.pdf${query}`;
    const name = `domaininfo-${kind === "csv" ? "findings" : kind}-${ctx.project!.name.replace(/[^\w.-]+/g, "_")}${auditId ? "-audit" + auditId : ""}.${kind === "csv" ? "csv" : "pdf"}`;
    try {
      await download(path, name);
      ctx.notify(t("Downloaded {file}", { file: name }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy("");
    }
  }

  const exports = [
    { kind: "executive" as const, title: t("Executive report (PDF)"), text: t("Grades, Security, Coverage and Confidence, top risks, counts by severity and the trend against the previous audit.") },
    { kind: "technical" as const, title: t("Technical report (PDF)"), text: t("Every finding with evidence, impact, safe verification and remediation; prioritized plan, false positives and change history.") },
    { kind: "csv" as const, title: t("Findings (CSV)"), text: t("One row per finding for spreadsheets and ticketing tools.") },
  ];

  return (
    <>
      <PageHeader title={t("Reports & export")} intro={t("Exports are generated on this computer. Cookies, tokens and keys are removed before anything is written.")} />
      <div className="panel form-row">
        <label className="grow">
          <span>{t("Scope of the export")}</span>
          <select value={auditId} onChange={(e) => setAuditId(e.target.value)}>
            <option value="">{t("Latest audit of every target in {project}", { project: ctx.project.name })}</option>
            {audits.data?.map((a) => (
              <option key={a.id} value={a.id}>{`#${a.id} · ${a.target} · ${a.mode} · ${formatDate(a.created_at)}`}</option>
            ))}
          </select>
        </label>
      </div>
      <ErrorNote error={error || audits.error} />
      <div className="exports">
        {exports.map((item) => (
          <article className="export" key={item.kind}>
            <h2>{item.title}</h2>
            <p>{item.text}</p>
            <button className="primary" onClick={() => get(item.kind)} disabled={busy !== ""} aria-busy={busy === item.kind}>
              {busy === item.kind ? t("Preparing…") : t("Download")}
            </button>
          </article>
        ))}
      </div>
    </>
  );
}
