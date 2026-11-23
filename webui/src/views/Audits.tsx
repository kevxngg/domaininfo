import { useEffect, useRef, useState, type ChangeEvent, type FormEvent } from "react";
import { api } from "../api";
import type { Ctx } from "../App";
import { formatDate, t } from "../i18n";
import type { Audit, Job, Target } from "../types";
import { ErrorNote, PageHeader, useLoad } from "../ui";
import { NeedProject } from "./common";

function modeInfo(mode: string) {
  return (
    {
      quick: [t("Quick"), t("DNS records and domain registration.")],
      web: [t("Web"), t("HTTP response, security headers, technologies and the TLS certificate.")],
      mail: [t("Mail"), t("SPF, DMARC, DKIM, MX and MTA-STS.")],
      recon: [t("Reconnaissance"), t("Network owner, technologies, subdomains from certificate logs and history.")],
      webapp: [t("Web application"), t("Passive review of one URL: cookies, forms and CSRF, CSP, CORS, errors and exposed secrets. GET requests only.")],
      brand: [t("Brand"), t("Look-alike domains that could be used for phishing.")],
    } as Record<string, [string, string]>
  )[mode] ?? [mode, ""];
}

const ACTIVE = new Set(["queued", "running", "cancelling"]);

export function AuditsView({ ctx }: { ctx: Ctx }) {
  const pid = ctx.project?.id;
  const targets = useLoad(() => (pid ? api<Target[]>(`/projects/${pid}/targets`) : Promise.resolve([])), [pid]);
  const audits = useLoad(() => (pid ? api<Audit[]>(`/projects/${pid}/audits`) : Promise.resolve([])), [pid]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [mode, setMode] = useState("web");
  const [targetId, setTargetId] = useState<string>(ctx.query.get("target") ?? "");
  const [error, setError] = useState<string | null>(null);
  const known = useRef(new Set<number>());

  useEffect(() => {
    if (!targetId && targets.data?.length) setTargetId(String(targets.data[0].id));
  }, [targets.data, targetId]);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const list = await api<Job[]>("/jobs");
        if (!alive) return;
        setJobs(list);
        for (const job of list) {
          if (job.state === "done" && !known.current.has(job.id)) {
            known.current.add(job.id);
            audits.reload();
          } else if (!ACTIVE.has(job.state)) known.current.add(job.id);
        }
        timer = setTimeout(poll, list.some((j) => ACTIVE.has(j.state)) ? 1200 : 5000);
      } catch {
        timer = setTimeout(poll, 5000);
      }
    };
    poll();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!ctx.project) return <NeedProject ctx={ctx} title={t("Available audits")} />;

  async function launch(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      const job = await api<Job>(`/projects/${pid}/jobs`, "POST", { target_id: Number(targetId), mode });
      setJobs((list) => [job, ...list.filter((j) => j.id !== job.id)]);
      ctx.notify(t("Audit queued: {mode} on {target}", { mode: modeInfo(mode)[0], target: job.target }));
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function cancel(job: Job) {
    try {
      const updated = await api<Job>(`/jobs/${job.id}/cancel`, "POST");
      setJobs((list) => list.map((j) => (j.id === job.id ? updated : j)));
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function importReport(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setError(null);
    try {
      if (file.size > 10 * 1024 * 1024) throw new Error(t("The file is larger than 10 MB"));
      const report = JSON.parse(await file.text());
      const audit = await api<Audit>(`/projects/${pid}/import`, "POST", report);
      audits.reload();
      ctx.notify(t("Report for {target} imported", { target: audit.target }));
    } catch (err) {
      setError(err instanceof SyntaxError ? t("The file is not valid JSON") : (err as Error).message);
    }
  }

  const projectJobs = jobs.filter((j) => j.project_id === pid);

  return (
    <>
      <PageHeader
        title={t("Available audits")}
        intro={t("Passive audits only: they read public information and send ordinary requests, never forms, credentials or port scans.")}
      />
      <form className="panel" onSubmit={launch}>
        <fieldset className="modes">
          <legend>{t("Audit type")}</legend>
          {ctx.session.passive_modes.map((m) => {
            const [label, description] = modeInfo(m);
            return (
              <label key={m} className={`mode ${mode === m ? "chosen" : ""}`}>
                <input type="radio" name="mode" value={m} checked={mode === m} onChange={() => setMode(m)} />
                <span className="mode-name">{label}</span>
                <span className="mode-desc">{description}</span>
                <span className="mode-modules">{(ctx.session.modes[m] || []).join(" + ")}</span>
              </label>
            );
          })}
        </fieldset>
        <div className="form-row">
          <label className="grow">
            <span>{t("Target from the project scope")}</span>
            <select value={targetId} onChange={(e) => setTargetId(e.target.value)} required>
              {!targets.data?.length ? <option value="">{t("Add a target first")}</option> : null}
              {targets.data?.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.value}
                </option>
              ))}
            </select>
          </label>
          <button className="primary" disabled={!targetId}>
            {t("Launch audit")}
          </button>
          <label className="file-button">
            <input type="file" accept="application/json,.json" onChange={importReport} />
            <span>{t("Import a JSON report")}</span>
          </label>
        </div>
        <p className="muted small">
          {t("Port scans, MikroTik and full audits stay in the command line, where you confirm scope and authorization explicitly.")}
        </p>
      </form>
      <ErrorNote error={error || targets.error} />

      <section aria-labelledby="jobs-heading">
        <h2 id="jobs-heading" className="section-title">
          {t("Running and recent audits")}
        </h2>
        {projectJobs.length === 0 ? (
          <p className="muted">{t("No audits launched in this session.")}</p>
        ) : (
          <ul className="jobs">
            {projectJobs.map((job) => (
              <li key={job.id} className={`job job-${job.state}`}>
                <div>
                  <strong>{job.target}</strong>
                  <span className="muted"> · {modeInfo(job.mode)[0]}</span>
                </div>
                <div className="job-state">
                  {job.state === "running" ? (
                    <>
                      <progress max={job.total || 1} value={job.progress} aria-label={t("Progress")} />
                      <span className="small">{job.module ?? ""}</span>
                    </>
                  ) : (
                    <span>{jobLabel(job)}</span>
                  )}
                </div>
                <div className="actions">
                  {ACTIVE.has(job.state) && job.state !== "cancelling" ? (
                    <button onClick={() => cancel(job)}>{t("Cancel")}</button>
                  ) : null}
                  {job.audit_id ? <button onClick={() => ctx.go("overview")}>{t("View results")}</button> : null}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="recent-heading">
        <h2 id="recent-heading" className="section-title">
          {t("Latest stored audits")}
        </h2>
        {audits.data?.length ? (
          <ul className="plain-list">
            {audits.data.slice(0, 8).map((a) => (
              <li key={a.id}>
                <span className="strong">{a.target}</span> <span className="muted">· {a.mode} · {formatDate(a.created_at)}</span>
                {a.grade ? <span className="pill">{t("Grade {grade}", { grade: a.grade })}</span> : null}
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">{t("No audits stored yet.")}</p>
        )}
      </section>
    </>
  );
}

function jobLabel(job: Job) {
  switch (job.state) {
    case "queued":
      return t("Queued");
    case "cancelling":
      return t("Cancelling after the current module…");
    case "cancelled":
      return t("Cancelled");
    case "done":
      return t("Finished");
    case "error":
      return t("Failed: {error}", { error: job.error ?? "" });
    default:
      return job.state;
  }
}
