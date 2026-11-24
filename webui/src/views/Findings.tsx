import { useState, type FormEvent } from "react";
import { api } from "../api";
import { formatDate, t } from "../i18n";
import type { Finding, HistoryEvent, ReviewStatus } from "../types";
import { ErrorNote, REVIEW, ReviewBadge, SeverityBadge, evidenceLabel, reviewLabel } from "../ui";

export function FindingList({ findings, onChange, compact = false }: { findings: Finding[]; onChange?: (f: Finding) => void; compact?: boolean }) {
  return (
    <ul className="findings">
      {findings.map((finding) => (
        <FindingItem key={finding.id} finding={finding} onChange={onChange} compact={compact} />
      ))}
    </ul>
  );
}

function FindingItem({ finding, onChange, compact }: { finding: Finding; onChange?: (f: Finding) => void; compact: boolean }) {
  const [open, setOpen] = useState(false);
  const [history, setHistory] = useState<HistoryEvent[] | null>(null);
  const [status, setStatus] = useState<ReviewStatus>(finding.review_status);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const id = `finding-${finding.id}`;

  async function toggle() {
    const next = !open;
    setOpen(next);
    if (next && history === null && !compact) {
      try {
        setHistory(await api<HistoryEvent[]>(`/findings/${finding.id}/history`));
      } catch {
        setHistory([]);
      }
    }
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      const updated = await api<Finding>(`/findings/${finding.id}`, "PATCH", { status, note });
      setNote("");
      setHistory(await api<HistoryEvent[]>(`/findings/${finding.id}/history`));
      onChange?.(updated);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const needsNote = status === "accepted_risk" || status === "false_positive";

  return (
    <li className={`finding ${finding.review_status !== "open" ? "settled" : ""}`}>
      <button className="finding-head" aria-expanded={open} aria-controls={id} onClick={toggle}>
        <SeverityBadge severity={finding.severity} />
        <span className="finding-title">{finding.title}</span>
        <span className="finding-meta">
          <span className="muted small">{finding.target.replace(/^https?:\/\//, "")}</span>
          <ReviewBadge status={finding.review_status} />
        </span>
      </button>
      {open ? (
        <div className="finding-body" id={id}>
          <dl className="facts-grid">
            <div><dt>{t("Evidence status")}</dt><dd>{evidenceLabel(finding.evidence_status)}</dd></div>
            <div><dt>{t("Confidence")}</dt><dd>{finding.confidence}</dd></div>
            <div><dt>{t("Category")}</dt><dd>{finding.category}</dd></div>
            <div><dt>{t("Priority")}</dt><dd className="num">{finding.priority}</dd></div>
            <div><dt>{t("Path")}</dt><dd>{finding.path || "—"}</dd></div>
            <div><dt>{t("Tool")}</dt><dd>{finding.tool}</dd></div>
            <div><dt>{t("ID")}</dt><dd>{finding.ext_id || finding.key}</dd></div>
          </dl>
          {finding.evidence ? (
            <>
              <h4>{t("Evidence")}</h4>
              <pre className="evidence">{finding.evidence}</pre>
            </>
          ) : null}
          {finding.impact ? (<><h4>{t("Impact")}</h4><p>{finding.impact}</p></>) : null}
          {finding.verification ? (<><h4>{t("Safe verification")}</h4><p>{finding.verification}</p></>) : null}
          {finding.recommendation ? (<><h4>{t("Remediation")}</h4><p>{finding.recommendation}</p></>) : null}
          {finding.references?.length ? (<><h4>{t("References")}</h4><p>{finding.references.join(", ")}</p></>) : null}
          {!compact ? (
            <>
              <form className="review-form" onSubmit={save}>
                <label>
                  <span>{t("Review status")}</span>
                  <select value={status} onChange={(e) => setStatus(e.target.value as ReviewStatus)}>
                    {REVIEW.map((s) => (
                      <option key={s} value={s}>{reviewLabel(s)}</option>
                    ))}
                  </select>
                </label>
                <label className="grow">
                  <span>{needsNote ? t("Reason (required)") : t("Note (optional)")}</span>
                  <input value={note} onChange={(e) => setNote(e.target.value)} required={needsNote} maxLength={2000} />
                </label>
                <button className="primary">{t("Save review")}</button>
              </form>
              <ErrorNote error={error} />
              {history?.length ? (
                <>
                  <h4>{t("History")}</h4>
                  <ol className="timeline">
                    {history.map((h) => (
                      <li key={h.id}>
                        <span className="muted small">{formatDate(h.created_at)}</span>{" "}
                        {h.old_status ? `${reviewLabel(h.old_status)} → ` : ""}
                        <strong>{reviewLabel(h.new_status)}</strong>
                        {h.note ? <span> — {h.note}</span> : null}
                        <span className="muted small"> ({h.author})</span>
                      </li>
                    ))}
                  </ol>
                </>
              ) : null}
            </>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}
