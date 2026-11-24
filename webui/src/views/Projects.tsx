import { useState, type FormEvent } from "react";
import { api } from "../api";
import type { Ctx } from "../App";
import { formatDate, t } from "../i18n";
import type { Project } from "../types";
import { Empty, ErrorNote, PageHeader } from "../ui";

export function ProjectsView({ ctx }: { ctx: Ctx }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function create(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const project = await api<Project>("/projects", "POST", { name, description });
      await ctx.reloadProjects();
      ctx.selectProject(project.id);
      setName("");
      setDescription("");
      ctx.notify(t("Project {name} created", { name: project.name }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(project: Project) {
    if (!window.confirm(t("Delete {name} with all its targets, audits and findings? This cannot be undone.", { name: project.name }))) return;
    try {
      await api(`/projects/${project.id}`, "DELETE");
      await ctx.reloadProjects();
      ctx.notify(t("Project {name} deleted", { name: project.name }));
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <>
      <PageHeader title={t("Projects")} intro={t("A project groups the targets you are authorized to audit and their results.")} />
      <form className="panel form-row" onSubmit={create}>
        <label>
          <span>{t("Name")}</span>
          <input value={name} onChange={(e) => setName(e.target.value)} required maxLength={120} />
        </label>
        <label className="grow">
          <span>{t("Description (optional)")}</span>
          <input value={description} onChange={(e) => setDescription(e.target.value)} maxLength={2000} />
        </label>
        <button className="primary" disabled={busy || !name.trim()}>
          {t("Create project")}
        </button>
      </form>
      <ErrorNote error={error} />
      {ctx.projects.length === 0 ? (
        <Empty title={t("No projects yet")} />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t("Project")}</th>
                <th scope="col" className="num">{t("Targets")}</th>
                <th scope="col" className="num">{t("Audits")}</th>
                <th scope="col">{t("Last audit")}</th>
                <th scope="col"><span className="sr-only">{t("Actions")}</span></th>
              </tr>
            </thead>
            <tbody>
              {ctx.projects.map((p) => (
                <tr key={p.id} className={p.id === ctx.project?.id ? "selected" : undefined}>
                  <td>
                    <button className="link strong" onClick={() => { ctx.selectProject(p.id); ctx.go("overview"); }}>
                      {p.name}
                    </button>
                    {p.description ? <div className="muted small">{p.description}</div> : null}
                  </td>
                  <td className="num">{p.target_count ?? 0}</td>
                  <td className="num">{p.audit_count ?? 0}</td>
                  <td>{formatDate(p.last_audit)}</td>
                  <td className="actions">
                    <button onClick={() => { ctx.selectProject(p.id); ctx.go("targets"); }}>{t("Scope")}</button>
                    <button className="danger" onClick={() => remove(p)}>{t("Delete")}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
