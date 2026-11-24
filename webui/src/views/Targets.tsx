import { useState, type FormEvent } from "react";
import { api } from "../api";
import type { Ctx } from "../App";
import { formatDate, t } from "../i18n";
import type { Target } from "../types";
import { Empty, ErrorNote, PageHeader, useLoad } from "../ui";
import { NeedProject } from "./common";

export function TargetsView({ ctx }: { ctx: Ctx }) {
  const pid = ctx.project?.id;
  const { data, error, reload } = useLoad(() => (pid ? api<Target[]>(`/projects/${pid}/targets`) : Promise.resolve([])), [pid]);
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  if (!ctx.project) return <NeedProject ctx={ctx} title={t("Domains & targets")} />;

  async function add(event: FormEvent) {
    event.preventDefault();
    setFormError(null);
    try {
      const target = await api<Target>(`/projects/${pid}/targets`, "POST", { value, note });
      setValue("");
      setNote("");
      reload();
      ctx.reloadProjects();
      ctx.notify(t("{target} added to the scope", { target: target.value }));
    } catch (err) {
      setFormError((err as Error).message);
    }
  }

  async function remove(target: Target) {
    if (!window.confirm(t("Remove {target} from the scope? Its audits are kept.", { target: target.value }))) return;
    try {
      await api(`/targets/${target.id}`, "DELETE");
      reload();
      ctx.reloadProjects();
    } catch (err) {
      setFormError((err as Error).message);
    }
  }

  return (
    <>
      <PageHeader
        title={t("Domains & targets")}
        intro={t("Only targets listed here can be audited from the Security Center. Add only systems you are authorized to review.")}
      />
      <form className="panel form-row" onSubmit={add}>
        <label className="grow">
          <span>{t("Domain, IP or full URL")}</span>
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="example.com · https://app.example.com/login"
            required
            maxLength={2048}
            spellCheck={false}
            autoCapitalize="off"
          />
        </label>
        <label className="grow">
          <span>{t("Authorization note (optional)")}</span>
          <input value={note} onChange={(e) => setNote(e.target.value)} placeholder={t("Owner, ticket or contract")} maxLength={2000} />
        </label>
        <button className="primary" disabled={!value.trim()}>
          {t("Add to scope")}
        </button>
      </form>
      <ErrorNote error={formError || error} />
      {data && data.length === 0 ? (
        <Empty title={t("The scope is empty")}>
          <p>{t("Add a domain or URL above to start.")}</p>
        </Empty>
      ) : null}
      {data && data.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t("Target")}</th>
                <th scope="col">{t("Type")}</th>
                <th scope="col">{t("Note")}</th>
                <th scope="col" className="num">{t("Audits")}</th>
                <th scope="col">{t("Last audit")}</th>
                <th scope="col"><span className="sr-only">{t("Actions")}</span></th>
              </tr>
            </thead>
            <tbody>
              {data.map((target) => (
                <tr key={target.id}>
                  <td className="mono-ish strong">{target.value}</td>
                  <td>{{ domain: t("Domain"), ip: t("IP address"), url: t("URL") }[target.kind]}</td>
                  <td className="muted">{target.note || "—"}</td>
                  <td className="num">{target.audit_count ?? 0}</td>
                  <td>{formatDate(target.last_audit)}</td>
                  <td className="actions">
                    <button onClick={() => ctx.go("audits", `target=${target.id}`)}>{t("Audit")}</button>
                    <button onClick={() => ctx.go("history", `target=${encodeURIComponent(target.id)}`)}>{t("History")}</button>
                    <button className="danger" onClick={() => remove(target)}>{t("Remove")}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </>
  );
}
