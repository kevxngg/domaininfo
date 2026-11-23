import { useState } from "react";
import { api } from "../api";
import { formatDate, t } from "../i18n";
import type { ToolInfo } from "../types";
import { ErrorNote, PageHeader, useLoad } from "../ui";

export function ToolsView() {
  const [refresh, setRefresh] = useState(0);
  const { data, error } = useLoad(
    () => api<{ checked_at: number; tools: Record<string, ToolInfo> }>("/tools" + (refresh ? "?refresh=true" : "")),
    [refresh],
  );
  const tools = Object.values(data?.tools ?? {});
  const available = tools.filter((tool) => tool.available).length;

  return (
    <>
      <PageHeader
        title={t("Tool configuration")}
        intro={t("Optional external tools DomainInfo can use. Missing tools are simply disabled; nothing is downloaded or installed for you.")}
      >
        <button onClick={() => setRefresh((n) => n + 1)}>{t("Check again")}</button>
      </PageHeader>
      <ErrorNote error={error} />
      {data ? (
        <p className="muted">
          {t("{available} of {total} tools available · checked {date}", { available, total: tools.length, date: formatDate(data.checked_at) })}
        </p>
      ) : (
        <p className="muted" aria-busy="true">{t("Checking installed tools…")}</p>
      )}
      {tools.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">{t("Tool")}</th>
                <th scope="col">{t("Category")}</th>
                <th scope="col">{t("Status")}</th>
                <th scope="col">{t("Version")}</th>
                <th scope="col">{t("How to install")}</th>
              </tr>
            </thead>
            <tbody>
              {tools.map((tool) => (
                <tr key={tool.name}>
                  <td className="strong">{tool.name}</td>
                  <td>{tool.category}</td>
                  <td>
                    <span className={`state ${tool.available ? (tool.compatible === false ? "warn" : "good") : "off"}`}>
                      {!tool.available ? t("Not installed") : tool.compatible === false ? t("Too old") : t("Available")}
                    </span>
                  </td>
                  <td className="num">
                    {tool.version ?? "—"} <span className="muted small">{t("min. {version}", { version: tool.minimum })}</span>
                  </td>
                  <td className="small break">{tool.install}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </>
  );
}
