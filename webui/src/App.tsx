import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { t } from "./i18n";
import type { Project, SectionId, Session } from "./types";
import { sectionLabel } from "./ui";
import { OverviewView } from "./views/Overview";
import { ProjectsView } from "./views/Projects";
import { TargetsView } from "./views/Targets";
import { AuditsView } from "./views/Audits";
import { SectionView } from "./views/Section";
import { HistoryView } from "./views/History";
import { CompareView } from "./views/Compare";
import { ToolsView } from "./views/Tools";
import { ReportsView } from "./views/Reports";

export type Route =
  | "overview"
  | "projects"
  | "targets"
  | "audits"
  | SectionId
  | "history"
  | "compare"
  | "tools"
  | "reports";

export interface Ctx {
  session: Session;
  projects: Project[];
  project: Project | null;
  reloadProjects: () => Promise<void>;
  selectProject: (id: number) => void;
  go: (route: Route, query?: string) => void;
  query: URLSearchParams;
  notify: (message: string) => void;
}

const SECTIONS: SectionId[] = ["web", "auth", "infra", "tls", "maildns", "vulns"];
const ROUTES: Route[] = ["overview", "projects", "targets", "audits", ...SECTIONS, "history", "compare", "tools", "reports"];

function parseHash(): { route: Route; query: URLSearchParams } {
  const raw = window.location.hash.replace(/^#\/?/, "");
  const [path, qs] = raw.split("?");
  const route = (ROUTES as string[]).includes(path) ? (path as Route) : "overview";
  return { route, query: new URLSearchParams(qs || "") };
}

function readPref(key: string) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writePref(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* preferences are optional */
  }
}

type Theme = "system" | "light" | "dark";

export function App({ session }: { session: Session }) {
  const [{ route, query }, setLocation] = useState(parseHash);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState<number | null>(() => Number(readPref("domaininfo-project")) || null);
  const [theme, setTheme] = useState<Theme>(() => (readPref("domaininfo-theme") as Theme) || "system");
  const [menuOpen, setMenuOpen] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const onHash = () => {
      if (/token=/.test(window.location.hash)) return; // handled in main.tsx (new access link)
      setLocation(parseHash());
      setMenuOpen(false);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    if (theme === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    writePref("domaininfo-theme", theme);
  }, [theme]);

  const reloadProjects = useCallback(async () => {
    const list = await api<Project[]>("/projects");
    setProjects(list);
    setProjectId((current) => (current && list.some((p) => p.id === current) ? current : list[0]?.id ?? null));
  }, []);

  useEffect(() => {
    reloadProjects().catch(() => undefined);
  }, [reloadProjects]);

  useEffect(() => {
    document.title = t("{section} · DomainInfo Security Center", { section: titleOf(route) });
    const heading = document.querySelector<HTMLElement>("main h1");
    heading?.focus();
  }, [route]);

  useEffect(() => {
    if (!message) return;
    const timer = setTimeout(() => setMessage(""), 5000);
    return () => clearTimeout(timer);
  }, [message]);

  const project = projects.find((p) => p.id === projectId) ?? null;
  const ctx: Ctx = {
    session,
    projects,
    project,
    reloadProjects,
    selectProject: (id) => {
      setProjectId(id);
      writePref("domaininfo-project", String(id));
    },
    go: (next, qs) => {
      window.location.hash = "#/" + next + (qs ? "?" + qs : "");
    },
    query,
    notify: setMessage,
  };

  const groups: { label: string; items: Route[] }[] = [
    { label: t("Workspace"), items: ["overview", "projects", "targets", "audits"] },
    { label: t("Findings"), items: SECTIONS },
    { label: t("Records"), items: ["history", "compare", "reports"] },
    { label: t("Setup"), items: ["tools"] },
  ];

  return (
    <div className="shell">
      <a className="skip" href="#main">
        {t("Skip to content")}
      </a>
      <aside className={`rail ${menuOpen ? "open" : ""}`}>
        <div className="brand">
          <svg viewBox="0 0 32 32" width="28" height="28" aria-hidden="true">
            <rect width="32" height="32" rx="7" className="brand-mark" />
            <path d="M9 7h7.5C22.4 7 26 10.6 26 16s-3.6 9-9.5 9H9z" fill="none" stroke="#fff" strokeWidth="3" />
            <circle cx="16.5" cy="16" r="3" fill="#fff" />
          </svg>
          <div>
            <strong>DomainInfo</strong>
            <span>{t("Security Center")}</span>
          </div>
          <button
            className="menu-toggle"
            aria-expanded={menuOpen}
            aria-controls="primary-nav"
            onClick={() => setMenuOpen((v) => !v)}
          >
            {menuOpen ? t("Close menu") : t("Menu")}
          </button>
        </div>
        <nav id="primary-nav" aria-label={t("Sections")}>
          {groups.map((group) => (
            <div className="nav-group" key={group.label}>
              <p className="nav-label">{group.label}</p>
              <ul>
                {group.items.map((item) => (
                  <li key={item}>
                    <a href={"#/" + item} aria-current={item === route ? "page" : undefined}>
                      {titleOf(item)}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
        <p className="rail-foot">
          {t("Local only · v{version}", { version: session.version })}
        </p>
      </aside>
      <div className="workspace">
        <div className="topbar">
          <label className="field-inline">
            <span>{t("Project")}</span>
            <select
              value={projectId ?? ""}
              onChange={(e) => ctx.selectProject(Number(e.target.value))}
              disabled={!projects.length}
            >
              {!projects.length ? <option value="">{t("No projects yet")}</option> : null}
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <label className="field-inline">
            <span>{t("Theme")}</span>
            <select value={theme} onChange={(e) => setTheme(e.target.value as Theme)}>
              <option value="system">{t("System")}</option>
              <option value="light">{t("Light")}</option>
              <option value="dark">{t("Dark")}</option>
            </select>
          </label>
        </div>
        <main id="main">
          <View route={route} ctx={ctx} />
        </main>
        <div className="toast" role="status" aria-live="polite">
          {message}
        </div>
      </div>
    </div>
  );
}

function titleOf(route: Route): string {
  switch (route) {
    case "overview":
      return t("Overview");
    case "projects":
      return t("Projects");
    case "targets":
      return t("Domains & targets");
    case "audits":
      return t("Available audits");
    case "history":
      return t("Audit history");
    case "compare":
      return t("Compare results");
    case "tools":
      return t("Tool configuration");
    case "reports":
      return t("Reports & export");
    default:
      return sectionLabel(route);
  }
}

function View({ route, ctx }: { route: Route; ctx: Ctx }) {
  switch (route) {
    case "overview":
      return <OverviewView ctx={ctx} />;
    case "projects":
      return <ProjectsView ctx={ctx} />;
    case "targets":
      return <TargetsView ctx={ctx} />;
    case "audits":
      return <AuditsView ctx={ctx} />;
    case "history":
      return <HistoryView ctx={ctx} />;
    case "compare":
      return <CompareView ctx={ctx} />;
    case "tools":
      return <ToolsView />;
    case "reports":
      return <ReportsView ctx={ctx} />;
    default:
      return <SectionView key={route} ctx={ctx} section={route} />;
  }
}
