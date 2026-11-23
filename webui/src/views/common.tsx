import type { Ctx } from "../App";
import { t } from "../i18n";
import { Empty, PageHeader } from "../ui";

export function NeedProject({ ctx, title }: { ctx: Ctx; title: string }) {
  return (
    <>
      <PageHeader title={title} />
      <Empty title={t("Choose or create a project first")}>
        <button className="primary" onClick={() => ctx.go("projects")}>
          {t("Go to projects")}
        </button>
      </Empty>
    </>
  );
}
