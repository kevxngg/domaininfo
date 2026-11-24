import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { api, ApiError, forgetToken, initToken } from "./api";
import { loadStrings, t } from "./i18n";
import type { Session } from "./types";
import { App } from "./App";
import "./styles.css";

function Root() {
  const [session, setSession] = useState<Session | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  useEffect(() => {
    // The server restarted (new token) or the token was rejected: show how to get a new link.
    const onUnauthorized = () => {
      forgetToken();
      setProblem("token");
    };
    const onHash = () => {
      if (/token=/.test(window.location.hash) && initToken()) window.location.reload();
    };
    window.addEventListener("domaininfo:unauthorized", onUnauthorized);
    window.addEventListener("hashchange", onHash);
    return () => {
      window.removeEventListener("domaininfo:unauthorized", onUnauthorized);
      window.removeEventListener("hashchange", onHash);
    };
  }, []);

  useEffect(() => {
    if (!initToken()) {
      setProblem("token");
      return;
    }
    (async () => {
      try {
        await loadStrings();
        setSession(await api<Session>("/session"));
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          forgetToken();
          setProblem("token");
        } else {
          setProblem((err as Error).message);
        }
      }
    })();
  }, []);

  if (problem) {
    return (
      <main className="gate">
        <h1>{t("DomainInfo Security Center")}</h1>
        {problem === "token" ? (
          <p>
            {t(
              "This page needs the access link printed in the terminal when the Security Center started. Open that link (it contains a one-time token) or restart the server.",
            )}
          </p>
        ) : (
          <p role="alert">{problem}</p>
        )}
      </main>
    );
  }
  if (!session) {
    return (
      <main className="gate" aria-busy="true">
        <p>{t("Loading…")}</p>
      </main>
    );
  }
  return <App session={session} />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
