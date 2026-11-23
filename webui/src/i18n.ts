// UI text is English; the server sends the Spanish catalog (i18n_es_phase4.py) when Spanish is active.
import { api } from "./api";

let strings: Record<string, string> = {};
let lang = "en";

export async function loadStrings() {
  try {
    const data = await api<{ language: string; strings: Record<string, string> }>("/i18n");
    strings = data.strings || {};
    lang = data.language || "en";
    document.documentElement.lang = lang;
  } catch {
    strings = {};
  }
}

export function t(text: string, values?: Record<string, string | number | null | undefined>): string {
  let out = strings[text] ?? text;
  if (values) {
    out = out.replace(/\{(\w+)\}/g, (whole, name: string) => (name in values ? String(values[name] ?? "") : whole));
  }
  return out;
}

export function formatDate(value?: string | number | null) {
  if (value === null || value === undefined || value === "") return "—";
  const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(lang === "es" ? "es-ES" : "en-GB", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}
