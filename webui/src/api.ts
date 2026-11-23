// Every API call carries the per-run token in a header. The token arrives once in the URL
// fragment (#token=...), which browsers never send to the server, and is kept only for this tab.
const STORAGE_KEY = "domaininfo-token";
let token = "";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function initToken(): boolean {
  const match = window.location.hash.match(/token=([A-Za-z0-9_-]{16,128})/);
  if (match) {
    token = match[1];
    try {
      sessionStorage.setItem(STORAGE_KEY, token);
    } catch {
      /* storage blocked: the token stays in memory for this page */
    }
    history.replaceState(null, "", window.location.pathname + "#/overview");
    return true;
  }
  try {
    token = sessionStorage.getItem(STORAGE_KEY) || "";
  } catch {
    token = "";
  }
  return token !== "";
}

export function forgetToken() {
  token = "";
  try {
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

async function request(path: string, method = "GET", body?: unknown): Promise<Response> {
  const headers: Record<string, string> = { "X-DomainInfo-Token": token };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch("/api" + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
  });
  if (!response.ok) {
    let message = response.statusText;
    try {
      const data = await response.json();
      message = data.error || (typeof data.detail === "string" ? data.detail : message);
    } catch {
      /* not JSON */
    }
    if (response.status === 401) window.dispatchEvent(new Event("domaininfo:unauthorized"));
    throw new ApiError(response.status, message);
  }
  return response;
}

export async function api<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  const response = await request(path, method, body);
  return (await response.json()) as T;
}

export async function download(path: string, filename: string) {
  const response = await request(path);
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
