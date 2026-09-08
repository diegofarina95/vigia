import type {
  DomainsResponse,
  EmailAuthReport,
  HistoryResponse,
  LatestResponse,
  Me,
  Schedule,
  SettingsResponse,
} from "./types";

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

import { APP_PREFIX } from "./prefix";
import { storedLang } from "./lib/lang";

/** Adds `?lang=` to a path, respecting a query string that is already there.
 *
 *  Done in one place rather than at each call site because until now it was done at
 *  none: the panel asked the server for findings and the server localised them from
 *  a cookie the client never wrote. A parameter that every request must carry is not
 *  something to remember per call. */
function conIdioma(path: string): string {
  const separador = path.includes("?") ? "&" : "?";
  return `${path}${separador}lang=${storedLang()}`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${APP_PREFIX}${conIdioma(path)}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    /* non-JSON body */
  }
  if (!response.ok) {
    const body = (payload ?? {}) as { error?: string; message?: string; retry_in?: number };
    throw new ApiError(
      response.status,
      body.error ?? "unknown",
      body.message ?? body.error ?? `Request failed (${response.status})`,
    );
  }
  return payload as T;
}

export const api = {
  me: () => request<Me>("/api/me"),
  latest: () => request<LatestResponse>("/api/scan/latest"),
  runScan: () => request<LatestResponse>("/api/scan", { method: "POST" }),
  history: () => request<HistoryResponse>("/api/scans"),
  disconnect: () => request<{ ok: boolean }>("/api/auth/disconnect", { method: "POST" }),
  domains: () => request<DomainsResponse>("/api/domains"),
  addDomain: (domain: string) =>
    request<DomainsResponse>("/api/domains", {
      method: "POST",
      body: JSON.stringify({ domain }),
    }),
  removeDomain: (domain: string) =>
    request<DomainsResponse>(`/api/domains/${encodeURIComponent(domain)}`, {
      method: "DELETE",
    }),
  // Demo: unauthenticated, read-only, backed by invented data.
  demoLatest: () => request<LatestResponse>("/api/demo/scan"),
  demoHistory: () => request<HistoryResponse>("/api/demo/scans"),
  demoDomains: () => request<DomainsResponse>("/api/demo/domains"),
  demoReportUrl: () => `${APP_PREFIX}/api/demo/report`,
  demoCsvUrl: () => `${APP_PREFIX}/api/demo/report/csv`,
  scanSettings: () => request<SettingsResponse>("/api/settings"),
  saveScanSettings: (settings: {
    super_admin_threshold: number;
    dormant_days: number;
    widely_granted_threshold: number;
    dkim_selectors: string;
  }) =>
    request<SettingsResponse>("/api/settings", {
      method: "PUT",
      body: JSON.stringify(settings),
    }),
  upgrade: () => request<{ ok: boolean; message: string }>("/api/billing/upgrade", { method: "POST" }),
  schedule: () => request<Schedule>("/api/schedule"),
  saveSchedule: (payload: {
    frequency: string;
    alert_email: string;
    alert_only_on_change: boolean;
  }) => request<Schedule>("/api/schedule", { method: "PUT", body: JSON.stringify(payload) }),
  sendTestAlert: (alert_email: string) =>
    request<{ ok: boolean; sent_to: string }>("/api/notify/test", {
      method: "POST",
      body: JSON.stringify({ alert_email }),
    }),
  reportUrl: () => `${APP_PREFIX}${conIdioma("/api/report")}`,
  csvUrl: () => `${APP_PREFIX}${conIdioma("/api/report/csv")}`,
  /** `selectors`: comma-separated selectors the visitor says they sign with.
   *  Checked in addition to the default list, and their presence turns a miss from
   *  "no verificado" into a failure — see `dkim_verdict` on the server. */
  emailAuth: (domain: string, selectors = "") =>
    request<EmailAuthReport>("/api/tools/email-auth", {
      method: "POST",
      body: JSON.stringify({ domain, selectors }),
    }),
};
