/* NOT MOUNTED. Removed from the dashboard to simplify the first impression
 * before opening to strangers. Domains still sync from Workspace on every scan
 * and every DNS check still runs and still appears in the report — what went
 * away is adding a domain by hand, along with the POST/DELETE routes this panel
 * used. Kept on disk, not deleted: only `GET /api/domains` still exists, so
 * remounting means restoring those two routes first. */
import { useEffect, useState } from "react";
import { ApiError, api } from "../api";
import { getComponentes } from "../content/componentes";
import { useLang } from "../lib/LangContext";
import type { DomainCheckDetail, DomainInfo, Scan, Status } from "../types";
import { StatusBadge } from "./Badges";

const MECHANISMS = ["spf", "dkim", "dmarc"] as const;
const EXTRAS = ["mta_sts", "tls_rpt", "dnssec"] as const;
type CheckKey = (typeof MECHANISMS)[number] | (typeof EXTRAS)[number];

const LABEL: Record<CheckKey, string> = {
  spf: "SPF",
  dkim: "DKIM",
  dmarc: "DMARC",
  mta_sts: "MTA-STS",
  tls_rpt: "TLS-RPT",
  dnssec: "DNSSEC",
};

const DOT: Record<Status, string> = {
  pass: "bg-ok",
  fail: "bg-bad",
  warn: "bg-mid",
  undetermined: "bg-line border border-dim",
};

/** Per-domain DNS detail, read out of the email-auth findings the scan already
 * produced (details.domains) — the same source the exported report uses. */
function domainDetails(scan: Scan | null): Record<string, Partial<Record<CheckKey, DomainCheckDetail>>> {
  const map: Record<string, Partial<Record<CheckKey, DomainCheckDetail>>> = {};
  if (!scan) return map;

  const findingKey = (id: string): CheckKey | null => {
    const stripped = id.replace("email-", "").replace("mail-", "").replace("dns-", "");
    const normalized = stripped.replace("-", "_") as CheckKey;
    return normalized in LABEL ? normalized : null;
  };

  for (const finding of scan.findings) {
    const key = findingKey(finding.id);
    if (!key) continue;
    const domains = (finding.details as { domains?: Record<string, DomainCheckDetail> } | undefined)
      ?.domains;
    if (!domains) continue;
    for (const [domain, detail] of Object.entries(domains)) {
      if (detail && typeof detail === "object") (map[domain] ??= {})[key] = detail;
    }
  }
  return map;
}

function Record({ value }: { value: string }) {
  return (
    <pre className="mt-1 overflow-x-auto rounded bg-ink px-2 py-1.5 font-mono text-[11px] text-mist">
      {value}
    </pre>
  );
}

function CheckDetail({ name, detail }: { name: CheckKey; detail: DomainCheckDetail }) {
  const { lang } = useLang();
  const t = getComponentes(lang).dominios;
  const overLimit = typeof detail.dns_lookups === "number" && detail.dns_lookups > 10;
  const weakKey = typeof detail.key_bits === "number" && detail.key_bits < 2048;

  return (
    <div className="border-t border-line py-2.5 first:border-t-0">
      <div className="flex flex-wrap items-center gap-2">
        <span className="w-20 font-mono text-xs font-semibold text-strong">{LABEL[name]}</span>
        <StatusBadge status={detail.status} />
      </div>
      <p className="mt-1 text-sm leading-snug text-dim">{detail.summary}</p>

      {detail.record && <Record value={detail.record} />}

      {name === "spf" && (
        <p className="mt-1 font-mono text-[11px] text-dim">
          {t.spfMecanismo}{" "}
          <strong className="text-strong">{(detail.all_qualifier ?? "?") + "all"}</strong>
          {typeof detail.dns_lookups === "number" && (
            <>
              {" · "}
              {t.spfConsultas}{" "}
              <strong className={overLimit ? "text-bad" : "text-strong"}>
                {detail.dns_lookups}
              </strong>{" "}
              / 10 (RFC 7208)
              {overLimit && (
                <span className="text-bad">
                  {" "}
                  {t.spfSobreLimite}
                </span>
              )}
            </>
          )}
        </p>
      )}

      {name === "dkim" && (
        <p className="mt-1 font-mono text-[11px] text-dim">
          {detail.selector ? (
            <>
              {t.dkimSelector} <strong className="text-strong">{detail.selector}</strong>
              {typeof detail.key_bits === "number" && (
                <>
                  {" · "}
                  {t.dkimClave}{" "}
                  <strong className={weakKey ? "text-mid" : "text-strong"}>
                    {detail.key_bits} {t.dkimBits}
                  </strong>
                  {weakKey ? t.dkimDebil : t.dkimAdecuada}
                </>
              )}
            </>
          ) : (
            <>
              {t.dkimProbados(detail.checked_selectors?.length ?? 0)}
              {detail.checked_selectors && detail.checked_selectors.length > 0 && (
                <> ({detail.checked_selectors.slice(0, 5).join(", ")})</>
              )}
              {t.dkimSelectorPropio}
            </>
          )}
        </p>
      )}

      {name === "dmarc" && (
        <p className="mt-1 font-mono text-[11px] text-dim">
          {t.dmarcPolitica}{" "}
          <strong className="text-strong">p={detail.policy ?? t.dmarcSinDefinir}</strong>
          {" · "}
          {t.dmarcAlineacion} DKIM{" "}
          <strong className="text-strong">
            {detail.adkim === "s" ? t.dmarcEstricta : t.dmarcRelajada}
          </strong>
          , SPF{" "}
          <strong className="text-strong">
            {detail.aspf === "s" ? t.dmarcEstricta : t.dmarcRelajada}
          </strong>
          <br />
          {t.dmarcInformes}{" "}
          <strong className={detail.rua_destination === "own" ? "text-ok" : "text-mid"}>
            {detail.rua_destination === "own"
              ? t.dmarcRuaPropio
              : detail.rua_destination === "third_party"
                ? t.dmarcRuaTercero
                : t.dmarcRuaNinguno}
          </strong>
        </p>
      )}

      {detail.issues && detail.issues.length > 0 && (
        <ul className="mt-1.5 space-y-0.5">
          {detail.issues.map((issue) => (
            <li key={issue} className="text-xs text-sev-high">
              ⚠ {issue}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function DomainsPanel({ scan, demo = false }: { scan: Scan | null; demo?: boolean }) {
  const { lang } = useLang();
  const t = getComponentes(lang).dominios;
  const [domains, setDomains] = useState<DomainInfo[]>([]);
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    const load = demo ? api.demoDomains() : api.domains();
    load.then((r) => setDomains(r.domains)).catch(() => {});
  }, [demo]);

  async function add(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const result = await api.addDomain(input);
      setDomains(result.domains);
      setInput("");
      setNotice(t.anadido);
    } catch (err) {
      setError(
        err instanceof ApiError && err.code === "invalid_domain"
          ? t.errorInvalido
          : t.errorAnadir,
      );
    } finally {
      setBusy(false);
    }
  }

  async function remove(domain: string) {
    setError(null);
    setNotice(null);
    try {
      const result = await api.removeDomain(domain);
      setDomains(result.domains);
    } catch {
      setError(t.errorQuitar);
    }
  }

  const details = domainDetails(scan);
  const allChecks: CheckKey[] = [...MECHANISMS, ...EXTRAS];

  return (
    <section className="rounded-lg border border-line bg-card p-6">
      <div className="mb-1 flex items-center justify-between gap-3">
        <h2 className="font-display text-lg font-bold text-strong">{t.titulo}</h2>
        <span className="font-mono text-[11px] text-dim">{t.subtitulo}</span>
      </div>
      <p className="mb-4 text-sm text-dim">{t.intro}</p>

      {domains.length === 0 ? (
        <p className="mb-4 rounded-md border border-dashed border-line px-4 py-4 text-sm text-dim">
          {t.vacioAntes}
          <span className="font-mono text-xs">{t.estado.undetermined}</span>
          {t.vacioDespues}
        </p>
      ) : (
        <ul className="mb-4 divide-y divide-line rounded-md border border-line">
          {domains.map(({ domain, source }) => {
            const domainChecks = details[domain];
            const expanded = open === domain;
            return (
              <li key={domain}>
                <div className="flex flex-wrap items-center gap-3 px-4 py-2.5">
                  <button
                    onClick={() => setOpen(expanded ? null : domain)}
                    aria-expanded={expanded}
                    disabled={!domainChecks}
                    className="flex items-center gap-2 font-mono text-sm text-strong disabled:cursor-default"
                  >
                    {domainChecks && (
                      <span className={`text-dim transition-transform ${expanded ? "rotate-90" : ""}`}>
                        ▸
                      </span>
                    )}
                    {domain}
                  </button>
                  <span className="rounded border border-line px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-dim">
                    {source === "google" ? "Workspace" : t.origenManual}
                  </span>
                  <span className="ml-auto flex items-center gap-3">
                    {allChecks.map((check) => (
                      <span
                        key={check}
                        className="inline-flex items-center gap-1 font-mono text-[10px] uppercase text-dim"
                        title={
                          domainChecks?.[check]
                            ? `${LABEL[check]}: ${t.estado[domainChecks[check]!.status]}`
                            : `${LABEL[check]}: ${t.sinEscanear}`
                        }
                      >
                        <span
                          className={`h-2 w-2 rounded-full ${
                            domainChecks?.[check] ? DOT[domainChecks[check]!.status] : "bg-line"
                          }`}
                        />
                        {LABEL[check]}
                      </span>
                    ))}
                    {source === "custom" && !demo && (
                      <button
                        onClick={() => remove(domain)}
                        aria-label={t.quitarAria(domain)}
                        className="rounded border border-line px-2 py-1 text-xs text-dim transition hover:border-bad hover:text-bad"
                      >
                        {t.quitar}
                      </button>
                    )}
                  </span>
                </div>

                {expanded && domainChecks && (
                  <div className="border-t border-line bg-paper px-4 py-2">
                    {allChecks
                      .filter((check) => domainChecks[check])
                      .map((check) => (
                        <CheckDetail key={check} name={check} detail={domainChecks[check]!} />
                      ))}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}

      {demo ? null : (
      <form onSubmit={add} className="flex max-w-md gap-2">
        <label htmlFor="new-domain" className="sr-only">
          {t.etiquetaNuevo}
        </label>
        <input
          id="new-domain"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder={t.placeholderNuevo}
          required
          className="w-full rounded-md border border-line bg-paper px-3 py-2 font-mono text-sm focus:border-ink-3 focus:outline-none"
        />
        <button
          type="submit"
          disabled={busy}
          className="shrink-0 rounded-md bg-ink px-4 py-2 text-sm font-semibold text-white transition hover:bg-ink-2 disabled:opacity-50"
        >
          {t.anadir}
        </button>
      </form>
      )}
      {error && <p className="mt-2 text-sm text-bad">{error}</p>}
      {notice && <p className="mt-2 text-sm text-ok">{notice}</p>}
    </section>
  );
}
