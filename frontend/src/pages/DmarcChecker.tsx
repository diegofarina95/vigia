import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../api";
import { StatusBadge } from "../components/Badges";
import { useLang } from "../lib/LangContext";
import { getPanel } from "../content/panel";
import type { EmailAuthReport, MechanismResult } from "../types";

function MechanismCard({
  name,
  longName,
  result,
}: {
  name: string;
  longName: string;
  result: MechanismResult;
}) {
  return (
    <div className="rounded-lg border border-line bg-card p-5">
      <div className="flex items-center justify-between gap-3">
        <h3 className="font-display text-lg font-bold text-strong">
          {name} <span className="text-sm font-normal text-dim">· {longName}</span>
        </h3>
        <StatusBadge status={result.status} />
      </div>
      <p className="mt-3 text-sm leading-relaxed">{result.summary}</p>
      {result.record && (
        <pre className="mt-3 overflow-x-auto rounded bg-ink px-3 py-2 font-mono text-xs text-mist">
          {result.record}
        </pre>
      )}
      {result.issues && result.issues.length > 0 && (
        <ul className="mt-3 space-y-1">
          {result.issues.map((issue) => (
            <li key={issue} className="text-xs text-sev-high">
              ⚠ {issue}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function DmarcChecker() {
  const { lang } = useLang();
  const t = getPanel(lang);
  const [domain, setDomain] = useState("");
  // Optional. However many names we guess, a domain with its own selector never
  // gets past "no verificado" — DKIM cannot be enumerated. Somebody looking at
  // their own domain knows the name, and telling us turns a guess into a check.
  const [selectores, setSelectores] = useState("");
  const [report, setReport] = useState<EmailAuthReport | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    document.title = t.dmarc.tituloPagina;
  }, [t]);

  async function check(event: React.FormEvent) {
    event.preventDefault();
    setChecking(true);
    setError(null);
    setReport(null);
    setCopied(false);
    try {
      setReport(await api.emailAuth(domain, selectores));
    } catch (err) {
      if (err instanceof ApiError && err.code === "invalid_domain") {
        setError(t.dmarc.errorDominio);
      } else if (err instanceof ApiError && err.code === "rate_limited") {
        setError(t.dmarc.errorLimite);
      } else {
        setError(t.dmarc.errorGenerico);
      }
    } finally {
      setChecking(false);
    }
  }

  // `dmarc@`, not `postmaster@`: the old suggestion proposed an address that may
  // not exist, and when it does not the reports bounce and nobody finds out —
  // advice that fails silently, in a tool whose argument is that it never does.
  //
  // `faltaSpf` drives the ordering: a DMARC record on a domain with neither SPF nor
  // DKIM returns reports where everything fails and protects nothing. SPF is what
  // actually starts protecting, so it goes first, and both records are given at
  // once because sending somebody away to come back later loses them.
  const faltaSpf = !!report && report.spf.status === "fail" && !report.spf.record;
  const suggestedSpf = "v=spf1 -all";
  const suggestedRecord = report
    ? `v=DMARC1; p=none; rua=mailto:dmarc@${report.domain}`
    : "";

  async function copySuggested() {
    await navigator.clipboard.writeText(
      faltaSpf ? `${suggestedSpf}\n${suggestedRecord}` : suggestedRecord
    );
    setCopied(true);
  }

  return (
    <div>
      <section className="bg-ink">
        <div className="mx-auto max-w-3xl px-4 py-14 text-center">
          <p className="font-mono text-xs font-medium uppercase tracking-[0.25em] text-beacon">
            {t.dmarc.etiquetaGratis}
          </p>
          <h1 className="font-display mt-3 text-3xl font-extrabold text-white sm:text-4xl">
            {t.dmarc.titular}
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-mist">{t.dmarc.subtitular}</p>
          <form onSubmit={check} className="mx-auto mt-8 max-w-md">
              <div className="flex gap-2">
            <label htmlFor="domain" className="sr-only">
              {t.dmarc.etiquetaDominio}
            </label>
            <input
              id="domain"
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              placeholder={t.dmarc.marcadorDominio}
              required
              className="w-full rounded-md border border-ink-3 bg-ink-2 px-4 py-2.5 font-mono text-sm text-white placeholder:text-mist/60 focus:border-beacon focus:outline-none"
            />
            <button
              type="submit"
              disabled={checking}
              className="shrink-0 rounded-md bg-beacon px-5 py-2.5 font-semibold text-strong transition hover:bg-beacon/90 disabled:opacity-60"
            >
              {checking ? t.dmarc.comprobando : t.dmarc.comprobar}
            </button>
            </div>

            <div className="mt-3 text-left">
              <label htmlFor="selectores" className="block text-sm text-mist">
                {t.dmarc.etiquetaSelectores}
              </label>
              <input
                id="selectores"
                value={selectores}
                onChange={(event) => setSelectores(event.target.value)}
                placeholder={t.dmarc.marcadorSelectores}
                className="mt-1.5 w-full rounded-md border border-ink-3 bg-ink-2 px-4 py-2 font-mono text-sm text-white placeholder:text-mist/60 focus:border-beacon focus:outline-none"
              />
              <p className="mt-1.5 text-xs text-mist/80">{t.dmarc.ayudaSelectores}</p>
            </div>
          </form>
          {error && <p className="mt-4 text-sm text-sev-high">{error}</p>}
        </div>
      </section>

      {report && (
        <section className="mx-auto max-w-3xl space-y-4 px-4 py-10">
          <div className="flex items-center justify-between">
            <h2 className="font-display text-xl font-bold text-strong">
              {t.dmarc.resultadosDe} <span className="font-mono">{report.domain}</span>
            </h2>
            {report.mx.google_workspace && (
              <span className="rounded bg-ok/10 px-2 py-1 font-mono text-[11px] text-ok">
                {t.dmarc.mxWorkspace}
              </span>
            )}
          </div>

          <MechanismCard name="SPF" longName={t.dmarc.spfLargo} result={report.spf} />
          <MechanismCard name="DKIM" longName={t.dmarc.dkimLargo} result={report.dkim} />
          <MechanismCard name="DMARC" longName={t.dmarc.dmarcLargo} result={report.dmarc} />

          <h3 className="font-display pt-2 text-lg font-bold text-strong">
            {t.dmarc.transporteTitulo}
            <span className="ml-2 text-sm font-normal text-dim">{t.dmarc.transporteNota}</span>
          </h3>
          <MechanismCard name="MTA-STS" longName={t.dmarc.mtaStsLargo} result={report.mta_sts} />
          <MechanismCard name="TLS-RPT" longName={t.dmarc.tlsRptLargo} result={report.tls_rpt} />
          <MechanismCard name="DNSSEC" longName={t.dmarc.dnssecLargo} result={report.dnssec} />

          {((report.dmarc.status === "fail" && !report.dmarc.record) || faltaSpf) && (
            <div className="rounded-lg border border-line bg-card p-5">
              <h3 className="font-semibold text-strong">
                  {faltaSpf ? t.dmarc.empiezaSpf : t.dmarc.empiezaDmarc}
                </h3>
              <p className="mt-2 text-sm text-dim">
                {faltaSpf ? (
                  t.dmarc.cuerpoSpf
                ) : (
                  <>
                    {t.dmarc.sugerenciaAnade}
                    <code className="font-mono">_dmarc.{report.domain}</code>
                    {t.dmarc.sugerenciaMonitorizacion}
                    <code className="font-mono">p=quarantine</code>
                    {t.dmarc.sugerenciaSinRiesgo}
                  </>
                )}
              </p>
              {/* The mailbox has to exist. The suggestion used to propose
                  `postmaster@`, an address that may simply not be there — and when
                  it is not, the aggregate reports bounce and nobody finds out.
                  Advice that fails silently, in a tool whose whole argument is
                  that it never does. */}
              <p className="mt-2 text-sm text-dim">
                <strong className="text-strong">
                  {t.dmarc.buzonAviso}
                  <code className="font-mono">dmarc@{report.domain}</code>
                  {t.dmarc.buzonAvisoFin}
                </strong>
              </p>
              <div className="mt-3 flex items-center gap-2">
                {/* Shows exactly what the button copies. The two had drifted
                    apart: one record on screen, two on the clipboard. */}
                <pre className="flex-1 overflow-x-auto whitespace-pre rounded bg-ink px-3 py-2 font-mono text-xs text-mist">
                  {faltaSpf ? `${suggestedSpf}\n${suggestedRecord}` : suggestedRecord}
                </pre>
                <button
                  onClick={copySuggested}
                  className="shrink-0 rounded-md border border-ink px-3 py-2 text-xs font-semibold text-strong transition hover:bg-ink hover:text-white"
                >
                  {copied ? t.dmarc.copiado : t.dmarc.copiar}
                </button>
              </div>
            </div>
          )}

          {/* CTA to the product */}
          <div className="flex flex-col items-start gap-4 rounded-lg bg-ink p-6 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h3 className="font-display font-bold text-white">{t.dmarc.ctaTitulo}</h3>
              <p className="mt-1 text-sm text-mist">{t.dmarc.ctaCuerpo}</p>
            </div>
            <Link
              to="/"
              className="shrink-0 rounded-md bg-beacon px-5 py-2.5 font-semibold text-strong transition hover:bg-beacon/90"
            >
              {t.dmarc.ctaBoton}
            </Link>
          </div>
        </section>
      )}

      <section className="mx-auto max-w-3xl px-4 pb-16 pt-4">
        <h2 className="font-display text-xl font-bold text-strong">
          {t.dmarc.explicadoresTitulo}
        </h2>
        <div className="mt-4 space-y-4">
          {t.dmarc.explicadores.map((explicador) => (
            <div key={explicador.titulo} className="rounded-lg border border-line bg-card p-5">
              <h3 className="font-semibold text-strong">{explicador.titulo}</h3>
              <p className="mt-2 text-sm leading-relaxed text-dim">{explicador.cuerpo}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
