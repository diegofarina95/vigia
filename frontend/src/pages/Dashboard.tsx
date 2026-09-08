import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, api } from "../api";
import FindingsList from "../components/FindingsList";
import FixFirst from "../components/FixFirst";
import ManualCheckCard from "../components/ManualCheckCard";
import RiskyUsers from "../components/RiskyUsers";
import { SEVERITY_ES } from "../components/Badges";

//: Hardcoded on purpose: it is the same address in every channel and the
//: backend reads it from configuration. If it ever needs to vary per
//: deployment it comes down on /api/me, not into a second constant.
const CONTACTO = "diego@diegofarina.com";
import ScoreGauge, { scoreLabel } from "../components/ScoreGauge";
import ScoreBreakdownPanel from "../components/ScoreBreakdownPanel";
import TrendChart, { dailyPoints } from "../components/TrendChart";
import { useLang } from "../lib/LangContext";
import { getPanel } from "../content/panel";
import type { Finding, HistoryResponse, LatestResponse, Me, Severity } from "../types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

// Lifted variants of the severity palette: the print-safe reds only reach
// ~2.9:1 against the ink headline, under the 3:1 minimum for large text.
// (The printed report has its own palette, generated server-side.)
const SEVERITY_HEX_ON_INK: Record<Severity, string> = {
  critical: "#f2818d",
  high: "#f0a068",
  medium: "#e8c65e",
  low: "#a8becd",
  info: "#9db4c4",
};

export default function Dashboard({ demo = false }: { demo?: boolean } = {}) {
  const navigate = useNavigate();
  const { lang } = useLang();
  const t = getPanel(lang);
  const [me, setMe] = useState<Me | null>(null);
  const [data, setData] = useState<LatestResponse | null>(null);
  const [history, setHistory] = useState<HistoryResponse | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  //: When the last scan finished, so the button can prove it did something.
  //: Every scan of an unchanged tenant returns the same score and the same
  //: findings, so without this the screen is byte-identical afterwards and
  //: the honest conclusion for the user is "it did not work".
  const [scannedAt, setScannedAt] = useState<Date | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        if (demo) {
          const [latest, hist] = await Promise.all([api.demoLatest(), api.demoHistory()]);
          setMe({ connected: true, mock_mode: false, org: latest.org });
          setData(latest);
          setHistory(hist);
          return;
        }
        const meData = await api.me();
        if (!meData.connected) {
          navigate("/", { replace: true });
          return;
        }
        setMe(meData);
        const [latest, hist] = await Promise.all([api.latest(), api.history()]);
        setData(latest);
        setHistory(hist);
      } catch {
        setError(t.dashboard.errorCarga);
      } finally {
        setLoading(false);
      }
    })();
    // `t` is one stable object per language (`getPanel` returns the catalogue
    // entry, not a copy), so this cannot loop. It is in the list so the failure
    // message is in the language on screen and not in the one that was on screen
    // when the component mounted.
  }, [navigate, demo, t]);

  const runScan = useCallback(async () => {
    setScanning(true);
    setError(null);
    try {
      setData(await api.runScan());
      setHistory(await api.history());
      setScannedAt(new Date());
    } catch (err) {
      if (err instanceof ApiError && err.code === "too_soon") {
        setError(t.dashboard.errorDemasiadoPronto);
      } else if (err instanceof ApiError && err.code === "reconnect_required") {
        setError(t.dashboard.errorReconectar);
      } else if (err instanceof ApiError) {
        // `err.message` arrives from the server already localised (`api.ts` sends
        // `?lang=`); only the wrapper around it is ours.
        setError(t.dashboard.errorApi(err.message, err.status));
      } else {
        // fetch() rejects with TypeError("Failed to fetch") when the
        // connection drops — a redeploy, a flaky network, a tunnel blip. That
        // string used to go straight to the screen: English, unexplained, in
        // an otherwise Spanish product, and it reads like the app is broken
        // when the scan may well have finished on the server.
        setError(t.dashboard.errorConexionPerdida);
      }
    } finally {
      setScanning(false);
    }
  }, [t]);

  if (loading) {
    return (
      <div className="mx-auto max-w-5xl space-y-6 px-4 py-10" aria-busy="true" aria-live="polite">
        <span className="sr-only">{t.dashboard.cargando}</span>
        <div className="flex items-center gap-4">
          <div className="skeleton h-8 w-56 rounded" />
          <div className="skeleton ml-auto h-10 w-36 rounded-md" />
        </div>
        <div className="skeleton h-44 rounded-lg" />
        <div className="skeleton h-28 rounded-lg" />
        <div className="space-y-2">
          {[0, 1, 2, 3, 4].map((row) => (
            <div key={row} className="skeleton h-12 rounded-md" />
          ))}
        </div>
      </div>
    );
  }

  const scan = data?.scan ?? null;
  const people = data?.people_at_risk ?? [];
  const worstPeople = people.filter(
    (person) => person.worst === "critical" || person.worst === "high",
  ).length;
  // A changed engine means the two scores measure different things. The
  // backend already refuses to compute the difference; rendering "= sin
  // cambios" over that refusal is how the report ended up claiming nothing
  // had moved after the check count went from 30 to 44.
  const engineChanged = data?.delta?.engine_changed === true;
  // Declared by the finding, not guessed from whether it lists accounts —
  // guessing is what let the policy checks enrol the whole payroll. Scans
  // stored before the field existed fall back to the old rule.
  const isOrgScope = (f: Finding) =>
    f.scope_type ? f.scope_type === "organization" : (f.accounts?.length ?? 0) === 0;
  const orgFindings = (scan?.findings ?? []).filter(isOrgScope);
  const accountFindings = (scan?.findings ?? []).filter((f) => !isOrgScope(f));
  const delta =
    !engineChanged && scan?.score != null && data?.previous_score != null
      ? scan.score - data.previous_score
      : null;
  // Why it moved, split by cause. A zero difference is NOT "sin cambios": the
  // score can hold still while our coverage moves, and it can move while the
  // tenant holds still — which is what happened on 3 August, 33 → 35 entirely
  // because three checks became readable. The label has to say which.
  const scoreChange = engineChanged ? null : data?.delta?.score_change ?? null;
  const exposure = scoreChange?.exposure ?? null;
  const scoreLines = (engineChanged ? [] : data?.delta?.score_lines) ?? [];
  const coverageGained = data?.delta?.coverage_gained ?? [];
  const coverageLost = data?.delta?.coverage_lost ?? [];

  return (
    <div className="mx-auto max-w-5xl space-y-8 px-3 py-6 sm:space-y-10 sm:px-4 sm:py-10">
      {demo && (
        <div className="rounded-lg border-l-4 border-beacon bg-beacon/10 px-4 py-3">
          <p className="font-semibold text-strong">{t.dashboard.demoTitulo}</p>
          <p className="mt-0.5 text-sm text-dim">{t.dashboard.demoCuerpo}</p>
        </div>
      )}

      {/* Header row */}
      <div className="flex flex-col gap-4 sm:flex-row sm:flex-wrap sm:items-center">
        <div className="min-w-0">
          <h1 className="font-display text-xl font-bold text-strong sm:text-2xl">
            {me?.org?.domain}
          </h1>
          <p className="break-all font-mono text-xs text-dim">
            {t.dashboard.conectadoComo} {me?.org?.admin_email}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 sm:ml-auto">
          {scan && (
            <>
              <a
                href={demo ? api.demoReportUrl() : api.reportUrl()}
                target="_blank"
                rel="noreferrer"
                className="flex-1 whitespace-nowrap rounded-md border border-line px-3 py-2.5 text-center text-sm text-dim transition hover:border-ink-3 hover:text-strong sm:flex-none"
              >
                {t.dashboard.informePdf}
              </a>
              <a
                href={demo ? api.demoCsvUrl() : api.csvUrl()}
                className="flex-1 whitespace-nowrap rounded-md border border-line px-3 py-2.5 text-center text-sm text-dim transition hover:border-ink-3 hover:text-strong sm:flex-none"
              >
                CSV
              </a>
            </>
          )}
          <button
            onClick={runScan}
            disabled={scanning}
            hidden={demo}
            className="w-full rounded-md bg-ink px-5 py-3 text-sm font-semibold text-white transition hover:bg-ink-2 disabled:opacity-50 sm:w-auto sm:py-2.5"
          >
            {scanning ? (
              <span className="flex items-center justify-center gap-2">
                <span className="pulse-dot h-2 w-2 rounded-full bg-beacon" aria-hidden />
                {t.dashboard.escaneando}
              </span>
            ) : scan ? (
              t.dashboard.volverAEscanear
            ) : (
              t.dashboard.primerEscaneo
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-sev-critical/50 bg-sev-critical/10 px-4 py-3 text-sm text-sev-critical">
          {error}
        </div>
      )}

      {!scan ? (
        <>
          <div className="rounded-lg border border-line bg-card px-6 py-16 text-center">
            <h2 className="font-display text-xl font-bold text-strong">
              {t.dashboard.vacioTitulo}
            </h2>
            <p className="mx-auto mt-2 max-w-md text-sm text-dim">{t.dashboard.vacioCuerpo}</p>
          </div>
        </>
      ) : (
        <>
          {/* Headline: severity counts and who is exposed lead; the score is a
              secondary metric for tracking movement over time. */}
          <section className="overflow-hidden rounded-lg bg-ink p-6 text-white sm:p-8">
            <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:gap-8">
              {/* No `min-w-0` here, deliberately. This column must floor at its own
                  min-content width so the counters below can never be squeezed
                  narrower than the word they print. The sibling column is what
                  yields space now. */}
              <div className="flex-1">
                {/* `minmax(5.5rem, 1fr)` instead of Tailwind's `grid-cols-4`, which
                    compiles to `minmax(0, 1fr)`. That zero is what let each cell be
                    crushed to 0px wide, at which point "CRÍTICO" broke between
                    characters and printed as a vertical column of letters. 5.5rem
                    holds the longest label plus its padding at this size. */}
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-[repeat(4,minmax(5.5rem,1fr))]">
                  {SEVERITIES.map((severity) => (
                    <div
                      key={severity}
                      className="rounded-md border-l-4 bg-white/5 px-3 py-2"
                      style={{ borderColor: SEVERITY_HEX_ON_INK[severity] }}
                    >
                      <p
                        className="font-mono text-3xl font-bold leading-none"
                        style={{ color: SEVERITY_HEX_ON_INK[severity] }}
                      >
                        {scan.counts[severity] ?? 0}
                      </p>
                      {/* `whitespace-nowrap` is the second lock: even if a future
                          layout squeezes the cell, the word overflows visibly
                          instead of silently stacking one letter per line. */}
                      <p className="mt-1 whitespace-nowrap font-mono text-[10px] uppercase tracking-wider text-mist">
                        {SEVERITY_ES[severity]}
                      </p>
                    </div>
                  ))}
                </div>

                <p className="mt-5 text-xl leading-snug text-white">
                  {people.length > 0 ? (
                    <>
                      <strong>{t.dashboard.cuentasEnRiesgo(people.length)}</strong>
                      {worstPeople > 0 && <>, {t.dashboard.deEllasGraves(worstPeople)}</>}
                      .
                    </>
                  ) : (
                    <strong>{t.dashboard.sinExposicionCuentas}</strong>
                  )}
                </p>
                <p className="mt-2 font-mono text-[11px] text-mist">
                  {t.dashboard.escaneadoEl}{" "}
                  {new Date(scan.created_at).toLocaleString(t.dashboard.locale, {
                    day: "numeric",
                    month: "short",
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                  })}
                </p>
              </div>

              {/* `shrink-0` was here, and it is what broke the row. This column was
                  designed to be about as wide as the dial, so refusing to shrink was
                  safe — until the score decomposition put a full sentence inside it.
                  A non-shrinking column with unbounded prose sets its own width and
                  makes flexbox take every pixel of shrinkage out of its sibling: the
                  counters collapsed to 0px and the summary printed one word per line.
                  Now this column yields, and the prose wraps. */}
              <div className="flex min-w-0 items-start gap-4 border-t border-ink-3 pt-6 lg:border-l lg:border-t-0 lg:pl-8 lg:pt-0">
                <ScoreGauge score={scan.score} onDark />
                <div className="min-w-0 pt-2">
                  <p className="font-mono text-[10px] uppercase tracking-wider text-mist">
                    {t.dashboard.puntuacionPostura}
                  </p>
                  <p className="font-display text-base font-bold text-white">
                    {scoreLabel(scan.score, lang)}
                  </p>
                  {delta !== null && delta !== 0 && (
                    <p
                      className={`font-mono text-sm font-semibold ${delta > 0 ? "text-ok" : "text-bad"}`}
                    >
                      {delta > 0 ? "▲" : "▼"} {Math.abs(delta)} {t.dashboard.respectoAnterior}
                    </p>
                  )}
                  {delta === 0 && !engineChanged && exposure === null && (
                    <p className="font-mono text-sm text-mist">{t.dashboard.sinCambios}</p>
                  )}
                  {/* The decomposition. `exposure === 0` prints "sin cambios en tu
                      organización", never a bare "sin cambios": the second also
                      claims our coverage held still, and that is the claim that
                      was false. */}
                  {/* A reading measure and `break-words` on each line: this is the
                      sentence that used to run past the right edge of the card and
                      end mid-word, because nothing capped it and its column could
                      not shrink. */}
                  {scoreLines.length > 0 && (
                    <div className="mt-1 space-y-0.5">
                      {scoreLines.map((linea) => (
                        <p key={linea} className="max-w-[34ch] break-words text-xs text-mist">
                          {linea}
                        </p>
                      ))}
                    </div>
                  )}
                  {engineChanged && (
                    <p className="mt-1 text-sm text-mist">{t.dashboard.motorCambiado}</p>
                  )}
                </div>
              </div>
            </div>
          </section>

          {/* Audits the number in the hero above, so it sits directly under it —
              but at full page width, and outside the dark block. It used to live
              inside the gauge's own column: `shrink-0` and about as wide as the
              dial, with a five-column table in it, and because that column is on
              `bg-ink` while the panel only declared its own background, every
              data row came out white on white. Collapsed by default, so being
              this high up costs one line. */}
          {data?.breakdown && (
            <section>
              <ScoreBreakdownPanel breakdown={data.breakdown} />
            </section>
          )}

          {/* Coverage changes, on their own, in a neutral box. They are not
              findings and they are not progress: they are what Vigía could and
              could not reach this time. Kept out of the findings list because
              mixing them in is what sent a customer "RESUELTOS DESDE EL ÚLTIMO
              ESCANEO: aplicaciones conectadas por cuentas suspendidas" for a
              check that had simply become readable. */}
          {(coverageGained.length > 0 || coverageLost.length > 0) && (
            <section className="rounded-lg border border-line bg-paper p-5 text-body">
              <h2 className="font-display text-base font-bold text-strong">
                {t.dashboard.coberturaTitulo}
              </h2>
              <p className="mt-1 text-sm text-dim">{t.dashboard.coberturaCuerpo}</p>
              {coverageGained.length > 0 && (
                <div className="mt-3">
                  <p className="font-mono text-[10px] uppercase tracking-wider text-dim">
                    {t.dashboard.coberturaGanada} ({coverageGained.length})
                  </p>
                  <ul className="mt-1 space-y-0.5">
                    {coverageGained.map((e) => (
                      <li key={e.id} className="text-sm">
                        {e.title}
                        {e.open && (
                          <span className="ml-2 font-mono text-[10px] uppercase text-bad">
                            {t.dashboard.coberturaGanadaAbierto}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {coverageLost.length > 0 && (
                <div className="mt-3">
                  <p className="font-mono text-[10px] uppercase tracking-wider text-dim">
                    {t.dashboard.coberturaPerdida} ({coverageLost.length})
                  </p>
                  <ul className="mt-1 space-y-0.5">
                    {coverageLost.map((e) => (
                      <li key={e.id} className="text-sm">
                        {e.title}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </section>
          )}

          {/* What to do first, before the findings list */}
          <FixFirst actions={data?.actions ?? []} />

          {/* What changed — the first question after "how bad is it?" */}
          {scannedAt && !error && (
            <section className="rounded-lg border-l-4 border-ok bg-ok/10 px-4 py-3">
              <p className="font-semibold text-strong">
                {t.dashboard.escaneoCompletadoA}{" "}
                {scannedAt.toLocaleTimeString(t.dashboard.locale, {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                })}
              </p>
              {/* This used to assert "nada ha cambiado en tu organización" after
                  every manual scan, without consulting the delta — so it read as
                  an explanation of the very bug it was sitting on top of, on a
                  screen where the score had gone from 33 to 35. It now only says
                  it when the comparison actually says it. */}
              <p className="mt-0.5 text-sm text-dim">
                {t.dashboard.escaneoGuardado}
                {exposure === 0 && t.dashboard.escaneoSinCambios}
                {exposure === null && t.dashboard.escaneoVerDesglose}
              </p>
            </section>
          )}

          {engineChanged && (
            <section className="rounded-lg border-l-4 border-beacon bg-beacon/10 px-4 py-3">
              <p className="font-semibold text-strong">{t.dashboard.noComparable}</p>
              <p className="mt-0.5 text-sm text-dim">
                {/* `delta.note` comes from the server, already localised. */}
                {data?.delta?.note ?? t.dashboard.motorCambiado}
                {data?.delta?.previous_engine && data?.delta?.engine_version && (
                  <span className="ml-1 font-mono text-xs text-mist">
                    ({data.delta.previous_engine} → {data.delta.engine_version})
                  </span>
                )}
              </p>
            </section>
          )}
          {!engineChanged &&
            data?.delta?.has_baseline &&
            (data.delta.new.length > 0 ||
              data.delta.worse.length > 0 ||
              data.delta.resolved.length > 0) && (
              <section className="rounded-lg border border-line bg-card p-5">
                <h2 className="font-display mb-3 text-lg font-bold text-strong">
                  {t.dashboard.desdeEscaneoAnterior}
                </h2>
                <div className="grid gap-3 sm:grid-cols-3">
                  {(
                    [
                      [t.dashboard.problemasNuevos, data.delta.new, "text-bad", "border-bad/40 bg-bad/5"],
                      [t.dashboard.hanEmpeorado, data.delta.worse, "text-sev-high", "border-sev-high/40 bg-sev-high/5"],
                      [t.dashboard.resueltos, data.delta.resolved, "text-ok", "border-ok/40 bg-ok/5"],
                    ] as const
                  ).map(([label, entries, textClass, boxClass]) => (
                    <div key={label} className={`rounded-md border p-3 ${boxClass}`}>
                      <p className={`font-mono text-2xl font-semibold ${textClass}`}>
                        {entries.length}
                      </p>
                      <p className="text-xs font-semibold uppercase tracking-wide text-dim">
                        {label}
                      </p>
                      {entries.length > 0 && (
                        <ul className="mt-2 space-y-0.5">
                          {entries.slice(0, 3).map((entry) => (
                            <li key={entry.id} className="text-xs leading-snug">
                              {entry.title}
                            </li>
                          ))}
                          {entries.length > 3 && (
                            <li className="text-xs text-dim">
                              {t.dashboard.masEntradas(entries.length - 3)}
                            </li>
                          )}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              </section>
            )}

          

          <RiskyUsers people={people} />

          {/* The configuration block used to live here: domains (with a manual
              "add domain" form), recurring scans with e-mail alerts, and the four
              scan thresholds. All three are gone from the screen on purpose.

              The thresholds are the substantive one: they let the tenant being
              measured move its own yardstick. `dormant_days` at 3650 and the
              dormant-accounts finding stops existing. This product's authority
              comes from measuring against CIS, so the ruler is now fixed in code
              (`services.SCORING_THRESHOLDS`) and the PUT route is gone, not just
              the form.

              Recurring scans are hidden rather than deleted — `jobs.py`, every
              `schedule_*` column and `db.set_schedule` are untouched, waiting for
              monthly monitoring to be a thing being sold. The product default is
              now `off`, because a schedule with no screen to stop it from is a
              schedule that mails a customer forever.

              Domains still sync from Workspace on every scan and the DNS checks
              (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC) still run and still
              appear in the findings and the report. Only adding one by hand is
              gone, along with its POST and DELETE routes. Rows added by hand
              before today are still stored and still checked. */}

          {/* Trend — only once there are two distinct days to compare */}
          {history && dailyPoints(history.history).length < 2 && (
            <section className="rounded-lg border border-dashed border-line bg-card px-5 py-4">
              <h2 className="font-display text-base font-bold text-strong">
                {t.dashboard.puntuacionEnTiempo}
              </h2>
              <p className="mt-1 text-sm text-dim">{t.dashboard.sinHistorico}</p>
            </section>
          )}
          {history && dailyPoints(history.history).length >= 2 && (
            <section className="rounded-lg border border-line bg-card p-6">
              <div className="mb-2 flex items-center justify-between">
                <h2 className="font-display text-lg font-bold text-strong">
                  {t.dashboard.puntuacionEnTiempo}
                </h2>
                
              </div>
              <TrendChart history={history.history} />
            </section>
          )}

          {/* Two questions, two sections: what the organization has configured
              badly, and who inside it is exposed. Mixing them made one console
              toggle read as a problem with every employee. */}
          <section>
            <h2 className="font-display mb-1 text-lg font-bold text-strong">
              {t.dashboard.ajustesOrgTitulo}{" "}
              <span className="font-mono text-sm font-normal text-dim">
                ({orgFindings.length})
              </span>
            </h2>
            <p className="mb-4 max-w-2xl text-sm text-dim">{t.dashboard.ajustesOrgCuerpo}</p>
            <FindingsList findings={orgFindings} />
          </section>

          <section>
            <h2 className="font-display mb-1 text-lg font-bold text-strong">
              {t.dashboard.hallazgosCuentaTitulo}{" "}
              <span className="font-mono text-sm font-normal text-dim">
                ({accountFindings.length})
              </span>
            </h2>
            <p className="mb-4 max-w-2xl text-sm text-dim">{t.dashboard.hallazgosCuentaCuerpo}</p>
            <FindingsList findings={accountFindings} />
          </section>

          {/* The one place on screen where the reader can answer the report.
              Free report → paid remediation, and until now the page ended with
              a score and no way to reply to it. No prices: the number depends
              on what the report found, and that conversation belongs in a
              reply, not on a page somebody may be forwarding. */}
          {scan && !demo && (
            <section className="rounded-lg border-2 border-ink bg-card p-5">
              <h2 className="font-display text-lg font-bold text-strong">
                {t.dashboard.remediacionTitulo}
              </h2>
              <p className="mt-1 max-w-2xl text-sm text-dim">{t.dashboard.remediacionCuerpo}</p>
              <a
                href={
                  `mailto:${CONTACTO}` +
                  `?subject=${encodeURIComponent(
                    t.dashboard.correoAsunto(me?.org?.domain ?? ""),
                  )}` +
                  `&body=${encodeURIComponent(
                    t.dashboard.correoCuerpo(me?.org?.domain ?? "", scan.score),
                  )}`
                }
                className="mt-4 inline-block rounded-md bg-ink px-5 py-3 text-sm font-semibold text-white transition hover:bg-ink-2"
              >
                {t.dashboard.remediacionEscribeme}: {CONTACTO}
              </a>
              <p className="mt-2 text-xs text-mist">{t.dashboard.remediacionNota}</p>
            </section>
          )}

          {/* Manual checks — only what Vigía could not read automatically */}
          {scan.manual_checks.length > 0 ? (
            <section>
              <h2 className="font-display mb-1 text-lg font-bold text-strong">
                {t.dashboard.manualesTitulo}{" "}
                <span className="font-mono text-sm font-normal text-dim">
                  ({scan.manual_checks.length})
                </span>
              </h2>
              <p className="mb-4 max-w-2xl text-sm text-dim">{t.dashboard.manualesCuerpo}</p>
              <div className="grid gap-4 md:grid-cols-2">
                {scan.manual_checks.map((check) => (
                  <ManualCheckCard key={check.id} check={check} />
                ))}
              </div>
            </section>
          ) : (
            <section className="rounded-lg border border-ok/40 bg-ok/5 p-5">
              <h2 className="font-display text-lg font-bold text-strong">
                {t.dashboard.manualesNingunaTitulo}
              </h2>
              <p className="mt-1 text-sm text-dim">{t.dashboard.manualesNingunaCuerpo}</p>
            </section>
          )}
        </>
      )}
    </div>
  );
}
