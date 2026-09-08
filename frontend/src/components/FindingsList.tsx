import { useState } from "react";
import { getComponentes, type Componentes } from "../content/componentes";
import { useLang } from "../lib/LangContext";
import type { Change, Finding, Severity } from "../types";
import { SeverityBadge, StatusBadge } from "./Badges";

const CHANGE_STYLE: Partial<Record<Change, string>> = {
  new: "bg-bad text-white",
  worse: "bg-sev-high text-white",
  improved: "bg-ok/15 text-ok",
  resolved: "bg-ok/15 text-ok",
  // Neutral on purpose. Green would read as "you fixed it" and red as "you
  // broke it", and neither happened: what moved is what Vigía can see.
  coverage_gained: "bg-ink-3/15 text-strong-2",
  coverage_lost: "bg-ink-3/15 text-strong-2",
};

/** The numbers behind a `worse`/`improved`, so a row can say what drifted
 *  instead of just that something did.
 *
 *  The severities are interpolated as the server sends them (`high`, `critical`),
 *  which is what this note has always shown. */
function changeNote(finding: Finding, t: Componentes["hallazgos"]): string | null {
  const d = finding.change_detail;
  if (!d) return null;
  if (d.from_count != null && d.to_count != null) {
    return t.notaAfectados(d.from_count, d.to_count);
  }
  if (d.from_severity && d.to_severity) {
    return d.regression
      ? t.notaSeveridadRegresion(d.from_severity, d.to_severity)
      : t.notaSeveridad(d.from_severity, d.to_severity);
  }
  if (finding.change === "coverage_gained" && d.to_status) {
    return t.notaCobertura;
  }
  return null;
}

function ChangeBadge({ change }: { change?: Change }) {
  const { lang } = useLang();
  const t = getComponentes(lang).hallazgos;
  const className = change ? CHANGE_STYLE[change] : undefined;
  const label = change ? t.cambio[change] : undefined;
  if (!className || !label) return null;
  return (
    <span
      className={`whitespace-nowrap rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wide ${className}`}
    >
      {label}
    </span>
  );
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUS_ORDER = { fail: 0, warn: 1, undetermined: 2, pass: 3 };

const SEVERITY_BAR: Record<Severity, string> = {
  critical: "border-l-sev-critical",
  high: "border-l-sev-high",
  medium: "border-l-sev-medium",
  low: "border-l-sev-low",
  info: "border-l-sev-info",
};


function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const { lang } = useLang();
  const t = getComponentes(lang).hallazgos;
  const nota = changeNote(finding, t);

  return (
    <div
      className={`row-lift rounded-md border border-line border-l-4 bg-card ${
        SEVERITY_BAR[finding.severity]
      } ${finding.severity === "critical" && finding.status === "fail" ? "shadow-[0_1px_3px_rgb(185_58_72/0.14)]" : ""}`}
    >
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="flex w-full items-center gap-3 px-4 py-3 text-left"
      >
        <SeverityBadge severity={finding.severity} />
        <ChangeBadge change={finding.change} />
        {nota && <span className="font-mono text-[10px] text-dim">{nota}</span>}
        <span className="flex-1 font-medium text-strong">
          {finding.title}
        </span>
        <StatusBadge status={finding.status} />
        <span className={`text-dim transition-transform ${open ? "rotate-180" : ""}`} aria-hidden>
          ▾
        </span>
      </button>

      {open && (
        <div className="space-y-4 border-t border-line px-4 py-4">
          {(
            <>
              {finding.description && <p className="text-sm leading-relaxed">{finding.description}</p>}

              {finding.scope_label && (
                <p className="text-xs text-dim">
                  <span className="font-semibold text-strong">{t.alcance}</span>{" "}
                  {finding.scope_label}
                </p>
              )}

              {finding.observed_value && (
                <p className="rounded bg-paper px-3 py-2 text-sm">
                  <span className="font-semibold text-strong">{t.valorActual}</span>{" "}
                  {finding.observed_value}
                </p>
              )}

              {finding.affected_items.length > 0 && (
                <div>
                  <p className="mb-1.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-dim">
                    {t.afectados} ({finding.affected_items.length})
                  </p>
                  <ul className="max-h-48 space-y-1 overflow-y-auto overflow-x-hidden rounded bg-paper p-2.5 sm:p-3">
                    {finding.affected_items.map((item) => (
                      <li key={item} className="break-all font-mono text-xs text-body">
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {finding.remediation && (
                <div>
                  <p className="mb-1.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-dim">
                    {finding.status === "pass" ? t.comoMantener : t.comoArreglar}
                  </p>
                  <p className="text-sm leading-relaxed">{finding.remediation}</p>
                </div>
              )}

              <div className="flex flex-wrap items-center gap-3 pt-1">
                {finding.admin_console_url && (
                  <a
                    href={finding.admin_console_url}
                    target="_blank"
                    rel="noreferrer"
                    className="rounded-md bg-ink px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-ink-2"
                  >
                    {t.abrirConsola}
                  </a>
                )}
                {finding.cis_control && (
                  <span className="rounded border border-line px-2 py-1 font-mono text-[11px] text-dim">
                    {finding.cis_control}
                  </span>
                )}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default function FindingsList({ findings }: { findings: Finding[] }) {
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [issuesOnly, setIssuesOnly] = useState(false);
  const [changedOnly, setChangedOnly] = useState(false);
  const { lang } = useLang();
  const componentes = getComponentes(lang);
  const t = componentes.hallazgos;

  const changedCount = findings.filter(
    (f) => f.change === "new" || f.change === "worse",
  ).length;

  const visible = findings
    .filter((f) => severityFilter === "all" || f.severity === severityFilter)
    .filter((f) => !issuesOnly || f.status === "fail" || f.status === "warn")
    .filter((f) => !changedOnly || f.change === "new" || f.change === "worse")
    .sort(
      (a, b) =>
        // New and worsened findings float to the top: they are what changed.
        Number(b.change === "new" || b.change === "worse") -
          Number(a.change === "new" || a.change === "worse") ||
        STATUS_ORDER[a.status] - STATUS_ORDER[b.status] ||
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    );

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {(["all", ...SEVERITY_ORDER] as const).map((severity) => (
          <button
            key={severity}
            onClick={() => setSeverityFilter(severity as Severity | "all")}
            className={`rounded-full px-3 py-1 font-mono text-xs transition ${
              severityFilter === severity
                ? "bg-ink text-white"
                : "border border-line bg-card text-dim hover:border-ink-3"
            }`}
          >
            {severity === "all"
              ? t.todas
              : componentes.insignias.severidad[severity as Severity]}
          </button>
        ))}
        <label className="ml-auto flex cursor-pointer items-center gap-2 text-xs text-dim">
          <input
            type="checkbox"
            checked={issuesOnly}
            onChange={(event) => setIssuesOnly(event.target.checked)}
            className="accent-ink"
          />
          {t.soloProblemas}
        </label>
        {changedCount > 0 && (
          <label className="flex cursor-pointer items-center gap-2 text-xs text-dim">
            <input
              type="checkbox"
              checked={changedOnly}
              onChange={(event) => setChangedOnly(event.target.checked)}
              className="accent-ink"
            />
            {t.soloCambios} ({changedCount})
          </label>
        )}
      </div>

      {visible.length === 0 ? (
        <p className="rounded-md border border-line bg-card px-4 py-6 text-center text-sm text-dim">
          {t.sinCoincidencias}
        </p>
      ) : (
        visible.map((finding) => <FindingRow key={finding.id} finding={finding} />)
      )}
    </div>
  );
}
