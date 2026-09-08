import { getComponentes } from "../content/componentes";
import { useLang } from "../lib/LangContext";
import type { Severity, Status } from "../types";

/**
 * The Spanish severity words, still exported because `pages/Dashboard.tsx` reads
 * this map. The badges below no longer use it: they take their label from the
 * bilingual catalogue, so the word follows the interface language.
 */
export const SEVERITY_ES: Record<Severity, string> = {
  critical: "crítico",
  high: "alto",
  medium: "medio",
  low: "bajo",
  info: "info",
};

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-sev-critical text-white",
  high: "bg-sev-high text-white",
  medium: "bg-sev-medium text-white",
  low: "bg-sev-low text-white",
  info: "bg-sev-info/20 text-sev-info",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const { lang } = useLang();
  const t = getComponentes(lang).insignias;

  return (
    <span
      className={`inline-block whitespace-nowrap rounded px-1.5 py-0.5 font-mono text-[11px] font-medium uppercase tracking-wide ${SEVERITY_STYLES[severity]}`}
    >
      {t.severidad[severity]}
    </span>
  );
}

// Three states, three treatments. "Not verified" is the absence of proof, not
// a failure: it gets its own dashed, colourless styling so it can never be
// misread as "this is broken" — and it never affects the score.
const STATUS_STYLES: Record<Status, { dot: string; text: string }> = {
  pass: { dot: "bg-ok", text: "text-ok" },
  fail: { dot: "bg-bad", text: "text-bad" },
  warn: { dot: "bg-mid", text: "text-mid" },
  undetermined: { dot: "bg-unk", text: "text-dim" },
};

export function StatusBadge({ status }: { status: Status }) {
  const { lang } = useLang();
  const t = getComponentes(lang).insignias;
  const style = STATUS_STYLES[status];

  if (status === "undetermined") {
    return (
      <span
        className="inline-flex items-center gap-1.5 whitespace-nowrap rounded border border-dashed border-dim px-1.5 py-0.5 font-mono text-[11px] font-medium text-dim"
        title={t.noVerificadoTitulo}
      >
        <span className="h-2 w-2 rounded-full border border-dim" aria-hidden />
        {t.estado[status]}
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap font-mono text-xs font-medium ${style.text}`}>
      <span className={`h-2 w-2 rounded-full ${style.dot}`} aria-hidden />
      {t.estado[status]}
    </span>
  );
}
