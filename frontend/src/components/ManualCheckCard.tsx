import { getComponentes } from "../content/componentes";
import { useLang } from "../lib/LangContext";
import type { ManualCheck } from "../types";
import { SeverityBadge } from "./Badges";

export default function ManualCheckCard({ check }: { check: ManualCheck }) {
  const { lang } = useLang();
  const t = getComponentes(lang).comprobacionManual;

  return (
    <div className="flex flex-col gap-3 rounded-md border border-dashed border-ink-3/40 bg-card p-4">
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="font-mono text-[11px] font-semibold uppercase tracking-wider text-dim">
            {t.etiqueta} · {check.area}
          </p>
          <h3 className="mt-0.5 font-semibold text-strong">{check.title}</h3>
        </div>
        <SeverityBadge severity={check.severity} />
      </div>

      <p className="text-sm text-dim">{check.why_manual}</p>

      <ol className="list-decimal space-y-1 pl-5 text-sm leading-relaxed">
        {check.instructions.map((step) => (
          <li key={step}>{step}</li>
        ))}
      </ol>

      <div className="mt-auto flex flex-wrap items-center gap-3 pt-1">
        <a
          href={check.admin_console_url}
          target="_blank"
          rel="noreferrer"
          className="rounded-md border border-ink px-3 py-1.5 text-xs font-semibold text-strong transition hover:bg-ink hover:text-white"
        >
          {t.abrirConsola}
        </a>
        {check.cis_control && (
          <span className="rounded border border-line px-2 py-1 font-mono text-[11px] text-dim">
            {check.cis_control}
          </span>
        )}
      </div>
    </div>
  );
}
