import { useState } from "react";
import { getComponentes } from "../content/componentes";
import { useLang } from "../lib/LangContext";
import type { ScoreBreakdown } from "../types";

/** Point 3: the score has to be auditable, or it cannot be discussed in a
 * meeting. Every row that moved the number, including what was excluded. */
export default function ScoreBreakdownPanel({ breakdown }: { breakdown: ScoreBreakdown }) {
  const [open, setOpen] = useState(false);
  const { lang } = useLang();
  const componentes = getComponentes(lang);
  const t = componentes.desglose;
  const severidad = componentes.insignias.severidad;

  const weights = Object.entries(breakdown.weights)
    .filter(([, weight]) => weight > 0)
    .map(([severity, weight]) => `${severity} ${weight}`)
    .join(", ");

  return (
    <div className="mt-3">
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        // Now that the panel sits on the page background rather than inside
        // the dark hero, this reads on light — and the container below declares
        // its own colour so the rows no longer depend on where it is mounted.
        className="font-mono text-xs text-dim underline hover:text-strong"
      >
        {open ? t.ocultar : t.ver}
      </button>

      {open && (
        // `text-body` on the container, not on each cell. This panel sets its
        // own light background but used to inherit its text colour from
        // whatever it was mounted in — and it is mounted inside the dark hero,
        // so every data row rendered white on white. The header (`text-dim`)
        // and the total (`text-strong`) declared a colour and stayed visible,
        // which is why only the rows in between vanished.
        //
        // A component that owns its background owns its foreground.
        <div className="mt-3 space-y-3 rounded-md border border-line bg-paper p-4 text-body">
          <p className="text-xs leading-relaxed text-dim">
            {t.pesos} {weights}. {t.credito}{" "}
            <strong className="text-strong">{t.ajustesFuerte}</strong>
            {t.ajustesResto}{" "}
            <strong className="text-strong">{t.cuentasFuerte}</strong>
            {t.cuentasResto}
            {typeof breakdown.people_scale === "number" && breakdown.people_scale < 1 && (
              <>
                {" "}
                {t.escala(Math.round(breakdown.people_scale * 100))}
              </>
            )}{" "}
            {t.excluidosNota}
          </p>

          <div className="-mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-line font-mono text-[10px] uppercase text-dim">
                  <th className="py-1.5 pr-3">{t.colElemento}</th>
                  <th className="py-1.5 pr-3">{t.colSeveridad}</th>
                  <th className="py-1.5 pr-3">{t.colEstado}</th>
                  <th className="py-1.5 pr-3 text-right">{t.colPeso}</th>
                  <th className="py-1.5 pr-3 text-right">{t.colObtenido}</th>
                </tr>
              </thead>
              <tbody>
                {breakdown.accounts.map((row) => (
                  <tr key={`a-${row.account}`} className="border-b border-line/60">
                    <td className="py-1.5 pr-3 font-mono">{row.account}</td>
                    <td className="py-1.5 pr-3">{severidad[row.severity]}</td>
                    <td className="py-1.5 pr-3">{t.estado[row.status]}</td>
                    <td className="py-1.5 pr-3 text-right">{row.weight}</td>
                    <td className="py-1.5 pr-3 text-right">{row.earned.toFixed(1)}</td>
                  </tr>
                ))}
                {breakdown.findings.map((row) => (
                  <tr key={`f-${row.id}`} className="border-b border-line/60">
                    <td className="py-1.5 pr-3">{row.title || row.id}</td>
                    <td className="py-1.5 pr-3">{severidad[row.severity]}</td>
                    <td className="py-1.5 pr-3">{t.estado[row.status]}</td>
                    <td className="py-1.5 pr-3 text-right">{row.weight}</td>
                    <td className="py-1.5 pr-3 text-right">{row.earned.toFixed(1)}</td>
                  </tr>
                ))}
                <tr className="font-semibold text-strong">
                  <td className="py-1.5 pr-3">{t.total}</td>
                  <td colSpan={2} />
                  <td className="py-1.5 pr-3 text-right">{breakdown.total_weight}</td>
                  <td className="py-1.5 pr-3 text-right">
                    {breakdown.earned_weight.toFixed(1)}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <p className="font-mono text-xs text-dim">
            {t.formula} = round(100 × {breakdown.earned_weight.toFixed(1)} ÷{" "}
            {breakdown.total_weight}) ={" "}
            <strong className="text-strong">
              {breakdown.score === null ? t.noDisponible : breakdown.score}
            </strong>
          </p>

          {breakdown.excluded.length > 0 && (
            <div>
              <p className="mb-1 font-mono text-[10px] uppercase tracking-wider text-dim">
                {t.excluidos} ({breakdown.excluded.length})
              </p>
              <ul className="space-y-0.5">
                {breakdown.excluded.map((row) => (
                  <li key={row.id} className="text-xs text-dim">
                    <span className="font-mono">{row.id}</span> — {row.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
