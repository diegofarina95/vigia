import { getComponentes } from "../content/componentes";
import { useLang } from "../lib/LangContext";
import type { RemediationAction } from "../types";

/** Point 2: the report used to say what was wrong and leave the triage to the
 * reader. This block answers "what do I do first?" — ranked by findings closed
 * per minute of work, with every number derived from the finding→action graph. */
export default function FixFirst({ actions }: { actions: RemediationAction[] }) {
  const { lang } = useLang();
  const componentes = getComponentes(lang);
  const t = componentes.arreglaPrimero;
  // The severity words come from the badge vocabulary, so "critical" reads the same
  // here as it does on the badge of the finding this action closes.
  const severidad = componentes.insignias.severidad;

  if (actions.length === 0) return null;

  return (
    <section className="rounded-lg border-2 border-ink bg-card p-6">
      <h2 className="font-display text-lg font-bold text-strong">{t.titulo}</h2>
      <p className="mb-4 max-w-2xl text-sm text-dim">{t.intro}</p>

      <ol className="space-y-4">
        {actions.map((action, index) => (
          <li
            key={action.id}
            className={
              index === 0
                ? "rounded-md border-2 border-ink bg-paper p-4"
                : "rounded-md border border-line p-4"
            }
          >
            <div className="flex flex-wrap items-baseline gap-2">
              <span
                className={
                  index === 0
                    ? "rounded bg-ink px-1.5 py-0.5 font-mono text-[10px] font-bold tracking-wider text-beacon"
                    : "font-mono text-[11px] font-bold tracking-wider text-dim"
                }
              >
                {index === 0 ? t.empiezaAqui : `${t.accion} ${index + 1}`}
              </span>
              <h3
                className={
                  index === 0
                    ? "flex-1 font-display text-base font-bold text-strong"
                    : "flex-1 font-semibold text-strong"
                }
              >
                {action.title}
              </h3>
              <span className="font-mono text-[11px] text-dim">~{action.minutes} min</span>
            </div>

            <p className="mt-1 font-mono text-xs text-dim">{action.console_path}</p>

            <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 rounded bg-paper px-3 py-2 text-sm">
              <span>
                <strong className="text-strong">{action.findings_closed}</strong>{" "}
                {action.findings_closed === 1 ? t.hallazgoCerrado : t.hallazgosCerrados}
                {(action.criticals_closed > 0 || action.highs_closed > 0) && (
                  <span className="text-dim">
                    {" ("}
                    {action.criticals_closed > 0 &&
                      `${action.criticals_closed} ${severidad.critical}`}
                    {action.criticals_closed > 0 && action.highs_closed > 0 && ", "}
                    {action.highs_closed > 0 && `${action.highs_closed} ${severidad.high}`}
                    {")"}
                  </span>
                )}
              </span>
              <span>
                <strong className="text-strong">{action.accounts_affected}</strong>{" "}
                {action.accounts_affected === 1 ? t.cuentaAfectada : t.cuentasAfectadas}
              </span>
              {action.score_gain > 0 && (
                <span className="text-ok">
                  {t.puntuacion} <strong>+{action.score_gain}</strong>
                </span>
              )}
            </div>

            {action.user_impact && (
              <p className="mt-3 border-l-4 border-sev-medium bg-sev-medium/10 px-3 py-2 text-xs leading-relaxed">
                <strong>{t.avisoUsuarios}</strong> {action.user_impact}
              </p>
            )}

            <div className="mt-3 flex flex-wrap items-center gap-3">
              <a
                href={action.console_url}
                target="_blank"
                rel="noreferrer"
                className={
                  index === 0
                    ? "rounded-md bg-beacon px-4 py-2 text-xs font-bold text-strong transition hover:bg-beacon/90"
                    : "rounded-md bg-ink px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-ink-2"
                }
              >
                {t.abrirConsola}
              </a>
              <span className="text-xs text-dim">
                {t.cierra} {action.finding_titles.slice(0, 3).join(" · ")}
                {action.finding_titles.length > 3 && ` +${action.finding_titles.length - 3}`}
              </span>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
