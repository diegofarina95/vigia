import { useState } from "react";
import { getComponentes } from "../content/componentes";
import { useLang } from "../lib/LangContext";
import type { PersonAtRisk } from "../types";
import { SeverityBadge } from "./Badges";

/** Findings list accounts one problem at a time; an attacker looks for the ONE
 * account weak in several ways at once. The ranking comes from the backend
 * (scoring.people_at_risk) so the dashboard, the report and the score can never
 * disagree about who is exposed. */
export default function RiskyUsers({ people }: { people: PersonAtRisk[] }) {
  const [expanded, setExpanded] = useState(false);
  const { lang } = useLang();
  const t = getComponentes(lang).personasEnRiesgo;

  if (people.length === 0) return null;

  const visible = expanded ? people : people.slice(0, 8);
  const stacked = people.filter((person) => person.issues.length > 1).length;

  return (
    <section className="rounded-lg border border-line bg-card p-6">
      <div className="mb-1 flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="font-display text-lg font-bold text-strong">
          {t.titulo}{" "}
          <span className="font-mono text-sm font-normal text-dim">({people.length})</span>
        </h2>
        <span className="font-mono text-[11px] text-dim">{t.orden}</span>
      </div>
      <p className="mb-4 text-sm text-dim">
        {stacked > 0 ? (
          <>
            <strong className="text-strong">{stacked}</strong>{" "}
            {stacked === 1 ? t.acumulaUna : t.acumulanVarias}
          </>
        ) : (
          t.ningunaAcumula
        )}{" "}
        {t.informe(people.length)}
      </p>

      <ul className="divide-y divide-line rounded-md border border-line">
        {visible.map((person) => (
          <li key={person.account} className="flex flex-wrap items-center gap-3 px-4 py-2.5">
            <SeverityBadge severity={person.worst} />
            <span className="font-mono text-sm text-strong">{person.account}</span>
            {person.issues.length > 1 && (
              <span className="rounded-full bg-ink px-2 py-0.5 font-mono text-[10px] text-white">
                {person.issues.length} {t.problemas}
              </span>
            )}
            <span className="w-full text-left text-xs text-dim sm:ml-auto sm:w-auto sm:max-w-[55%] sm:text-right">
              {person.issues.map((issue) => issue.title).join(" · ")}
            </span>
          </li>
        ))}
      </ul>

      {people.length > 8 && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="mt-3 text-sm font-semibold text-strong-2 underline"
        >
          {expanded ? t.verMenos : t.verTodas(people.length)}
        </button>
      )}
    </section>
  );
}
