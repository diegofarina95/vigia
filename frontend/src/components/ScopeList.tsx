import { SCOPES } from "../generated/scopes";
import { useLang } from "../lib/LangContext";

/**
 * The scopes, read from the generated definition rather than typed here.
 *
 * This component used to hold its own copy of the list — the sixth in the project,
 * counting the authorization request, the privacy policy, the homepage's
 * no-JavaScript block and Google Cloud Console. All six agreed about which scopes
 * were requested and disagreed about how each one was described, which is the kind
 * of difference a reviewer at Google notices and a reader has no way to resolve.
 *
 * `generated/scopes.ts` comes from `backend/vigia/scopes.py`, the same definition
 * that builds the authorization request, so the identifier shown here is by
 * construction the identifier asked for. Do not add a scope to this file.
 *
 * The descriptions are already bilingual in the generated file, so the only thing
 * this component decides is which column to read. It used to take a `lang` prop that
 * nobody ever passed — meaning the list stayed Spanish in an English page — and now
 * asks the language context, like every other component.
 */
export default function ScopeList({ onInk = false }: { onInk?: boolean }) {
  const { lang } = useLang();

  return (
    <ul className="space-y-3">
      {SCOPES.map((s) => (
        <li key={s.id} className="flex flex-col gap-0.5">
          <code
            className={`font-mono text-[13px] font-medium ${
              onInk ? "text-beacon" : "text-strong-2"
            }`}
          >
            {s.corto}
          </code>
          <span className={`text-sm ${onInk ? "text-mist" : "text-dim"}`}>{s.lee[lang]}</span>
        </li>
      ))}
    </ul>
  );
}
