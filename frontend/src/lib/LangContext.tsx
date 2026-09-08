import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { DEFAULT_LANG, applyLang, saveLang, storedLang, type Lang } from "./lang";

/**
 * One language for the whole tree, so no component decides on its own.
 *
 * Deliberately a context rather than a prop threaded down: `ScopeList` already
 * accepted a `lang` prop and nobody ever passed it, which is what a prop for a
 * page-wide concern turns into. A component that needs the language asks for it.
 */
type Contexto = {
  lang: Lang;
  setLang: (lang: Lang) => void;
};

const LangCtx = createContext<Contexto>({ lang: DEFAULT_LANG, setLang: () => {} });

export function LangProvider({ children }: { children: React.ReactNode }) {
  const [lang, setEstado] = useState<Lang>(DEFAULT_LANG);

  // Read after mount, not during render: `storedLang` touches `localStorage` and
  // `document.cookie`, and the first paint must not depend on either.
  useEffect(() => {
    const guardado = storedLang();
    setEstado(guardado);
    applyLang(guardado);
  }, []);

  const setLang = useCallback((siguiente: Lang) => {
    setEstado(siguiente);
    saveLang(siguiente);
    applyLang(siguiente);
  }, []);

  const valor = useMemo(() => ({ lang, setLang }), [lang, setLang]);
  return <LangCtx.Provider value={valor}>{children}</LangCtx.Provider>;
}

export function useLang(): Contexto {
  return useContext(LangCtx);
}
