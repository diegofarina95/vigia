import { useLang } from "../lib/LangContext";
import type { Lang } from "../lib/lang";

/**
 * ES | EN, as two segments rather than a cycling button.
 *
 * The theme control cycles because it has three states and one of them ("whatever
 * the system says") has no natural icon. Language has two, and both have a name, so
 * showing both and marking the active one is one fewer thing to work out: the reader
 * sees what they are on and what they would get, without pressing anything.
 *
 * `lang` on each segment matters — without it a screen reader reads "EN" with
 * Spanish phonetics while announcing a control that switches to English.
 */
const ETIQUETA: Record<Lang, { corto: string; largo: Record<Lang, string> }> = {
  es: { corto: "ES", largo: { es: "Español", en: "Spanish" } },
  en: { corto: "EN", largo: { es: "Inglés", en: "English" } },
};

export default function LangToggle() {
  const { lang, setLang } = useLang();

  return (
    <div
      className="inline-flex shrink-0 overflow-hidden rounded-md border border-ink-3"
      role="group"
      aria-label={lang === "es" ? "Idioma de la interfaz" : "Interface language"}
    >
      {(["es", "en"] as Lang[]).map((codigo) => {
        const activo = codigo === lang;
        return (
          <button
            key={codigo}
            type="button"
            lang={codigo}
            onClick={() => setLang(codigo)}
            aria-pressed={activo}
            title={ETIQUETA[codigo].largo[lang]}
            className={`shrink-0 whitespace-nowrap px-2 py-1 font-mono text-[11px] font-semibold transition ${
              activo
                ? "bg-beacon text-strong"
                : "text-mist hover:bg-ink-2 hover:text-white"
            }`}
          >
            {ETIQUETA[codigo].corto}
          </button>
        );
      })}
    </div>
  );
}
