/**
 * The interface language, in one place.
 *
 * Two states, not three. The theme has a `system` option because the operating
 * system already holds an answer worth respecting; language does not work that way
 * here. `routes.py` documents why `Accept-Language` was removed from the server: a
 * Spanish-speaking user in London with an English laptop got a Spanish interface
 * wrapped around English findings and concluded the translation was unfinished. The
 * content was fine; the browser was overriding a choice nobody had made. So the
 * default is Spanish and the only way to change it is to say so.
 *
 * Persisted twice, on purpose, exactly like the theme:
 *  · `localStorage` for the React app, read before the first render;
 *  · the `vigia_lang` cookie, because /privacy, /terms, /connect and the downloaded
 *    report are rendered by Flask. `_requested_lang()` in `api/routes.py` already
 *    reads that cookie — this file exists so the client finally writes it. Until
 *    now nothing did, which is why the panel asked the server for findings and got
 *    them in whatever language a cookie nobody had set happened to imply.
 */
export type Lang = "es" | "en";

export const LANG_KEY = "vigia_lang";

/** Same name and lifetime the server uses. `LANG_COOKIE` in `api/routes.py`. */
const COOKIE = "vigia_lang";
const UN_ANO = 60 * 60 * 24 * 365;

export const DEFAULT_LANG: Lang = "es";

export function isLang(value: unknown): value is Lang {
  return value === "es" || value === "en";
}

export function storedLang(): Lang {
  try {
    const raw = window.localStorage.getItem(LANG_KEY);
    if (isLang(raw)) return raw;
  } catch {
    /* private mode: fall through to the cookie */
  }
  const match = document.cookie.match(/(?:^|;\s*)vigia_lang=([^;]+)/);
  return isLang(match?.[1]) ? (match![1] as Lang) : DEFAULT_LANG;
}

export function saveLang(lang: Lang): void {
  try {
    window.localStorage.setItem(LANG_KEY, lang);
  } catch {
    /* the cookie below still carries the choice */
  }
  // No `Secure` flag: the app is also served over plain HTTP on the tailnet. The
  // value is a display preference with no identifier in it.
  document.cookie = `${COOKIE}=${lang}; path=/; max-age=${UN_ANO}; samesite=lax`;
}

/** Keeps `<html lang>` honest, which screen readers and translators both read. */
export function applyLang(lang: Lang): void {
  document.documentElement.lang = lang;
}
