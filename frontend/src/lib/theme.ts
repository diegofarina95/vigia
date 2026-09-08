/**
 * The theme, in one place.
 *
 * Three states, not two: `system` is the default and the only honest one for a
 * first visit — the reader has already told their operating system what they
 * want and being asked again is the app second-guessing them. `light` and `dark`
 * are explicit overrides that survive reloads.
 *
 * Persisted twice on purpose:
 *  · `localStorage` for the app itself, read before first paint by the inline
 *    script in index.html so nothing flashes;
 *  · a `vigia_theme` cookie, because /privacy, /terms, /connect and /help/data
 *    are rendered by Flask, not by React. Without the cookie a reader who chose
 *    dark would click "Privacidad" and land on a white page — which is exactly
 *    the discontinuity this whole change exists to remove.
 *
 * The cookie carries the choice only. `system` sends no cookie at all, so the
 * server-rendered pages fall back to their own `prefers-color-scheme` query and
 * the two halves still agree.
 */
export type Theme = "system" | "light" | "dark";

export const THEME_KEY = "vigia_theme";
const COOKIE = "vigia_theme";

export function isTheme(value: unknown): value is Theme {
  return value === "system" || value === "light" || value === "dark";
}

export function storedTheme(): Theme {
  try {
    const raw = window.localStorage.getItem(THEME_KEY);
    return isTheme(raw) ? raw : "system";
  } catch {
    return "system";
  }
}

export function systemPrefersDark(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

/** What the page should actually render, once `system` is resolved. */
export function resolveTheme(theme: Theme): "light" | "dark" {
  if (theme === "system") return systemPrefersDark() ? "dark" : "light";
  return theme;
}

/** Writes the class the `dark:` variant and the `.dark` token block key off. */
export function applyTheme(theme: Theme): void {
  const efectivo = resolveTheme(theme);
  document.documentElement.classList.toggle("dark", efectivo === "dark");
  document.documentElement.style.colorScheme = efectivo;
}

export function saveTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* private mode: the choice lasts for this page, which is better than throwing */
  }

  // A year, SameSite=Lax, no Secure flag so it also works over plain HTTP on the
  // tailnet. It carries a display preference and nothing else; there is no
  // identifier in it, which is why it does not make the "no tracking cookies"
  // statement false — but the privacy page says so explicitly rather than
  // leaving the reader to take that on trust.
  const base = `${COOKIE}=; path=/; max-age=0; samesite=lax`;
  if (theme === "system") {
    document.cookie = base;
    return;
  }
  document.cookie = `${COOKIE}=${theme}; path=/; max-age=31536000; samesite=lax`;
}
