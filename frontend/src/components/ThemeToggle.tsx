import { useEffect, useState } from "react";
import {
  applyTheme,
  saveTheme,
  storedTheme,
  systemPrefersDark,
  type Theme,
} from "../lib/theme";

/**
 * Three states in one control, cycled in the order a reader expects: system →
 * light → dark → system.
 *
 * A two-state switch would have to guess what "off" means on a first visit, and
 * guessing against the operating system's answer is the one thing a theme control
 * must not do. The label always says which state is active, so the button is
 * legible to somebody who cannot see the icon at all.
 *
 * It also listens to the system while set to `system`: a reader whose OS flips at
 * sunset gets the app flipping with it, without a reload.
 */
const SIGUIENTE: Record<Theme, Theme> = {
  system: "light",
  light: "dark",
  dark: "system",
};

const ETIQUETA: Record<Theme, string> = {
  system: "Tema: el del sistema",
  light: "Tema: claro",
  dark: "Tema: oscuro",
};

export default function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>("system");

  // The inline script in index.html already wrote the class before paint; this
  // only brings React's state into agreement with it.
  useEffect(() => {
    setTheme(storedTheme());
  }, []);

  // While on `system`, follow the operating system live.
  useEffect(() => {
    if (theme !== "system" || typeof window.matchMedia !== "function") return;
    const consulta = window.matchMedia("(prefers-color-scheme: dark)");
    const alCambiar = () => applyTheme("system");
    consulta.addEventListener("change", alCambiar);
    return () => consulta.removeEventListener("change", alCambiar);
  }, [theme]);

  function cambiar() {
    const siguiente = SIGUIENTE[theme];
    setTheme(siguiente);
    saveTheme(siguiente);
    applyTheme(siguiente);
  }

  const efectivo = theme === "system" ? (systemPrefersDark() ? "dark" : "light") : theme;

  return (
    <button
      type="button"
      onClick={cambiar}
      aria-label={`${ETIQUETA[theme]}. Pulsa para cambiar a: ${ETIQUETA[SIGUIENTE[theme]].replace("Tema: ", "")}`}
      title={ETIQUETA[theme]}
      className="inline-flex h-9 w-9 items-center justify-center rounded-md text-mist transition-colors hover:bg-ink-3/40 hover:text-white"
    >
      <Icono estado={theme} efectivo={efectivo} />
    </button>
  );
}

/** Drawn, one stroke weight, no emoji: sun, moon, and a half-filled disc for
 *  "whatever the system says". */
function Icono({ estado, efectivo }: { estado: Theme; efectivo: "light" | "dark" }) {
  const comun = {
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    className: "h-[18px] w-[18px]",
    "aria-hidden": true,
  };

  if (estado === "system") {
    return (
      <svg {...comun}>
        <circle cx="12" cy="12" r="8" />
        <path d="M12 4a8 8 0 0 0 0 16z" fill="currentColor" stroke="none" />
      </svg>
    );
  }
  if (efectivo === "dark") {
    return (
      <svg {...comun}>
        <path d="M20 14.5A8.5 8.5 0 1 1 9.5 4a6.8 6.8 0 0 0 10.5 10.5z" />
      </svg>
    );
  }
  return (
    <svg {...comun}>
      <circle cx="12" cy="12" r="4.2" />
      <path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M18.4 5.6L17 7M7 17l-1.4 1.4" />
    </svg>
  );
}
