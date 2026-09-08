import { useEffect, useState } from "react";
import { Link, NavLink, Route, Routes, useNavigate } from "react-router-dom";
import { api } from "./api";
import { APP_PREFIX } from "./prefix";
import type { Me } from "./types";
import Dashboard from "./pages/Dashboard";
import DmarcChecker from "./pages/DmarcChecker";
import Landing from "./pages/Landing";
import ThemeToggle from "./components/ThemeToggle";
import LangToggle from "./components/LangToggle";
import { useLang } from "./lib/LangContext";
import { getUi } from "./content/ui";

/**
 * The mark, then the name.
 *
 * The mark is a raster served from `public/`, not an inline SVG: it is a shield with
 * a gradient rim and modelled binoculars, and tracing it would mean redrawing the
 * artwork rather than using it. Shipped at 4x (98x112) so it stays crisp on hidpi.
 *
 * The URL carries `APP_PREFIX` rather than being relative. Relative would work here
 * by accident — the header only renders once React has run, and the inline `<base>`
 * script in index.html has run by then — but it breaks the moment a route gains a
 * trailing slash, and being explicit costs nothing.
 *
 * The name stays live text, not part of the image: it has to match the OAuth consent
 * screen's App name character for character, and text is greppable, translatable and
 * selectable in a way that pixels are not.
 */
function Logo() {
  return (
    <Link to="/" className="flex items-center gap-2">
      <img
        src={`${APP_PREFIX}/marca-vigia.png`}
        alt=""
        aria-hidden
        width={25}
        height={28}
        className="h-7 w-auto"
      />
      <span className="font-display text-lg font-bold tracking-tight text-white">Vigía</span>
    </Link>
  );
}

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const navigate = useNavigate();
  const { lang } = useLang();
  const t = getUi(lang);

  useEffect(() => {
    api.me().then(setMe).catch(() => setMe({ connected: false, mock_mode: false }));
  }, []);

  async function disconnect() {
    if (!window.confirm(t.cabecera.confirmarDesconectar)) return;
    await api.disconnect();
    setMe({ connected: false, mock_mode: me?.mock_mode ?? false });
    navigate("/");
  }

  const navLink = ({ isActive }: { isActive: boolean }) =>
    `rounded px-2.5 py-1.5 text-sm transition ${
      isActive ? "bg-ink-2 text-white" : "text-mist hover:text-white"
    }`;

  return (
    <div className="flex min-h-screen flex-col">
      <header className="bg-ink">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
          <Logo />
          <nav className="ml-4 flex items-center gap-1">
            {me?.connected && (
              <NavLink to="/dashboard" className={navLink}>
                {t.cabecera.panel}
              </NavLink>
            )}
            <NavLink to="/demo" className={navLink}>
              {t.cabecera.informeEjemplo}
            </NavLink>
            <NavLink to="/dmarc-checker" className={navLink}>
              {t.cabecera.comprobadorDmarc}
            </NavLink>
            {/* A plain anchor, not a NavLink: the legal pages are rendered
                by the server so a person and Google's crawler read the same
                document. Client-side routing would bypass it. */}
            <a href={`${APP_PREFIX}/privacy`} className={navLink({ isActive: false })}>
              {t.cabecera.privacidad}
            </a>
          </nav>
          <div className="ml-auto flex items-center gap-3">
            <LangToggle />
            <ThemeToggle />
            {me?.mock_mode && (
              <span
                className="rounded bg-beacon/20 px-2 py-1 font-mono text-[11px] text-beacon"
                title={t.cabecera.tenantDemoTitulo}
              >
                {t.cabecera.tenantDemo}
              </span>
            )}
            {me?.connected && me.org ? (
              <>
                <span className="hidden font-mono text-xs text-mist sm:inline">{me.org.domain}</span>
                <button
                  onClick={disconnect}
                  className="rounded border border-ink-3 px-2.5 py-1.5 text-xs text-mist transition hover:border-mist hover:text-white"
                >
                    {t.cabecera.desconectar}
                </button>
              </>
            ) : (
              <a
                href={`${APP_PREFIX}/api/auth/google/start`}
                className="rounded-md bg-beacon px-3 py-1.5 text-sm font-semibold text-strong transition hover:bg-beacon/90"
              >
                {t.cabecera.conectar}
              </a>
            )}
          </div>
        </div>
      </header>

      <main className="flex-1">
        <Routes>
          <Route path="/" element={<Landing connected={me?.connected ?? false} />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/dmarc-checker" element={<DmarcChecker />} />
          <Route path="/demo" element={<Dashboard demo />} />
        </Routes>
      </main>

      <footer className="bg-ink py-8 text-mist">
        <div className="mx-auto flex max-w-5xl flex-col gap-2 px-4 text-sm">
          <p>
            <span className="font-display font-bold text-white">Vigía</span> —{" "}
            {t.pie.lema}
          </p>
          <p className="flex flex-wrap gap-x-4 gap-y-2 font-mono text-xs [&>*]:whitespace-nowrap">
            <a href={`${APP_PREFIX}/privacy`} className="hover:text-white">
              {t.pie.privacidadPermisos}
            </a>
            <a href={`${APP_PREFIX}/terms`} className="hover:text-white">
              {t.pie.terminos}
            </a>
            <a href={`${APP_PREFIX}/help/data`} className="hover:text-white">
              {t.pie.tusDatos}
            </a>
            <Link to="/dmarc-checker" className="hover:text-white">
              {t.pie.comprobadorGratis}
            </Link>
          </p>
        </div>
      </footer>
    </div>
  );
}
