import { Link, useSearchParams } from "react-router-dom";
import ScopeList from "../components/ScopeList";
import { getLanding } from "../content/landing";
import { useLang } from "../lib/LangContext";
import type { Lang } from "../lib/lang";
import { APP_PREFIX } from "../prefix";

/**
 * One list, because there is one tier.
 *
 * This was two columns, Gratis and Pro, ending in "el pago abre pronto; el control
 * de acceso ya está funcionando". Three things were wrong with it by the time it
 * was removed:
 *
 *  • There is no Pro. The plan concept was deleted from the backend, not gated —
 *    `test_nothing_is_behind_a_paywall` asserts every route stays open — so the
 *    sentence about access control already working was false.
 *  • Half the Pro list was already free: full findings detail, history, PDF.
 *  • "Escaneos periódicos automáticos" was taken off the product, and "vista
 *    multiempresa (para MSP)" never existed. Selling either would be selling
 *    something that cannot be delivered, to an audience whose whole reason for
 *    reading is deciding whether to trust me.
 *
 * What is paid is the remediation, by email, with the report in front of us. That
 * is a person's time, not a feature flag.
 */

/**
 * The three sentences pinned to THIS file, in both languages.
 *
 * Everything else this page prints moved to `content/landing.ts` — including the
 * list the comment above describes, now `precio.incluido`. These three did not,
 * and the reason is not aesthetic: three Python tests read `Landing.tsx` as raw
 * text, because no Python import can reach a React component.
 *
 *  · `claim` — `test_readonly_wording.py::test_surface_4_the_react_landing`
 *    asserts `READ_ONLY_CLAIM` from `backend/vigia/wording.py` appears here, so
 *    that the four surfaces stating the read-only promise cannot drift apart. It
 *    strips tags and collapses whitespace, so the Spanish sentence has to be ONE
 *    literal: split across `"…" + "…"` the way the catalogue wraps its long
 *    strings, the test fails. Long line on purpose — do not reflow it, and edit
 *    it in `wording.py` and copy the text rather than rewriting it here.
 *  · `precioTitulo` and `precioCuerpo` —
 *    `test_routes_smoke.py::test_the_landing_does_not_advertise_a_tier_that_does_not_exist`
 *    asserts "El análisis es gratis" and "no hay tarjeta" are here, so that
 *    deleting the free-tier block counts as a failure rather than a tidy-up. It
 *    strips block comments first, so a comment would not satisfy it — and should
 *    not: the point is what the page SHOWS.
 *
 * So the pin is a constraint from the test suite, not a translation exception:
 * the English half lives here beside the Spanish for the same three keys, which
 * is why `content/landing.ts` marks the two gaps in `Confianza` and `Precio`.
 */
type Ancladas = {
  claim: string;
  precioTitulo: string;
  precioCuerpo: string;
};

const ANCLADAS: Record<Lang, Ancladas> = {
  es: {
    claim: "Vigía nunca ha solicitado permisos de Gmail, Drive ni ningún otro permiso restringido, así que no puede leer el contenido de mensajes ni de archivos: lo impide la propia API de Google, no solo nuestra política.",
    precioTitulo: "El análisis es gratis. Todo el análisis.",
    precioCuerpo:
      "No hay niveles, no hay funciones bloqueadas y no hay tarjeta. Nada de lo que " +
      "Vigía calcula se guarda detrás de un muro de pago: si una comprobación " +
      "encuentra algo, lo ves entero.",
  },
  en: {
    claim:
      "Vigía has never requested Gmail, Drive or any other restricted permission, so " +
      "it cannot read the content of messages or files: Google's own API prevents " +
      "it, not just our policy.",
    precioTitulo: "The analysis is free. All of the analysis.",
    precioCuerpo:
      "There are no tiers, no locked features and no card. Nothing Vigía works out " +
      "is kept behind a paywall: if a check finds something, you see all of it.",
  },
};

export default function Landing({ connected }: { connected: boolean }) {
  const [params] = useSearchParams();
  const error = params.get("error");
  const { lang } = useLang();
  const t = getLanding(lang);
  const anclado = ANCLADAS[lang];

  return (
    <div>
      {/* Hero — la guardia nocturna */}
      <section className="relative overflow-hidden bg-ink">
        <div
          className="radar-sweep pointer-events-none absolute -top-64 left-1/2 h-[56rem] w-[56rem] -translate-x-1/2 rounded-full"
          aria-hidden
        />
        <div className="relative mx-auto max-w-5xl px-4 py-20 sm:py-28">
          {error && (
            <div className="mb-8 rounded-md border border-sev-critical/60 bg-sev-critical/15 px-4 py-3 text-sm text-white">
              {t.errores.porCodigo[error] ?? t.errores.generico}
            </div>
          )}
          {/* The app name leads, because Google's OAuth verification compares the
              name on this page against the "App name" field on the consent screen
              and rejected the app once for not finding a match. It used to say only
              "Google Workspace · solo lectura", which left the name to the header
              logo, the <title> and body prose — none of them where a reviewer looks
              first. Keep this string spelled exactly as the consent screen. */}
          <p className="font-mono text-xs font-medium uppercase tracking-[0.25em] text-beacon">
            {t.hero.marca}
          </p>
          <h1 className="font-display mt-4 max-w-3xl text-4xl font-extrabold leading-tight text-white sm:text-6xl">
            {t.hero.titular}
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-relaxed text-mist">
            {t.hero.entradilla}
          </p>
          <div className="mt-9 flex flex-wrap items-center gap-4">
            {connected ? (
              <Link
                to="/dashboard"
                className="rounded-md bg-beacon px-6 py-3 font-semibold text-strong transition hover:bg-beacon/90"
              >
                {t.hero.irAlPanel}
              </Link>
            ) : (
              <a
                href={`${APP_PREFIX}/connect`}
                className="rounded-md bg-beacon px-6 py-3 font-semibold text-strong transition hover:bg-beacon/90"
              >
                {t.hero.conectar}
              </a>
            )}
            <span className="font-mono text-xs text-mist">{t.hero.sinTarjeta}</span>
          </div>
        </div>
      </section>

      {/* Confianza: los permisos exactos, antes del consentimiento */}
      <section className="border-b border-line bg-card">
        <div className="mx-auto grid max-w-5xl gap-10 px-4 py-16 md:grid-cols-2">
          <div>
            <h2 className="font-display text-2xl font-bold text-strong">
              {t.confianza.titulo}
            </h2>
            {/* The canonical wording, verbatim. This claim existed in four
                different phrasings across the report, the two privacy pages and
                this file — all true, all worded differently, which is what makes
                a product look assembled by somebody not paying attention. It is
                also the sentence that decides whether an administrator hands over
                super-admin access at all.

                Source of truth: `backend/vigia/wording.py::READ_ONLY_CLAIM`.
                `tests/test_readonly_wording.py` reads THIS file and fails if the
                text drifts, so edit it there and not here. */}
            <p className="mt-4 leading-relaxed">
              <strong>{t.confianza.soloLecturaLead}</strong> {anclado.claim}
            </p>
            <p className="mt-3 leading-relaxed">
              {t.confianza.sinEscrituraA}{" "}
              <strong>{t.confianza.comprobacionManual}</strong>
              {t.confianza.sinEscrituraB}
            </p>
            <a href={`${APP_PREFIX}/privacy`} className="mt-4 inline-block text-sm font-semibold text-strong-2 underline">
              {t.confianza.enlacePrivacidad}
            </a>
          </div>
          <div className="rounded-lg border border-line bg-paper p-6">
            <p className="mb-4 font-mono text-[11px] font-semibold uppercase tracking-wider text-dim">
              {t.confianza.etiquetaPermisos}
            </p>
            <ScopeList />
          </div>
        </div>
      </section>

      {/* Qué cubre un escaneo */}
      <section className="mx-auto max-w-5xl px-4 py-16">
        <h2 className="font-display text-2xl font-bold text-strong">
          {t.comprobaciones.titulo}
        </h2>
        <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {t.comprobaciones.lista.map(([title, blurb]) => (
            <div key={title} className="rounded-lg border border-line bg-card p-5">
              <h3 className="font-semibold text-strong">{title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-dim">{blurb}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Un solo nivel: todo incluido */}
      <section className="border-y border-line bg-card">
        <div className="mx-auto max-w-3xl px-4 py-16">
          <h2 className="font-display text-2xl font-bold text-strong">
            {anclado.precioTitulo}
          </h2>
          <p className="mt-3 text-sm leading-relaxed text-dim">{anclado.precioCuerpo}</p>
          <ul className="mt-6 grid gap-2 text-sm sm:grid-cols-2">
            {t.precio.incluido.map((feature) => (
              <li key={feature} className="flex gap-2">
                <span className="text-ok" aria-hidden="true">
                  ✓
                </span>
                <span>{feature}</span>
              </li>
            ))}
          </ul>
          <p className="mt-6 rounded-md border border-line bg-paper p-4 text-sm leading-relaxed text-body">
            {t.precio.remediacion}
          </p>
        </div>
      </section>

      {/* Gancho de la herramienta gratuita */}
      <section className="mx-auto max-w-5xl px-4 py-16">
        <div className="flex flex-col items-start gap-4 rounded-lg bg-ink p-8 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="font-display text-xl font-bold text-white">
              {t.dmarc.titulo}
            </h2>
            <p className="mt-1 text-sm text-mist">{t.dmarc.entradilla}</p>
          </div>
          <Link
            to="/dmarc-checker"
            className="shrink-0 rounded-md bg-beacon px-5 py-2.5 font-semibold text-strong transition hover:bg-beacon/90"
          >
            {t.dmarc.boton}
          </Link>
        </div>
      </section>
    </div>
  );
}
