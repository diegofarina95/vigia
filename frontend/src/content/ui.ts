/**
 * Every string the interface prints, in both languages.
 *
 * Typed as `Record<Lang, T>` with one shape per section, so a string missing from
 * one language is a compile error rather than a hole somebody notices in production.
 * That is the whole reason for not reaching for `react-i18next`: a runtime lookup
 * that returns the key when a translation is absent fails silently, and this project
 * has 6 dependencies for a reason.
 *
 * English is BRITISH: organisation, authorise, recognise, enrolment, prioritised.
 * The market is London and Galicia, and `organization` in a security report read by
 * a British administrator is the kind of detail that costs credibility in exactly
 * the audience that notices. `backend/tests/test_bilingue.py` makes that executable
 * for the server-side catalogue.
 *
 * Findings, severities and statuses are NOT here: those live in
 * `backend/vigia/locales/{es,en}.json`, generated from one bilingual table, and
 * arrive already localised because `api.ts` sends `?lang=`. This file is only the
 * chrome the client owns.
 */
import type { Lang } from "../lib/lang";

type Cabecera = {
  panel: string;
  informeEjemplo: string;
  comprobadorDmarc: string;
  privacidad: string;
  conectar: string;
  desconectar: string;
  tenantDemo: string;
  tenantDemoTitulo: string;
  confirmarDesconectar: string;
};

type Pie = {
  lema: string;
  privacidadPermisos: string;
  terminos: string;
  tusDatos: string;
  comprobadorGratis: string;
};

export type Ui = {
  cabecera: Cabecera;
  pie: Pie;
};

const CATALOGO: Record<Lang, Ui> = {
  es: {
    cabecera: {
      panel: "Panel",
      informeEjemplo: "Informe de ejemplo",
      comprobadorDmarc: "Comprobador DMARC",
      privacidad: "Privacidad",
      conectar: "Conectar Workspace",
      desconectar: "Desconectar",
      tenantDemo: "TENANT DEMO",
      tenantDemoTitulo:
        "Los datos de Workspace (usuarios, aplicaciones, auditoría) están simulados " +
        "hasta que se configuren las credenciales de Google OAuth. Las comprobaciones " +
        "de DNS son reales.",
      confirmarDesconectar:
        "¿Desconectar y borrar todos los datos guardados (token e historial de escaneos)?",
    },
    pie: {
      lema:
        "postura de seguridad de solo lectura para Google Workspace. Nunca pedimos " +
        "permisos de contenido de Gmail ni de Drive.",
      privacidadPermisos: "Privacidad y permisos",
      terminos: "Términos del servicio",
      tusDatos: "Tus datos",
      comprobadorGratis: "Comprobador DMARC gratuito",
    },
  },
  en: {
    cabecera: {
      panel: "Dashboard",
      informeEjemplo: "Sample report",
      comprobadorDmarc: "DMARC checker",
      privacidad: "Privacy",
      conectar: "Connect Workspace",
      desconectar: "Disconnect",
      tenantDemo: "DEMO TENANT",
      tenantDemoTitulo:
        "The Workspace data (users, applications, audit log) is simulated until the " +
        "Google OAuth credentials are configured. The DNS checks are real.",
      confirmarDesconectar:
        "Disconnect and delete everything stored (the token and the scan history)?",
    },
    pie: {
      lema:
        "read-only security posture for Google Workspace. We never request Gmail or " +
        "Drive content permissions.",
      privacidadPermisos: "Privacy and permissions",
      terminos: "Terms of service",
      tusDatos: "Your data",
      comprobadorGratis: "Free DMARC checker",
    },
  },
};

export function getUi(lang: Lang): Ui {
  return CATALOGO[lang];
}
