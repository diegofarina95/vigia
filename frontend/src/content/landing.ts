/**
 * Every string the landing page prints, in both languages.
 *
 * Same shape and same reasoning as `content/ui.ts`: `Record<Lang, T>` with one
 * type per section, so a string missing from one language is a compile error
 * rather than a hole somebody notices in production.
 *
 * English is BRITISH: organisation, authorise, recognise, prioritised, licence.
 * This is the first page a British administrator reads before deciding whether to
 * hand a stranger's tool super-admin access, and `organization` there is the kind
 * of detail that costs credibility in exactly the audience that notices.
 *
 * Nothing here says more than the Spanish said. The page is the sales surface of
 * a security product, so an English sentence that promises a capability the
 * Spanish one did not is not a style slip, it is a false claim — and half of this
 * page exists to explain what Vigía deliberately cannot do.
 *
 * Findings, severities and statuses are NOT here: those arrive already localised
 * from `backend/vigia/locales/{es,en}.json` because `api.ts` sends `?lang=`.
 *
 * THREE STRINGS ARE MISSING FROM THIS FILE ON PURPOSE — the canonical read-only
 * claim and the two pricing texts. They are pinned inside `pages/Landing.tsx`
 * because the Python suite reads that file as raw text and cannot follow an
 * import. See `ANCLADAS` there; the gaps are marked in `Confianza` and `Precio`.
 */
import type { Lang } from "../lib/lang";

type Errores = {
  /**
   * Keyed by the `?error=` code the OAuth callback redirects with. Codes are
   * identifiers, not prose: they are the same in both languages.
   */
  porCodigo: Record<string, string>;
  /** For a code this catalogue does not know. */
  generico: string;
};

type Hero = {
  /**
   * The app name leads, and it is NOT translated: Google's OAuth verification
   * compares the name on this page against the "App name" field on the consent
   * screen, and rejected the app once for not finding a match. Only the
   * "read-only" descriptor after it changes language.
   */
  marca: string;
  titular: string;
  entradilla: string;
  irAlPanel: string;
  conectar: string;
  sinTarjeta: string;
};

type Confianza = {
  titulo: string;
  /**
   * The lead-in of the canonical claim — `READ_ONLY_LEAD` in
   * `backend/vigia/wording.py`. The claim itself is NOT here: see `ANCLADAS` in
   * `pages/Landing.tsx`.
   */
  soloLecturaLead: string;
  /** Split in three because `comprobacionManual` is bold mid-sentence. */
  sinEscrituraA: string;
  comprobacionManual: string;
  sinEscrituraB: string;
  enlacePrivacidad: string;
  etiquetaPermisos: string;
};

type Comprobaciones = {
  titulo: string;
  /** `[title, blurb]`, in the order they are printed. */
  lista: [string, string][];
};

type Precio = {
  /**
   * The heading and the body paragraph are NOT here — `test_routes_smoke.py`
   * reads them out of `pages/Landing.tsx`. See `ANCLADAS` there.
   */
  incluido: string[];
  remediacion: string;
};

type Dmarc = {
  titulo: string;
  entradilla: string;
  boton: string;
};

export type Landing = {
  errores: Errores;
  hero: Hero;
  confianza: Confianza;
  comprobaciones: Comprobaciones;
  precio: Precio;
  dmarc: Dmarc;
};

const CATALOGO: Record<Lang, Landing> = {
  es: {
    errores: {
      porCodigo: {
        consent_denied:
          "Has cancelado la pantalla de consentimiento de Google. No se ha conectado nada.",
        state_mismatch:
          "El proceso de inicio de sesión ha caducado. Vuelve a intentar la conexión.",
        missing_code: "Google no ha devuelto un código de autorización. Inténtalo otra vez.",
        token_exchange:
          "No se ha podido canjear el código de autorización con Google. Inténtalo otra vez.",
        no_refresh_token:
          "Google no ha emitido un token de refresco. Quita el permiso anterior en myaccount.google.com/permissions y vuelve a conectar.",
        identity: "No se ha podido leer tu identidad desde Google. Inténtalo otra vez.",
        not_workspace:
          "Esa es una cuenta personal de Google. Conéctate con una cuenta de administrador de Google Workspace.",
        not_admin:
          "Esa cuenta no puede leer los datos de todo el dominio. Conéctate con un superadministrador (o un administrador delegado con permisos de lectura de Usuarios e Informes).",
        google_api:
          "La API de Google ha dado un error durante la configuración. Inténtalo en un minuto.",
        not_configured:
          "Este servidor todavía no tiene credenciales de Google OAuth configuradas (mira el README).",
      },
      generico: "Algo ha ido mal durante el inicio de sesión. Inténtalo otra vez.",
    },
    hero: {
      marca: "Vigía · Google Workspace · solo lectura",
      titular: "Alguien debería estar vigilando tu Workspace.",
      entradilla:
        "Vigía se conecta en modo solo lectura, busca las malas configuraciones que los " +
        "atacantes usan de verdad —administradores sin 2FA, permisos OAuth peligrosos, cuentas " +
        "dormidas, DMARC ausente— y te entrega una puntuación con una lista de arreglos " +
        "ordenada por prioridad.",
      irAlPanel: "Ir a tu panel →",
      conectar: "Conecta tu Google Workspace — solo lectura",
      sinTarjeta: "Gratis · sin tarjeta · permisos de solo lectura",
    },
    confianza: {
      titulo: "No podemos leer tu correo. Nunca lo pedimos.",
      soloLecturaLead: "Solo lectura por diseño.",
      sinEscrituraA:
        "La aplicación tampoco puede cambiar ningún ajuste: no existe una ruta de escritura " +
        "en el código. Lo que no se puede leer con estos permisos aparece como",
      comprobacionManual: "comprobación manual",
      sinEscrituraB: ", con instrucciones paso a paso.",
      enlacePrivacidad: "Leer la política de privacidad completa",
      etiquetaPermisos: "Los permisos exactos que verás en la pantalla de Google",
    },
    comprobaciones: {
      titulo: "Un escaneo, toda la lista de vigilancia",
      lista: [
        [
          "Superadmin sin 2FA y sin usar",
          "El hallazgo que nadie más cruza: una cuenta con control total, sin segundo factor y que nunca se ha usado es una puerta trasera permanente que nadie va a detectar.",
        ],
        [
          "Verificación en dos pasos",
          "Administradores y usuarios sin segundo factor: la vía número uno para el robo de cuentas.",
        ],
        [
          "Cuentas comprometidas",
          "Contraseñas filtradas, secuestros y ataques que Google ya ha detectado, más las ráfagas de intentos fallidos.",
        ],
        [
          "Superadministradores de más",
          "Cuánta gente tiene las llaves de todo (el objetivo son 2-4).",
        ],
        [
          "Cuentas dormidas y sin estrenar",
          "Cuentas habilitadas que nadie ha usado en más de 90 días, o nunca.",
        ],
        [
          "Aplicaciones de terceros de riesgo",
          "Apps con permisos sobre Gmail, Drive o administración, cuántos usuarios las han autorizado y las delegaciones en todo el dominio.",
        ],
        [
          "Ajustes de la consola",
          "Uso compartido de Drive, reenvío de Gmail, política de contraseñas, duración de sesión, Marketplace y Grupos, leídos automáticamente.",
        ],
        [
          "Autenticación del correo",
          "SPF, DKIM y DMARC en cada dominio, con el registro real y el límite de 10 consultas del RFC 7208.",
        ],
        [
          "Cifrado en tránsito e integridad del DNS",
          "MTA-STS, TLS-RPT y DNSSEC: lo que impide que alguien degrade o falsifique tu correo.",
        ],
      ],
    },
    precio: {
      incluido: [
        "Puntuación de postura (0-100), auditable línea a línea",
        "Detalle completo de todos los hallazgos, sin recortes",
        "Cuentas afectadas y recuento por severidad",
        "SPF, DKIM, DMARC, MTA-STS, TLS-RPT y DNSSEC en todos tus dominios",
        "Informe en PDF y exportación a CSV",
        "Historial de escaneos y comparación con el anterior",
        "Guía de las comprobaciones que hay que hacer a mano",
      ],
      remediacion:
        "Lo que se paga es arreglarlo, si quieres que lo arregle yo: repasamos el " +
        "informe hallazgo por hallazgo, toco lo crítico y lo alto en tu Consola de " +
        "Administración contigo delante, y te queda documentado qué cambió y por qué. " +
        "Eso se habla por correo con el informe encima de la mesa, y te digo claro si no " +
        "me necesitas.",
    },
    dmarc: {
      titulo: "¿Tu dominio está protegido contra la suplantación?",
      entradilla:
        "Comprueba SPF, DKIM y DMARC en cualquier dominio: gratis, sin registro, al instante.",
      boton: "Abrir el comprobador DMARC",
    },
  },
  en: {
    errores: {
      porCodigo: {
        consent_denied: "You cancelled Google's consent screen. Nothing has been connected.",
        state_mismatch: "The sign-in process has expired. Try connecting again.",
        missing_code: "Google did not return an authorisation code. Try again.",
        token_exchange:
          "The authorisation code could not be exchanged with Google. Try again.",
        no_refresh_token:
          "Google did not issue a refresh token. Remove the earlier permission at myaccount.google.com/permissions and connect again.",
        identity: "Your identity could not be read from Google. Try again.",
        not_workspace:
          "That is a personal Google account. Connect with a Google Workspace administrator account.",
        not_admin:
          "That account cannot read the data for the whole domain. Connect with a super administrator (or a delegated administrator with read permissions for Users and Reports).",
        google_api: "Google's API returned an error during setup. Try again in a minute.",
        not_configured:
          "This server does not have Google OAuth credentials configured yet (see the README).",
      },
      generico: "Something went wrong during sign-in. Try again.",
    },
    hero: {
      marca: "Vigía · Google Workspace · read-only",
      titular: "Somebody should be watching your Workspace.",
      entradilla:
        "Vigía connects in read-only mode, looks for the misconfigurations attackers " +
        "really do use — administrators without 2FA, dangerous OAuth permissions, " +
        "dormant accounts, missing DMARC — and hands you a score with a list of fixes " +
        "ordered by priority.",
      irAlPanel: "Go to your dashboard →",
      conectar: "Connect your Google Workspace — read-only",
      sinTarjeta: "Free · no card · read-only permissions",
    },
    confianza: {
      titulo: "We cannot read your email. We never ask for it.",
      soloLecturaLead: "Read-only by design.",
      sinEscrituraA:
        "Nor can the application change any setting: there is no write path in the " +
        "code. Whatever cannot be read with these permissions appears as a",
      comprobacionManual: "manual check",
      sinEscrituraB: ", with step-by-step instructions.",
      enlacePrivacidad: "Read the full privacy policy",
      etiquetaPermisos: "The exact permissions you will see on Google's screen",
    },
    comprobaciones: {
      titulo: "One scan, the whole watch list",
      lista: [
        [
          "Super admin with no 2FA and never used",
          "The finding nobody else cross-references: an account with full control, with no second factor and that has never been used, is a permanent back door that nobody is going to spot.",
        ],
        [
          "Two-step verification",
          "Administrators and users with no second factor: the number one route to account theft.",
        ],
        [
          "Compromised accounts",
          "Leaked passwords, hijackings and attacks Google has already detected, plus bursts of failed attempts.",
        ],
        [
          "Too many super administrators",
          "How many people hold the keys to everything (the target is 2-4).",
        ],
        [
          "Dormant and never-used accounts",
          "Enabled accounts nobody has used in more than 90 days, or ever.",
        ],
        [
          "Risky third-party applications",
          "Apps with permissions over Gmail, Drive or administration, how many users have authorised them, and domain-wide delegations.",
        ],
        [
          "Console settings",
          "Drive sharing, Gmail forwarding, password policy, session length, Marketplace and Groups, read automatically.",
        ],
        [
          "Email authentication",
          "SPF, DKIM and DMARC on every domain, with the actual record and the 10-lookup limit from RFC 7208.",
        ],
        [
          "Encryption in transit and DNS integrity",
          "MTA-STS, TLS-RPT and DNSSEC: what stops somebody downgrading or forging your email.",
        ],
      ],
    },
    precio: {
      incluido: [
        "Posture score (0-100), auditable line by line",
        "Full detail of every finding, nothing cut out",
        "Affected accounts and the count by severity",
        "SPF, DKIM, DMARC, MTA-STS, TLS-RPT and DNSSEC on all your domains",
        "PDF report and CSV export",
        "Scan history and comparison with the previous one",
        "A guide to the checks that have to be done by hand",
      ],
      remediacion:
        "What you pay for is fixing it, if you want me to be the one who fixes it: we " +
        "go through the report finding by finding, I act on the critical and high ones " +
        "in your Admin console with you watching, and you are left with a record of what " +
        "changed and why. That is discussed by email with the report in front of us, and " +
        "I will tell you plainly if you do not need me.",
    },
    dmarc: {
      titulo: "Is your domain protected against spoofing?",
      entradilla:
        "Check SPF, DKIM and DMARC on any domain: free, no sign-up, instantly.",
      boton: "Open the DMARC checker",
    },
  },
};

export function getLanding(lang: Lang): Landing {
  return CATALOGO[lang];
}
