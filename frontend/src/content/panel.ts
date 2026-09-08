/**
 * Every string the two report screens print, in both languages.
 *
 * Same contract as `content/ui.ts` and for the same reason: `Record<Lang, T>` with
 * one shape per section, so a string missing from one language is a compile error
 * instead of a hole somebody notices in production. Two sections, one per page —
 * `dashboard` for `pages/Dashboard.tsx`, `dmarc` for `pages/DmarcChecker.tsx` —
 * because a flat bag of a hundred keys stops telling you where a string is used.
 *
 * English is BRITISH: organisation, authorise, recognise, enrolment, prioritised.
 *
 * Findings, severities, statuses and the delta notes are NOT here: they arrive
 * already localised from `backend/vigia/locales/{es,en}.json` because `api.ts`
 * sends `?lang=`. Anything read off `report.*`, `scan.findings` or `data.delta.note`
 * is server text and is printed as it comes.
 *
 * A few entries are functions rather than strings. That is deliberate: a count that
 * decides a plural ("1 cuenta" / "2 cuentas") and the remediation e-mail body cannot
 * be assembled by concatenating fragments without one of the two languages coming
 * out wrong, so each language owns the whole sentence.
 */
import type { Lang } from "../lib/lang";

type Tablero = {
  /** Screen chrome */
  cargando: string;
  demoTitulo: string;
  demoCuerpo: string;
  conectadoComo: string;
  informePdf: string;
  escaneando: string;
  volverAEscanear: string;
  primerEscaneo: string;

  /** Errors raised by this page (server messages come through `errorApi`) */
  errorCarga: string;
  errorDemasiadoPronto: string;
  errorReconectar: string;
  errorApi: (mensaje: string, codigo: number) => string;
  errorConexionPerdida: string;

  /** Empty state, before the first scan */
  vacioTitulo: string;
  vacioCuerpo: string;

  /** Headline block */
  cuentasEnRiesgo: (cuentas: number) => string;
  deEllasGraves: (cuentas: number) => string;
  sinExposicionCuentas: string;
  escaneadoEl: string;
  /** BCP 47 tag for `toLocaleString`, so dates match the interface language. */
  locale: string;
  puntuacionPostura: string;
  respectoAnterior: string;
  sinCambios: string;
  motorCambiado: string;

  /** What Vigía could and could not reach this time */
  coberturaTitulo: string;
  coberturaCuerpo: string;
  coberturaGanada: string;
  coberturaGanadaAbierto: string;
  coberturaPerdida: string;

  /** After a manual scan */
  escaneoCompletadoA: string;
  escaneoGuardado: string;
  escaneoSinCambios: string;
  escaneoVerDesglose: string;

  /** Comparison with the previous scan */
  noComparable: string;
  desdeEscaneoAnterior: string;
  problemasNuevos: string;
  hanEmpeorado: string;
  resueltos: string;
  masEntradas: (restantes: number) => string;

  /** Trend */
  puntuacionEnTiempo: string;
  sinHistorico: string;

  /** The two findings sections */
  ajustesOrgTitulo: string;
  ajustesOrgCuerpo: string;
  hallazgosCuentaTitulo: string;
  hallazgosCuentaCuerpo: string;

  /** Remediation offer */
  remediacionTitulo: string;
  remediacionCuerpo: string;
  remediacionEscribeme: string;
  remediacionNota: string;
  correoAsunto: (dominio: string) => string;
  correoCuerpo: (dominio: string, puntuacion: number | null) => string;

  /** Manual checks */
  manualesTitulo: string;
  manualesCuerpo: string;
  manualesNingunaTitulo: string;
  manualesNingunaCuerpo: string;
};

type Explicador = {
  titulo: string;
  cuerpo: string;
};

type Dmarc = {
  tituloPagina: string;

  /** Errors raised by this page */
  errorDominio: string;
  errorLimite: string;
  errorGenerico: string;

  /** Hero and form */
  etiquetaGratis: string;
  titular: string;
  subtitular: string;
  etiquetaDominio: string;
  marcadorDominio: string;
  comprobando: string;
  comprobar: string;
  etiquetaSelectores: string;
  marcadorSelectores: string;
  ayudaSelectores: string;

  /** Results */
  resultadosDe: string;
  mxWorkspace: string;
  spfLargo: string;
  dkimLargo: string;
  dmarcLargo: string;
  transporteTitulo: string;
  transporteNota: string;
  mtaStsLargo: string;
  tlsRptLargo: string;
  dnssecLargo: string;

  /** The suggested record */
  empiezaSpf: string;
  empiezaDmarc: string;
  /** Two bodies, because the heading has two. A translation pass collapsed them
   *  into the DMARC one, leaving a block headed "publish SPF first" whose
   *  paragraph described the _dmarc record. */
  cuerpoSpf: string;
  buzonAviso: string;
  buzonAvisoFin: string;
  sugerenciaAnade: string;
  sugerenciaMonitorizacion: string;
  sugerenciaSinRiesgo: string;
  copiado: string;
  copiar: string;

  /** CTA to the product */
  ctaTitulo: string;
  ctaCuerpo: string;
  ctaBoton: string;

  /** What each record is for */
  explicadoresTitulo: string;
  explicadores: Explicador[];
};

export type Panel = {
  dashboard: Tablero;
  dmarc: Dmarc;
};

const CATALOGO: Record<Lang, Panel> = {
  es: {
    dashboard: {
      cargando: "Cargando tu panel…",
      demoTitulo: "Informe de ejemplo con datos ficticios",
      demoCuerpo:
        "Ni el dominio ni las personas de este informe existen: es una demostración generada " +
        "con el mismo motor que un análisis real. El PDF que descargues no lleva esta marca, " +
        "para que puedas adjuntarlo tal cual.",
      conectadoComo: "conectado como",
      informePdf: "Informe (PDF)",
      escaneando: "Escaneando…",
      volverAEscanear: "Volver a escanear",
      primerEscaneo: "Ejecutar el primer escaneo",

      errorCarga: "No se han podido cargar tus datos. Recarga la página para reintentarlo.",
      errorDemasiadoPronto:
        "Acaba de terminar un escaneo. Espera un minuto antes de volver a escanear.",
      errorReconectar: "Google ha revocado la conexión. Desconecta y vuelve a conectar.",
      errorApi: (mensaje, codigo) => `${mensaje} (código ${codigo}).`,
      errorConexionPerdida:
        "Se ha perdido la conexión con el servidor durante el escaneo. Puede ser un " +
        "corte de red o que el servicio se estuviera actualizando. El escaneo quizá " +
        "haya terminado igualmente: recarga la página y, si no ves resultados nuevos, " +
        "vuelve a escanear.",

      vacioTitulo: "Aquí empieza la vigilancia",
      vacioCuerpo:
        "Ejecuta el primer escaneo para obtener tu puntuación de postura. Tus dominios se " +
        "detectan solos desde Workspace. Se lee tu directorio, el registro de auditoría y " +
        "el DNS: no se modifica nada, nunca.",

      cuentasEnRiesgo: (cuentas) => `${cuentas} cuenta${cuentas === 1 ? "" : "s"} en riesgo`,
      deEllasGraves: (cuentas) => `${cuentas} de ellas con un problema crítico o alto`,
      sinExposicionCuentas: "No se ha encontrado exposición a nivel de cuenta.",
      escaneadoEl: "Escaneado el",
      locale: "es-ES",
      puntuacionPostura: "Puntuación de postura",
      respectoAnterior: "respecto al anterior",
      sinCambios: "= sin cambios",
      motorCambiado:
        "El conjunto de comprobaciones ha cambiado desde el último análisis: " +
        "los resultados no son comparables.",

      coberturaTitulo: "Cambios en lo que Vigía alcanza a ver",
      coberturaCuerpo:
        "Esto no son cambios en tu organización. Son comprobaciones que antes no se " +
        "podían hacer y ahora sí, o al contrario — un permiso concedido o revocado, o " +
        "un límite de la API de Google.",
      coberturaGanada: "Antes no se podían comprobar",
      coberturaGanadaAbierto:
        "y resulta ser un problema abierto — era invisible, no inexistente",
      coberturaPerdida: "Han dejado de poder comprobarse",

      escaneoCompletadoA: "Escaneo completado a las",
      escaneoGuardado: "Se ha consultado Google de nuevo y se ha guardado un análisis nuevo.",
      escaneoSinCambios:
        " La comparación con el anterior no encuentra ningún cambio en tu organización:" +
        " eso es un resultado, no un fallo.",
      escaneoVerDesglose: " Abajo tienes el desglose de qué ha cambiado respecto al anterior.",

      noComparable: "No se puede comparar con el análisis anterior",
      desdeEscaneoAnterior: "Desde el escaneo anterior",
      problemasNuevos: "Problemas nuevos",
      hanEmpeorado: "Han empeorado",
      resueltos: "Resueltos",
      masEntradas: (restantes) => `+${restantes} más`,

      puntuacionEnTiempo: "Puntuación en el tiempo",
      sinHistorico: "Aún no hay histórico. La gráfica aparece con el segundo escaneo semanal.",

      ajustesOrgTitulo: "Ajustes de la organización",
      ajustesOrgCuerpo:
        "Configuración del tenant. La decide un administrador en la Consola de " +
        "Administración y afecta a todo el mundo por igual: no es un fallo de ninguna " +
        "persona en concreto.",
      hallazgosCuentaTitulo: "Hallazgos por cuenta",
      hallazgosCuentaCuerpo:
        "Cosas que son ciertas de personas concretas: sin segundo factor, cuentas que " +
        "nunca han iniciado sesión, privilegios de administrador, recuperación mal " +
        "puesta o un acceso desde un país nuevo.",

      remediacionTitulo: "¿Quieres que lo arreglemos?",
      remediacionCuerpo:
        "El informe dice qué está mal y dónde se toca. Si prefieres que lo haga " +
        "alguien que ya ha hecho esto antes, lo hago yo contigo: repasamos el informe " +
        "hallazgo por hallazgo, arreglo los críticos y altos en tu Consola de " +
        "Administración contigo delante, hago una sesión con quien lleve la " +
        "informática en casa y os dejo documentado qué se cambió y por qué. Y si " +
        "quieres, repetimos la revisión cada cierto tiempo: es lo que impide volver " +
        "al punto de partida en seis meses.",
      remediacionEscribeme: "Escríbeme",
      remediacionNota:
        "Contesto yo, no un formulario. El precio depende de lo que haya que hacer, " +
        "así que lo hablamos por correo con el informe delante.",
      correoAsunto: (dominio) => `Vigía — arreglar los hallazgos de ${dominio}`,
      correoCuerpo: (dominio, puntuacion) =>
        `Hola Diego:\n\nHe pasado el informe de Vigía en ${dominio}` +
        (puntuacion != null ? ` (puntuación ${puntuacion}/100)` : "") +
        ".\n\nMe gustaría hablar de la remediación.\n\n",

      manualesTitulo: "Comprobaciones manuales",
      manualesCuerpo:
        "Vigía no ha podido leer estos ajustes automáticamente, así que compruébalos a " +
        "mano: cada uno lleva más o menos un minuto. Desaparecen de esta lista en cuanto " +
        "una comprobación automática pueda confirmarlos.",
      manualesNingunaTitulo: "No queda ninguna comprobación manual",
      manualesNingunaCuerpo:
        "Todos los ajustes de la Consola de Administración que cubre Vigía se han leído " +
        "automáticamente en este escaneo.",
    },
    dmarc: {
      tituloPagina: "Comprobador gratuito de SPF, DKIM y DMARC — Vigía",

      errorDominio: "Eso no parece un dominio. Prueba con algo como ejemplo.com.",
      errorLimite:
        "Demasiadas comprobaciones desde tu red: espera un minuto y vuelve a intentarlo.",
      errorGenerico: "La comprobación ha fallado. Inténtalo en un momento.",

      etiquetaGratis: "Herramienta gratuita · sin registro",
      titular: "¿Puede un desconocido enviar correo en nombre de tu dominio?",
      subtitular:
        "Comprueba tus registros SPF, DKIM y DMARC en segundos. Resultados en lenguaje claro, " +
        "sin muro de jerga.",
      etiquetaDominio: "Dominio que quieres comprobar",
      marcadorDominio: "tuempresa.com",
      comprobando: "Comprobando…",
      comprobar: "Comprobar",
      etiquetaSelectores: "¿Firmáis con un selector propio? Escríbelo aquí y lo compruebo.",
      marcadorSelectores: "zoho2, k2 — opcional, varios separados por comas",
      ayudaSelectores:
        "Solo el selector, sin «._domainkey» ni el dominio. Se comprueba además " +
        "de los nombres habituales, no en su lugar.",

      resultadosDe: "Resultados de",
      mxWorkspace: "MX de Google Workspace detectados",
      spfLargo: "quién puede enviar",
      dkimLargo: "firma criptográfica",
      dmarcLargo: "qué hacer con las falsificaciones",
      transporteTitulo: "Transporte e integridad del DNS",
      transporteNota:
        "más allá de lo básico: esto frena la degradación del cifrado y la falsificación de DNS",
      mtaStsLargo: "TLS obligatorio en el correo entrante",
      tlsRptLargo: "informes de fallos de TLS",
      dnssecLargo: "respuestas DNS firmadas",

      empiezaSpf: "Empieza por aquí: publica primero el SPF",
      empiezaDmarc: "Empieza por aquí: publica un DMARC de monitorización",
      cuerpoSpf:
        "Este dominio no tiene SPF ni DMARC. El SPF es el que de verdad empieza a " +
        "proteger: un DMARC sin SPF ni DKIM solo devuelve informes con todo fallando. " +
        "Publica los dos, en este orden.",
      buzonAviso: "Antes de publicarlo, comprueba que ",
      buzonAvisoFin:
        " existe de verdad. Si ese buzón no existe, los informes rebotan y no te " +
        "enteras de nada.",
      sugerenciaAnade: "Añade este registro TXT en ",
      sugerenciaMonitorizacion:
        ". Todavía no cambia nada en la entrega: solo empieza a recoger informes para que " +
        "después puedas pasar a ",
      sugerenciaSinRiesgo: " sin riesgo.",
      copiado: "Copiado ✓",
      copiar: "Copiar",

      ctaTitulo: "La autenticación del correo es solo una parte de lo que revisa Vigía",
      ctaCuerpo:
        "Conecta tu Google Workspace en modo solo lectura y obtén la puntuación completa: " +
        "cobertura de 2FA, aplicaciones OAuth peligrosas, cuentas dormidas y más. Gratis.",
      ctaBoton: "Escanear mi Workspace",

      explicadoresTitulo: "¿Para qué sirve cada registro?",
      explicadores: [
        {
          titulo: "SPF — quién puede enviar",
          cuerpo:
            "Un registro DNS que lista los servidores autorizados a enviar correo en nombre " +
            "de tu dominio. Sin él (o con uno permisivo), cualquiera puede poner tu dominio " +
            "en el remitente y muchos servidores lo aceptarán.",
        },
        {
          titulo: "DKIM — la prueba de que no se ha alterado",
          cuerpo:
            "Tu servidor firma cada mensaje que sale con una clave privada; la pública está " +
            "en el DNS. Los receptores verifican la firma para confirmar que el mensaje viene " +
            "de verdad de ti y sin modificar.",
        },
        {
          titulo: "DMARC — qué pasa con las falsificaciones",
          cuerpo:
            "DMARC le dice al receptor qué hacer cuando un mensaje no pasa SPF ni DKIM: nada " +
            "(p=none), mandarlo a spam (p=quarantine) o rechazarlo (p=reject). Solo quarantine " +
            "y reject protegen de verdad; p=none es únicamente monitorización.",
        },
        {
          titulo: "MTA-STS y TLS-RPT — cifrado que no se puede quitar",
          cuerpo:
            "El cifrado de SMTP es oportunista por defecto, así que un atacante situado entre " +
            "servidores puede quitarlo y leer el mensaje. MTA-STS indica a quien envía que " +
            "exija TLS válido para tu dominio, y TLS-RPT te manda un informe cada vez que una " +
            "entrega no cumple ese requisito.",
        },
        {
          titulo: "DNSSEC — poder fiarse de las respuestas",
          cuerpo:
            "SPF, DKIM y DMARC viven en el DNS, así que son tan fiables como el propio DNS. " +
            "DNSSEC firma tus registros, de modo que quien manipule las respuestas es " +
            "rechazado en lugar de creído.",
        },
      ],
    },
  },
  en: {
    dashboard: {
      cargando: "Loading your dashboard…",
      demoTitulo: "Sample report with fictitious data",
      demoCuerpo:
        "Neither the domain nor the people in this report exist: it is a demonstration " +
        "generated with the same engine as a real scan. The PDF you download does not carry " +
        "this notice, so you can attach it as it is.",
      conectadoComo: "connected as",
      informePdf: "Report (PDF)",
      escaneando: "Scanning…",
      volverAEscanear: "Scan again",
      primerEscaneo: "Run the first scan",

      errorCarga: "We could not load your data. Reload the page to try again.",
      errorDemasiadoPronto: "A scan has just finished. Wait a minute before scanning again.",
      errorReconectar: "Google has revoked the connection. Disconnect and connect again.",
      errorApi: (mensaje, codigo) => `${mensaje} (code ${codigo}).`,
      errorConexionPerdida:
        "The connection to the server was lost during the scan. It may be a network " +
        "outage, or the service being updated. The scan may well have finished anyway: " +
        "reload the page and, if you do not see new results, scan again.",

      vacioTitulo: "The watch starts here",
      vacioCuerpo:
        "Run the first scan to get your posture score. Your domains are detected on their " +
        "own from Workspace. Your directory, the audit log and the DNS are read: nothing is " +
        "ever modified.",

      cuentasEnRiesgo: (cuentas) => `${cuentas} account${cuentas === 1 ? "" : "s"} at risk`,
      deEllasGraves: (cuentas) => `${cuentas} of them with a critical or high issue`,
      sinExposicionCuentas: "No account-level exposure was found.",
      escaneadoEl: "Scanned on",
      locale: "en-GB",
      puntuacionPostura: "Posture score",
      respectoAnterior: "compared with the previous scan",
      sinCambios: "= no change",
      motorCambiado:
        "The set of checks has changed since the last scan: the results are not comparable.",

      coberturaTitulo: "Changes in what Vigía can see",
      coberturaCuerpo:
        "These are not changes in your organisation. They are checks that could not be made " +
        "before and now can, or the other way round — a permission granted or revoked, or a " +
        "limit in Google's API.",
      coberturaGanada: "Could not be checked before",
      coberturaGanadaAbierto:
        "and it turns out to be an open problem — it was invisible, not non-existent",
      coberturaPerdida: "No longer possible to check",

      escaneoCompletadoA: "Scan completed at",
      escaneoGuardado: "Google has been queried again and a new scan has been saved.",
      escaneoSinCambios:
        " The comparison with the previous one finds no change in your organisation:" +
        " that is a result, not a failure.",
      escaneoVerDesglose:
        " Below is the breakdown of what has changed compared with the previous one.",

      noComparable: "It cannot be compared with the previous scan",
      desdeEscaneoAnterior: "Since the previous scan",
      problemasNuevos: "New problems",
      hanEmpeorado: "Got worse",
      resueltos: "Resolved",
      masEntradas: (restantes) => `+${restantes} more`,

      puntuacionEnTiempo: "Score over time",
      sinHistorico: "There is no history yet. The chart appears with the second weekly scan.",

      ajustesOrgTitulo: "Organisation settings",
      ajustesOrgCuerpo:
        "Tenant configuration. An administrator decides it in the Admin console and it " +
        "affects everybody equally: it is not the fault of any one person.",
      hallazgosCuentaTitulo: "Findings by account",
      hallazgosCuentaCuerpo:
        "Things that are true of specific people: no second factor, accounts that have " +
        "never signed in, administrator privileges, recovery set up badly or a sign-in " +
        "from a new country.",

      remediacionTitulo: "Would you like us to fix it?",
      remediacionCuerpo:
        "The report says what is wrong and where to change it. If you would rather it was " +
        "done by somebody who has done this before, I do it with you: we go through the " +
        "report finding by finding, I fix the critical and high ones in your Admin console " +
        "with you watching, I run a session with whoever looks after the IT in-house and I " +
        "leave you a record of what was changed and why. And if you want, we repeat the " +
        "review from time to time: that is what stops you being back where you started in " +
        "six months.",
      remediacionEscribeme: "Write to me",
      remediacionNota:
        "I reply myself, not a form. The price depends on what needs doing, so we discuss " +
        "it by e-mail with the report in front of us.",
      correoAsunto: (dominio) => `Vigía — fixing the findings for ${dominio}`,
      correoCuerpo: (dominio, puntuacion) =>
        `Hello Diego,\n\nI have run the Vigía report on ${dominio}` +
        (puntuacion != null ? ` (score ${puntuacion}/100)` : "") +
        ".\n\nI would like to talk about remediation.\n\n",

      manualesTitulo: "Manual checks",
      manualesCuerpo:
        "Vigía could not read these settings automatically, so check them by hand: each one " +
        "takes about a minute. They disappear from this list as soon as an automatic check " +
        "can confirm them.",
      manualesNingunaTitulo: "No manual checks left",
      manualesNingunaCuerpo:
        "Every Admin console setting Vigía covers was read automatically in this scan.",
    },
    dmarc: {
      tituloPagina: "Free SPF, DKIM and DMARC checker — Vigía",

      errorDominio: "That does not look like a domain. Try something like example.com.",
      errorLimite: "Too many checks from your network: wait a minute and try again.",
      errorGenerico: "The check failed. Try again in a moment.",

      etiquetaGratis: "Free tool · no sign-up",
      titular: "Can a stranger send e-mail on behalf of your domain?",
      subtitular:
        "Check your SPF, DKIM and DMARC records in seconds. Results in plain language, " +
        "with no wall of jargon.",
      etiquetaDominio: "Domain you want to check",
      marcadorDominio: "yourcompany.com",
      comprobando: "Checking…",
      comprobar: "Check",
      etiquetaSelectores: "Do you sign with your own selector? Type it here and I will check it.",
      marcadorSelectores: "zoho2, k2 — optional, several separated by commas",
      ayudaSelectores:
        "Just the selector, without “._domainkey” or the domain. It is checked in addition " +
        "to the usual names, not instead of them.",

      resultadosDe: "Results for",
      mxWorkspace: "Google Workspace MX records detected",
      spfLargo: "who can send",
      dkimLargo: "cryptographic signature",
      dmarcLargo: "what to do with forgeries",
      transporteTitulo: "Transport and DNS integrity",
      transporteNota:
        "beyond the basics: this stops encryption being downgraded and DNS being spoofed",
      mtaStsLargo: "mandatory TLS on incoming mail",
      tlsRptLargo: "reports of TLS failures",
      dnssecLargo: "signed DNS responses",

      empiezaSpf: "Start here: publish SPF first",
      empiezaDmarc: "Start here: publish a monitoring DMARC",
      cuerpoSpf:
        "This domain has neither SPF nor DMARC. SPF is the one that actually starts " +
        "protecting it: a DMARC record with no SPF and no DKIM only returns reports " +
        "with everything failing. Publish both, in this order.",
      buzonAviso: "Before publishing it, check that ",
      buzonAvisoFin:
        " really exists. If that mailbox does not exist, the reports bounce and you " +
        "never find out.",
      sugerenciaAnade: "Add this TXT record at ",
      sugerenciaMonitorizacion:
        ". It does not change anything about delivery yet: it only starts collecting reports " +
        "so that you can then move to ",
      sugerenciaSinRiesgo: " without risk.",
      copiado: "Copied ✓",
      copiar: "Copy",

      ctaTitulo: "E-mail authentication is only one part of what Vigía reviews",
      ctaCuerpo:
        "Connect your Google Workspace in read-only mode and get the full score: 2FA " +
        "coverage, dangerous OAuth applications, dormant accounts and more. Free.",
      ctaBoton: "Scan my Workspace",

      explicadoresTitulo: "What is each record for?",
      explicadores: [
        {
          titulo: "SPF — who can send",
          cuerpo:
            "A DNS record that lists the servers authorised to send e-mail on behalf of your " +
            "domain. Without it (or with a permissive one), anybody can put your domain in " +
            "the sender and many servers will accept it.",
        },
        {
          titulo: "DKIM — the proof that it has not been altered",
          cuerpo:
            "Your server signs every outgoing message with a private key; the public one is " +
            "in the DNS. Recipients verify the signature to confirm that the message really " +
            "does come from you, unmodified.",
        },
        {
          titulo: "DMARC — what happens to forgeries",
          cuerpo:
            "DMARC tells the recipient what to do when a message passes neither SPF nor DKIM: " +
            "nothing (p=none), send it to spam (p=quarantine) or reject it (p=reject). Only " +
            "quarantine and reject genuinely protect; p=none is monitoring only.",
        },
        {
          titulo: "MTA-STS and TLS-RPT — encryption that cannot be taken away",
          cuerpo:
            "SMTP encryption is opportunistic by default, so an attacker positioned between " +
            "servers can take it away and read the message. MTA-STS tells the sender to " +
            "require valid TLS for your domain, and TLS-RPT sends you a report every time a " +
            "delivery does not meet that requirement.",
        },
        {
          titulo: "DNSSEC — being able to trust the answers",
          cuerpo:
            "SPF, DKIM and DMARC live in the DNS, so they are only as trustworthy as the DNS " +
            "itself. DNSSEC signs your records, so anybody tampering with the answers is " +
            "rejected instead of believed.",
        },
      ],
    },
  },
};

export function getPanel(lang: Lang): Panel {
  return CATALOGO[lang];
}
