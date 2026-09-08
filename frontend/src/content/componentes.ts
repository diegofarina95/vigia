/**
 * Every string the components print, in both languages.
 *
 * Same shape as `content/ui.ts` and for the same reason: `Record<Lang, T>` with one
 * explicit section per component, so a string missing from one language is a compile
 * error rather than a hole somebody notices in production. One section per component
 * on purpose — a phrase that appears in two components is written twice here, which
 * is the price of being able to read a component's whole vocabulary in one place.
 *
 * English is BRITISH: organisation, authorise, recognise, prioritised, licence.
 *
 * A few entries are functions rather than strings. Those are the sentences where the
 * two languages put the number in a different place, so splitting them into a prefix
 * and a suffix would produce fragments no translator could check.
 *
 * NOT here: the title, description, remediation, scope and observed value of a
 * finding, the area and instructions of a manual check, and the exclusion reasons in
 * the score breakdown. All of those come from `backend/vigia/locales/{es,en}.json`
 * and arrive already localised because `api.ts` sends `?lang=`.
 */
import type { Lang } from "../lib/lang";
import type { Change, Severity, Status } from "../types";

/** Badges.tsx — the severity and status words, and the tooltip that explains
 *  why `undetermined` is not a failure. */
type Insignias = {
  severidad: Record<Severity, string>;
  estado: Record<Status, string>;
  noVerificadoTitulo: string;
};

/** ScoreGauge.tsx */
type Medidor = {
  sinDeterminar: string;
  solida: string;
  buena: string;
  atencion: string;
  riesgo: string;
  expuesta: string;
  ariaSinDeterminar: string;
  aria: (score: number) => string;
};

/** TrendChart.tsx */
type Tendencia = {
  aria: string;
  /** Date locale for `toLocaleDateString`, not a translated string. */
  localeFecha: string;
  corte: string;
  puntoCambio: string;
};

/** FindingsList.tsx */
type Hallazgos = {
  cambio: Partial<Record<Change, string>>;
  notaAfectados: (desde: number, hasta: number) => string;
  notaSeveridad: (desde: string, hasta: string) => string;
  notaSeveridadRegresion: (desde: string, hasta: string) => string;
  notaCobertura: string;
  alcance: string;
  valorActual: string;
  afectados: string;
  comoMantener: string;
  comoArreglar: string;
  abrirConsola: string;
  todas: string;
  soloProblemas: string;
  soloCambios: string;
  sinCoincidencias: string;
};

/** ScoreBreakdownPanel.tsx */
type Desglose = {
  estado: Record<Status, string>;
  ocultar: string;
  ver: string;
  pesos: string;
  credito: string;
  ajustesFuerte: string;
  ajustesResto: string;
  cuentasFuerte: string;
  cuentasResto: string;
  escala: (porcentaje: number) => string;
  excluidosNota: string;
  colElemento: string;
  colSeveridad: string;
  colEstado: string;
  colPeso: string;
  colObtenido: string;
  total: string;
  formula: string;
  noDisponible: string;
  excluidos: string;
};

/** FixFirst.tsx */
type ArreglaPrimero = {
  titulo: string;
  intro: string;
  empiezaAqui: string;
  accion: string;
  hallazgoCerrado: string;
  hallazgosCerrados: string;
  cuentaAfectada: string;
  cuentasAfectadas: string;
  puntuacion: string;
  avisoUsuarios: string;
  abrirConsola: string;
  cierra: string;
};

/** RiskyUsers.tsx */
type PersonasEnRiesgo = {
  titulo: string;
  orden: string;
  acumulaUna: string;
  acumulanVarias: string;
  ningunaAcumula: string;
  informe: (total: number) => string;
  problemas: string;
  verMenos: string;
  verTodas: (total: number) => string;
};

/** ManualCheckCard.tsx */
type ComprobacionManual = {
  etiqueta: string;
  abrirConsola: string;
};

/** DomainsPanel.tsx */
type Dominios = {
  estado: Record<Status, string>;
  titulo: string;
  subtitulo: string;
  intro: string;
  vacioAntes: string;
  vacioDespues: string;
  origenManual: string;
  sinEscanear: string;
  quitar: string;
  quitarAria: (dominio: string) => string;
  etiquetaNuevo: string;
  placeholderNuevo: string;
  anadir: string;
  anadido: string;
  errorInvalido: string;
  errorAnadir: string;
  errorQuitar: string;
  spfMecanismo: string;
  spfConsultas: string;
  spfSobreLimite: string;
  dkimSelector: string;
  dkimClave: string;
  dkimBits: string;
  dkimDebil: string;
  dkimAdecuada: string;
  dkimProbados: (total: number) => string;
  dkimSelectorPropio: string;
  dmarcPolitica: string;
  dmarcSinDefinir: string;
  dmarcAlineacion: string;
  dmarcEstricta: string;
  dmarcRelajada: string;
  dmarcInformes: string;
  dmarcRuaPropio: string;
  dmarcRuaTercero: string;
  dmarcRuaNinguno: string;
};

/** SchedulePanel.tsx */
type Programacion = {
  frecuencias: Record<string, string>;
  titulo: string;
  ultimo: string;
  intro: string;
  frecuenciaEtiqueta: string;
  avisosEtiqueta: string;
  soloCambios: string;
  soloCambiosAyuda: string;
  sinSmtpAntes: string;
  sinSmtpY: string;
  sinSmtpDespues: string;
  guardando: string;
  guardar: string;
  enviarPrueba: string;
  guardadoDesactivado: string;
  guardadoActivo: (frecuencia: string) => string;
  errorGuardar: string;
  pruebaEnviada: (destino: string) => string;
  errorPrueba: string;
};

type CampoOpciones = {
  etiqueta: string;
  ayuda: string;
};

/** SettingsPanel.tsx */
type Opciones = {
  titulo: string;
  subtitulo: string;
  campos: {
    super_admin_threshold: CampoOpciones;
    dormant_days: CampoOpciones;
    widely_granted_threshold: CampoOpciones;
    dkim_selectors: CampoOpciones;
  };
  guardado: string;
  errorGuardar: string;
  guardando: string;
  guardar: string;
  restaurar: string;
};

export type Componentes = {
  insignias: Insignias;
  medidor: Medidor;
  tendencia: Tendencia;
  hallazgos: Hallazgos;
  desglose: Desglose;
  arreglaPrimero: ArreglaPrimero;
  personasEnRiesgo: PersonasEnRiesgo;
  comprobacionManual: ComprobacionManual;
  dominios: Dominios;
  programacion: Programacion;
  opciones: Opciones;
};

const CATALOGO: Record<Lang, Componentes> = {
  es: {
    insignias: {
      severidad: {
        critical: "crítico",
        high: "alto",
        medium: "medio",
        low: "bajo",
        info: "info",
      },
      estado: {
        pass: "Correcto",
        fail: "Fallo",
        warn: "Aviso",
        undetermined: "No verificado",
      },
      noVerificadoTitulo:
        "Comprobado por heurística y sin poder confirmarse. Nunca cuenta en la " +
        "puntuación, ni a favor ni en contra.",
    },
    medidor: {
      sinDeterminar: "Sin determinar",
      solida: "Postura sólida",
      buena: "Buena, con detalles",
      atencion: "Requiere atención",
      riesgo: "En riesgo",
      expuesta: "Expuesta",
      ariaSinDeterminar: "Puntuación sin determinar",
      aria: (score) => `Puntuación de seguridad ${score} sobre 100`,
    },
    tendencia: {
      aria: "Puntuación a lo largo del tiempo",
      localeFecha: "es-ES",
      corte:
        "Aquí cambió el conjunto de comprobaciones: los puntos de un lado y del otro " +
        "no son comparables.",
      puntoCambio: " (cambió el conjunto de comprobaciones)",
    },
    hallazgos: {
      cambio: {
        new: "Nuevo",
        worse: "Peor",
        improved: "Mejorado",
        resolved: "Resuelto",
        coverage_gained: "Ahora visible",
        coverage_lost: "Ya no se comprueba",
      },
      notaAfectados: (desde, hasta) => `de ${desde} a ${hasta} afectados`,
      notaSeveridad: (desde, hasta) => `severidad de ${desde} a ${hasta}`,
      notaSeveridadRegresion: (desde, hasta) =>
        `severidad de ${desde} a ${hasta}, por regresión`,
      notaCobertura: "antes no se podía comprobar; ahora sí",
      alcance: "Alcance:",
      valorActual: "Valor actual:",
      afectados: "Afectados",
      comoMantener: "Cómo mantenerlo",
      comoArreglar: "Cómo se arregla",
      abrirConsola: "Abrir la Consola de Administración ↗",
      todas: "todas",
      soloProblemas: "Solo problemas",
      soloCambios: "Solo cambios",
      sinCoincidencias: "Ningún hallazgo coincide con este filtro.",
    },
    desglose: {
      estado: {
        pass: "correcto",
        fail: "fallo",
        warn: "aviso",
        undetermined: "no verificado",
      },
      ocultar: "▾ Ocultar el cálculo",
      ver: "▸ Ver el cálculo",
      pesos: "Pesos por severidad:",
      credito:
        "Crédito: correcto 100%, aviso 50%, fallo 0%. La puntuación se reparte en dos " +
        "bloques que se leen distinto.",
      ajustesFuerte: "Los ajustes de la organización cuentan una vez cada uno",
      ajustesResto:
        ": son decisiones de un administrador, no fallos de cada empleado, y contarlas " +
        "por cabeza hacía que un solo interruptor pesara tanto como la plantilla entera.",
      cuentasFuerte: "Cada cuenta cuenta una sola vez",
      cuentasResto:
        ", con la peor severidad en la que aparece, así que alguien con varias " +
        "debilidades es una exposición y no cuatro.",
      escala: (porcentaje) =>
        `En esta organización el bloque de cuentas se ha reducido al ${porcentaje}% de ` +
        "su peso bruto para que no supere al de ajustes: si no, una plantilla grande " +
        "dejaría la configuración en un decimal.",
      excluidosNota:
        "Los hallazgos informativos, manuales y no verificados quedan excluidos por completo.",
      colElemento: "Elemento",
      colSeveridad: "Severidad",
      colEstado: "Estado",
      colPeso: "Peso",
      colObtenido: "Obtenido",
      total: "Total",
      formula: "puntuación",
      noDisponible: "N/D",
      excluidos: "Excluidos de la puntuación",
    },
    arreglaPrimero: {
      titulo: "Arregla esto primero",
      intro:
        "Ordenado por hallazgos cerrados por minuto de trabajo, no por severidad. " +
        "Hacerlos en este orden elimina la mayor exposición con el menor esfuerzo.",
      empiezaAqui: "EMPIEZA AQUÍ",
      accion: "ACCIÓN",
      hallazgoCerrado: "hallazgo cerrado",
      hallazgosCerrados: "hallazgos cerrados",
      cuentaAfectada: "cuenta afectada",
      cuentasAfectadas: "cuentas afectadas",
      puntuacion: "puntuación",
      avisoUsuarios: "Aviso para los usuarios:",
      abrirConsola: "Abrir la Consola de Administración ↗",
      cierra: "Cierra:",
    },
    personasEnRiesgo: {
      titulo: "Personas en riesgo",
      orden: "ordenadas por severidad combinada",
      acumulaUna:
        "cuenta acumula más de un problema a la vez: son las que un atacante solo tiene " +
        "que acertar una vez.",
      acumulanVarias:
        "cuentas acumulan más de un problema a la vez: son las que un atacante solo tiene " +
        "que acertar una vez.",
      ningunaAcumula: "Cada una de estas cuentas aparece en un hallazgo abierto.",
      informe: (total) => `El informe exportado siempre lista las ${total}.`,
      problemas: "problemas",
      verMenos: "Ver menos",
      verTodas: (total) => `Ver todas (${total})`,
    },
    comprobacionManual: {
      etiqueta: "Comprobación manual",
      abrirConsola: "Abrir la Consola de Administración ↗",
    },
    dominios: {
      estado: {
        pass: "correcto",
        fail: "fallo",
        warn: "aviso",
        undetermined: "no verificado",
      },
      titulo: "Dominios",
      subtitulo: "SPF · DKIM · DMARC · MTA-STS · TLS-RPT · DNSSEC, por DNS público",
      intro:
        "Se comprueban en cada escaneo. Los dominios de Workspace se sincronizan solos; " +
        "añade cualquier otro que sea tuyo. Pulsa en un dominio para ver los registros " +
        "reales y qué falla exactamente en ellos.",
      vacioAntes:
        "Todavía no hay dominios configurados. Añade el primero abajo: los hallazgos de " +
        "autenticación del correo se quedan en ",
      vacioDespues: " hasta que haya algo que comprobar.",
      origenManual: "Añadido a mano",
      sinEscanear: "sin escanear todavía",
      quitar: "Quitar",
      quitarAria: (dominio) => `Quitar ${dominio}`,
      etiquetaNuevo: "Dominio que quieres añadir",
      placeholderNuevo: "tuempresa.com",
      anadir: "Añadir dominio",
      anadido: "Dominio añadido: ejecuta un escaneo para comprobarlo.",
      errorInvalido: "Eso no parece un dominio válido (por ejemplo, tuempresa.com).",
      errorAnadir: "No se ha podido añadir el dominio. Inténtalo de nuevo.",
      errorQuitar: "No se ha podido quitar el dominio.",
      spfMecanismo: "mecanismo final:",
      spfConsultas: "consultas DNS:",
      spfSobreLimite:
        "— por encima del límite: los receptores devuelven permerror y dejan de evaluar el SPF",
      dkimSelector: "selector:",
      dkimClave: "clave:",
      dkimBits: "bits",
      dkimDebil: " — débil, rota a 2048 o más",
      dkimAdecuada: " — adecuada",
      dkimProbados: (total) => `probados ${total} selectores habituales`,
      dkimSelectorPropio:
        ". Un selector propio no lo encontraría esta comprobación: añade el tuyo en " +
        "Opciones de escaneo.",
      dmarcPolitica: "política:",
      dmarcSinDefinir: "sin definir",
      dmarcAlineacion: "alineación:",
      dmarcEstricta: "estricta",
      dmarcRelajada: "relajada",
      dmarcInformes: "informes:",
      dmarcRuaPropio: "van a tu propio dominio",
      dmarcRuaTercero: "van solo a un tercero: nunca ves tu propia telemetría",
      dmarcRuaNinguno: "a ningún sitio: sin etiqueta rua, así que no hay informes",
    },
    programacion: {
      frecuencias: {
        off: "Desactivado (solo escaneos manuales)",
        daily: "Todos los días",
        weekly: "Todas las semanas",
      },
      titulo: "Escaneos automáticos y avisos",
      ultimo: "último escaneo automático:",
      intro:
        "Vigía vuelve a escanear por su cuenta y te avisa por correo cuando aparece algo " +
        "nuevo, para que un ajuste que se ha desviado o una cuenta comprometida no esperen " +
        "a tu próxima visita.",
      frecuenciaEtiqueta: "Frecuencia de escaneo",
      avisosEtiqueta: "Enviar los avisos a",
      soloCambios: "Avisar solo cuando algo cambie",
      soloCambiosAyuda:
        "Hallazgos nuevos o que han empeorado, o una bajada de puntuación. Desmárcalo " +
        "para recibir todos los escaneos.",
      sinSmtpAntes:
        "Esta instancia no tiene servidor de correo configurado, así que todavía no se " +
        "pueden enviar avisos. Los escaneos sí se ejecutan según lo programado. Define ",
      sinSmtpY: " y ",
      sinSmtpDespues: " para activar el correo.",
      guardando: "Guardando…",
      guardar: "Guardar programación",
      enviarPrueba: "Enviar correo de prueba",
      guardadoDesactivado: "Guardado: los escaneos automáticos están desactivados.",
      guardadoActivo: (frecuencia) =>
        `Guardado: Vigía escaneará (${frecuencia}) y te avisará por correo.`,
      errorGuardar: "No se ha podido guardar la programación.",
      pruebaEnviada: (destino) => `Correo de prueba enviado a ${destino}.`,
      errorPrueba: "No se ha podido enviar el correo de prueba.",
    },
    opciones: {
      titulo: "Opciones de escaneo",
      subtitulo: "umbrales y selectores DKIM, por organización",
      campos: {
        super_admin_threshold: {
          etiqueta: "Umbral de aviso de superadministradores",
          ayuda:
            "Avisa cuando la organización tenga más superadministradores que este número " +
            "(CIS recomienda 2-4).",
        },
        dormant_days: {
          etiqueta: "Días para considerar una cuenta inactiva",
          ayuda:
            "Las cuentas sin iniciar sesión durante más tiempo que esto se marcan como inactivas.",
        },
        widely_granted_threshold: {
          etiqueta: "Umbral de app autorizada por muchos usuarios",
          ayuda:
            "Marca las aplicaciones de terceros autorizadas por al menos este número de usuarios.",
        },
        dkim_selectors: {
          etiqueta: "Selectores DKIM que se van a probar",
          ayuda:
            "Separados por comas. «google» es el de Workspace; añade aquí el selector propio " +
            "de tu proveedor para que el DKIM pase de «no verificado» a verificado.",
        },
      },
      guardado: "Guardado: se aplica desde el próximo escaneo.",
      errorGuardar: "No se han podido guardar las opciones.",
      guardando: "Guardando…",
      guardar: "Guardar opciones",
      restaurar: "Restaurar valores por defecto",
    },
  },
  en: {
    insignias: {
      severidad: {
        critical: "critical",
        high: "high",
        medium: "medium",
        low: "low",
        info: "info",
      },
      estado: {
        pass: "Pass",
        fail: "Fail",
        warn: "Warning",
        undetermined: "Not verified",
      },
      noVerificadoTitulo:
        "Checked by heuristic and impossible to confirm. It never counts towards the " +
        "score, neither for nor against.",
    },
    medidor: {
      sinDeterminar: "Undetermined",
      solida: "Solid posture",
      buena: "Good, with details",
      atencion: "Needs attention",
      riesgo: "At risk",
      expuesta: "Exposed",
      ariaSinDeterminar: "Undetermined score",
      aria: (score) => `Security score ${score} out of 100`,
    },
    tendencia: {
      aria: "Score over time",
      localeFecha: "en-GB",
      corte:
        "The set of checks changed here: the points on either side of it are not comparable.",
      puntoCambio: " (the set of checks changed)",
    },
    hallazgos: {
      cambio: {
        new: "New",
        worse: "Worse",
        improved: "Improved",
        resolved: "Resolved",
        coverage_gained: "Now visible",
        coverage_lost: "No longer checked",
      },
      notaAfectados: (desde, hasta) => `from ${desde} to ${hasta} affected`,
      notaSeveridad: (desde, hasta) => `severity from ${desde} to ${hasta}`,
      notaSeveridadRegresion: (desde, hasta) =>
        `severity from ${desde} to ${hasta}, a regression`,
      notaCobertura: "it could not be checked before; now it can",
      alcance: "Scope:",
      valorActual: "Current value:",
      afectados: "Affected",
      comoMantener: "How to keep it",
      comoArreglar: "How to fix it",
      abrirConsola: "Open the Admin console ↗",
      todas: "all",
      soloProblemas: "Issues only",
      soloCambios: "Changes only",
      sinCoincidencias: "No finding matches this filter.",
    },
    desglose: {
      estado: {
        pass: "pass",
        fail: "fail",
        warn: "warning",
        undetermined: "not verified",
      },
      ocultar: "▾ Hide the calculation",
      ver: "▸ Show the calculation",
      pesos: "Weights by severity:",
      credito:
        "Credit: pass 100%, warning 50%, fail 0%. The score splits into two blocks that " +
        "read differently.",
      ajustesFuerte: "Organisation settings count once each",
      ajustesResto:
        ": they are decisions taken by an administrator, not failures of each employee, " +
        "and counting them per head made a single switch weigh as much as the whole workforce.",
      cuentasFuerte: "Each account counts only once",
      cuentasResto:
        ", under the worst severity it appears with, so somebody with several weaknesses " +
        "is one exposure and not four.",
      escala: (porcentaje) =>
        `In this organisation the accounts block has been reduced to ${porcentaje}% of its ` +
        "raw weight so that it does not outweigh the settings one: otherwise a large " +
        "workforce would leave the configuration down to a decimal.",
      excluidosNota:
        "Informational, manual and not verified findings are excluded entirely.",
      colElemento: "Item",
      colSeveridad: "Severity",
      colEstado: "Status",
      colPeso: "Weight",
      colObtenido: "Earned",
      total: "Total",
      formula: "score",
      noDisponible: "N/A",
      excluidos: "Excluded from the score",
    },
    arreglaPrimero: {
      titulo: "Fix this first",
      intro:
        "Ordered by findings closed per minute of work, not by severity. Doing them in " +
        "this order removes the greatest exposure with the least effort.",
      empiezaAqui: "START HERE",
      accion: "ACTION",
      hallazgoCerrado: "finding closed",
      hallazgosCerrados: "findings closed",
      cuentaAfectada: "account affected",
      cuentasAfectadas: "accounts affected",
      puntuacion: "score",
      avisoUsuarios: "Notice for users:",
      abrirConsola: "Open the Admin console ↗",
      cierra: "Closes:",
    },
    personasEnRiesgo: {
      titulo: "People at risk",
      orden: "ordered by combined severity",
      acumulaUna:
        "account stacks up more than one problem at a time: it is the one an attacker " +
        "only has to get right once.",
      acumulanVarias:
        "accounts stack up more than one problem at a time: they are the ones an attacker " +
        "only has to get right once.",
      ningunaAcumula: "Each of these accounts appears in an open finding.",
      informe: (total) => `The exported report always lists all ${total}.`,
      problemas: "problems",
      verMenos: "Show fewer",
      verTodas: (total) => `Show all (${total})`,
    },
    comprobacionManual: {
      etiqueta: "Manual check",
      abrirConsola: "Open the Admin console ↗",
    },
    dominios: {
      estado: {
        pass: "pass",
        fail: "fail",
        warn: "warning",
        undetermined: "not verified",
      },
      titulo: "Domains",
      subtitulo: "SPF · DKIM · DMARC · MTA-STS · TLS-RPT · DNSSEC, over public DNS",
      intro:
        "They are checked on every scan. Workspace domains sync by themselves; add any " +
        "other domain of yours. Click a domain to see the actual records and exactly what " +
        "fails in them.",
      vacioAntes:
        "No domains are configured yet. Add the first one below: the e-mail authentication " +
        "findings stay as ",
      vacioDespues: " until there is something to check.",
      origenManual: "Added by hand",
      sinEscanear: "not scanned yet",
      quitar: "Remove",
      quitarAria: (dominio) => `Remove ${dominio}`,
      etiquetaNuevo: "Domain you want to add",
      placeholderNuevo: "yourcompany.com",
      anadir: "Add domain",
      anadido: "Domain added: run a scan to check it.",
      errorInvalido: "That does not look like a valid domain (for example, yourcompany.com).",
      errorAnadir: "The domain could not be added. Try again.",
      errorQuitar: "The domain could not be removed.",
      spfMecanismo: "final mechanism:",
      spfConsultas: "DNS lookups:",
      spfSobreLimite:
        "— above the limit: receivers return permerror and stop evaluating SPF",
      dkimSelector: "selector:",
      dkimClave: "key:",
      dkimBits: "bits",
      dkimDebil: " — weak, rotate it to 2048 or more",
      dkimAdecuada: " — adequate",
      dkimProbados: (total) => `${total} common selectors tested`,
      dkimSelectorPropio:
        ". This check would not find a selector of your own: add yours in Scan options.",
      dmarcPolitica: "policy:",
      dmarcSinDefinir: "not set",
      dmarcAlineacion: "alignment:",
      dmarcEstricta: "strict",
      dmarcRelajada: "relaxed",
      dmarcInformes: "reports:",
      dmarcRuaPropio: "they go to your own domain",
      dmarcRuaTercero: "they go only to a third party: you never see your own telemetry",
      dmarcRuaNinguno: "nowhere: no rua tag, so there are no reports",
    },
    programacion: {
      frecuencias: {
        off: "Off (manual scans only)",
        daily: "Every day",
        weekly: "Every week",
      },
      titulo: "Automatic scans and alerts",
      ultimo: "last automatic scan:",
      intro:
        "Vigía scans again on its own and alerts you by e-mail when something new appears, " +
        "so that a setting that has drifted or a compromised account does not wait for your " +
        "next visit.",
      frecuenciaEtiqueta: "Scan frequency",
      avisosEtiqueta: "Send the alerts to",
      soloCambios: "Only alert when something changes",
      soloCambiosAyuda:
        "New or worsened findings, or a drop in the score. Untick it to receive every scan.",
      sinSmtpAntes:
        "This instance has no mail server configured, so alerts cannot be sent yet. The " +
        "scans do run as scheduled. Set ",
      sinSmtpY: " and ",
      sinSmtpDespues: " to enable e-mail.",
      guardando: "Saving…",
      guardar: "Save schedule",
      enviarPrueba: "Send test e-mail",
      guardadoDesactivado: "Saved: automatic scans are off.",
      guardadoActivo: (frecuencia) =>
        `Saved: Vigía will scan (${frecuencia}) and will alert you by e-mail.`,
      errorGuardar: "The schedule could not be saved.",
      pruebaEnviada: (destino) => `Test e-mail sent to ${destino}.`,
      errorPrueba: "The test e-mail could not be sent.",
    },
    opciones: {
      titulo: "Scan options",
      subtitulo: "thresholds and DKIM selectors, per organisation",
      campos: {
        super_admin_threshold: {
          etiqueta: "Super administrator warning threshold",
          ayuda:
            "Warns when the organisation has more super administrators than this number " +
            "(CIS recommends 2-4).",
        },
        dormant_days: {
          etiqueta: "Days before an account counts as dormant",
          ayuda:
            "Accounts that have not signed in for longer than this are flagged as dormant.",
        },
        widely_granted_threshold: {
          etiqueta: "Threshold for an app authorised by many users",
          ayuda:
            "Flags third-party applications authorised by at least this number of users.",
        },
        dkim_selectors: {
          etiqueta: "DKIM selectors to be tested",
          ayuda:
            "Comma-separated. “google” is the Workspace one; add your provider's own " +
            "selector here so that DKIM goes from “not verified” to verified.",
        },
      },
      guardado: "Saved: it applies from the next scan.",
      errorGuardar: "The options could not be saved.",
      guardando: "Saving…",
      guardar: "Save options",
      restaurar: "Restore default values",
    },
  },
};

export function getComponentes(lang: Lang): Componentes {
  return CATALOGO[lang];
}
