// GENERATED FILE — do not edit.
// Source: backend/vigia/scopes.py · Regenerate: python backend/scripts/build_scopes_ts.py
//
// The scopes are defined once, in Python, because the authorization request is
// built there and that request is the only source of truth. This file exists so the
// React app can render the same list without a second copy to keep in sync;
// tests/test_scopes_single_source.py fails if it drifts.

export type ScopeFamily = "workspace" | "identidad";

export type ScopeInfo = {
  /** Full identifier, exactly as sent to Google and as configured in Cloud Console. */
  id: string;
  /** Abbreviated form, as the consent screen shows it. */
  corto: string;
  familia: ScopeFamily;
  nombre: { es: string; en: string };
  /** What data it reads, and what for. */
  lee: { es: string; en: string };
  /** Checks that stop working without it. */
  checks: readonly string[];
};

export const SCOPES: readonly ScopeInfo[] = [
  {
    "id": "openid",
    "corto": "openid",
    "familia": "identidad",
    "nombre": {
      "es": "Identificador de la sesión",
      "en": "Session identifier"
    },
    "lee": {
      "es": "Obtener el identificador de la sesión de Google que autoriza la conexión.",
      "en": "The identifier of the Google session that authorises the connection."
    },
    "checks": []
  },
  {
    "id": "email",
    "corto": "email",
    "familia": "identidad",
    "nombre": {
      "es": "Dirección del administrador",
      "en": "Administrator address"
    },
    "lee": {
      "es": "Saber con qué dirección de administrador se ha conectado, para mostrarla en la interfaz y asociar la autorización a tu organización.",
      "en": "Which administrator address connected, so it can be shown in the interface and the authorisation tied to your organisation."
    },
    "checks": []
  },
  {
    "id": "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "corto": "admin.directory.user.readonly",
    "familia": "workspace",
    "nombre": {
      "es": "Lectura de cuentas",
      "en": "Read accounts"
    },
    "lee": {
      "es": "Listar las cuentas y sus indicadores de seguridad: inscripción en la verificación en dos pasos, rol de administrador, último inicio de sesión, estado de suspensión, fecha de creación, datos de recuperación y unidad organizativa.",
      "en": "List the accounts and their security metadata: 2-Step Verification enrolment, administrator role, last sign-in, suspension state, creation date, recovery details and organizational unit."
    },
    "checks": [
      "2sv",
      "dormant",
      "stale",
      "super_admins",
      "recovery",
      "backup_codes",
      "admin_logins",
      "suspended_tokens",
      "policies"
    ]
  },
  {
    "id": "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "corto": "admin.directory.domain.readonly",
    "familia": "workspace",
    "nombre": {
      "es": "Lectura de dominios",
      "en": "Read domains"
    },
    "lee": {
      "es": "Listar tus dominios verificados, para comprobar SPF, DKIM, DMARC y MTA-STS en cada uno a través del DNS público.",
      "en": "List your verified domains, so SPF, DKIM, DMARC and MTA-STS can be checked for each one through public DNS."
    },
    "checks": [
      "email_auth",
      "mail_transport"
    ]
  },
  {
    "id": "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "corto": "admin.reports.audit.readonly",
    "familia": "workspace",
    "nombre": {
      "es": "Lectura del registro de auditoría",
      "en": "Read the audit log"
    },
    "lee": {
      "es": "Leer el registro de auditoría: qué aplicaciones de terceros se han autorizado, los cambios recientes de administración y los eventos de inicio de sesión.",
      "en": "Read the audit log: which third-party applications have been authorised, recent administrative changes, and sign-in events."
    },
    "checks": [
      "oauth_apps",
      "audit_log",
      "admin_logins",
      "login_security",
      "suspended_tokens",
      "backup_codes"
    ]
  },
  {
    "id": "https://www.googleapis.com/auth/cloud-identity.policies.readonly",
    "corto": "cloud-identity.policies.readonly",
    "familia": "workspace",
    "nombre": {
      "es": "Lectura de ajustes de la consola",
      "en": "Read console settings"
    },
    "lee": {
      "es": "Leer los ajustes que has configurado en la Consola de Administración (uso compartido de Drive, reenvío de Gmail, política de contraseñas, duración de sesión, Marketplace y Grupos) para comprobarlos automáticamente en lugar de pedirte que los mires a mano.",
      "en": "Read the settings configured in your Admin console (Drive sharing, Gmail forwarding, password policy, session length, Marketplace and Groups) so they are checked automatically instead of by hand."
    },
    "checks": [
      "policies",
      "alert_rules"
    ]
  }
] as const;

export const WORKSPACE_SCOPES = SCOPES.filter((s) => s.familia === "workspace");
export const IDENTITY_SCOPES = SCOPES.filter((s) => s.familia === "identidad");
