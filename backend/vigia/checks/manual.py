"""Manual checks — fallback instructions for settings Vigía could not read
automatically. Spanish output.

Most of these are now read by the Cloud Identity Policy API (see
``check_policies``), which needs only a read-only, non-restricted scope.
Each entry declares the automated finding that supersedes it via
``automated_by``: when that finding comes back conclusive, the scan drops
the manual card, so the manual list shrinks to exactly what genuinely
still needs a human.
"""

MANUAL_CHECKS: list[dict] = [
    {
        "id": "manual-drive-sharing",
        "automated_by": "policy-drive-sharing",
        "title": "Uso compartido externo de Drive (valores por defecto)",
        "severity": "high",
        "area": "Google Drive",
        "why_manual": (
            "Aparece porque Vigía no ha podido leer este ajuste automáticamente. Concede el "
            "permiso de solo lectura de políticas (reconectando) y pasa a ser una comprobación "
            "automática."
        ),
        "instructions": [
            "Consola de Administración > Aplicaciones > Google Workspace > Drive y Documentos > "
            "Configuración de uso compartido.",
            "Pon «Uso compartido fuera de tu organización» en DESACTIVADO o solo con dominios de "
            "la lista de permitidos.",
            "Pon el uso compartido por enlace por defecto para los archivos nuevos en "
            "«Restringido» (no en «Cualquier persona con el enlace»).",
            "Activa los avisos cuando alguien comparta archivos fuera de la organización.",
        ],
        "admin_console_url": "https://admin.google.com/ac/home",
        "cis_control": "CIS GWS §4 (Drive) — Restringir el uso compartido externo",
    },
    {
        "id": "manual-gmail-routing",
        # No automated_by: the Policy API documents gmail.per_user_outbound_gateway
        # but exposes no routing-rule setting at all, and this tenant returns
        # none. There is nothing an automatic check could ever confirm here.
        "title": "Reglas de enrutamiento y pasarela de salida de Gmail",
        "severity": "high",
        "area": "Gmail",
        "why_manual": (
            "El Policy API no expone las reglas de enrutamiento, así que esto no se puede "
            "comprobar automáticamente ni pidiendo más permisos. Vale el minuto que cuesta: "
            "una regla de enrutamiento maliciosa es exfiltración que sobrevive a un cambio "
            "de contraseña, a un cierre de sesiones y a activar la verificación en dos "
            "pasos. Sigue copiando el correo hasta que alguien mire esta pantalla, y nadie "
            "la mira nunca."
        ),
        "instructions": [
            "Consola de Administración > Aplicaciones > Google Workspace > Gmail > "
            "Enrutamiento.",
            "Repasa una a una las reglas de «Enrutamiento», «Recipient address map» y "
            "«Enrutamiento de destinatarios»: cualquier regla que copie o desvíe correo a "
            "un dominio que no sea vuestro debe tener un dueño y un motivo escrito.",
            "Mira «Pasarelas de salida» (outbound gateway): si hay un servidor SMTP "
            "externo configurado, confirma que es el vuestro y no un relé que alguien dejó "
            "puesto.",
            "Comprueba también «Cumplimiento de contenido» por si hay una regla que envíe "
            "copia silenciosa de los mensajes que cumplan cierto patrón.",
            "Si encuentras algo que no reconoces, no lo borres sin más: apunta quién la "
            "creó y cuándo (aparece en el registro de auditoría) antes de quitarla.",
        ],
        "admin_console_url": "https://admin.google.com/ac/apps/gmail/routing",
        "cis_control": "CIS GWS §2 (Gmail) — Revisar el enrutamiento y las pasarelas de salida",
    },
    {
        "id": "manual-imap-pop",
        # Deliberately NOT automated_by: the policy checks for these two can
        # only ever come back undetermined for a tenant that never set them,
        # so tying the card to them would hide it the moment it is needed.
        "title": "Acceso IMAP y POP a Gmail",
        "severity": "high",
        "area": "Gmail",
        "why_manual": (
            "Vigía sí pide y tiene el permiso para leer este ajuste, y el identificador es el "
            "que documenta Google (gmail.imap_access y gmail.pop_access). Lo que pasa es otra "
            "cosa: tu organización nunca ha fijado una política explícita para ellos, y Google "
            "—a diferencia de casi todos los demás ajustes— no publica cuál es el valor por "
            "defecto ni lo devuelve por API. No hay nada que leer, así que decir «permitido» o "
            "«bloqueado» sería inventárselo. Se mira a mano en un minuto."
        ),
        "instructions": [
            "Consola de Administración > Aplicaciones > Google Workspace > Gmail > Acceso de "
            "usuario final.",
            "Mira «Acceso IMAP» y «Acceso POP». Desactiva los dos si nadie usa un cliente de "
            "correo de escritorio; casi nunca hace falta ninguno.",
            "Si necesitas IMAP, limítalo a los clientes de correo aprobados por OAuth en lugar "
            "de dejarlo abierto a cualquier cliente.",
            "Importante: estas dos vías entran con usuario y contraseña sin pasar por el "
            "desafío de la verificación en dos pasos, así que dejarlas abiertas anula buena "
            "parte de lo que te da la 2FA.",
        ],
        "admin_console_url": "https://admin.google.com/ac/apps/gmail/enduseraccess",
        "cis_control": "CIS GWS §2 (Gmail) — Desactivar los protocolos de acceso heredados",
    },
    {
        "id": "manual-gmail-forwarding",
        # Deliberately NOT automated_by: the org-wide policy is now a real
        # check (policy-gmail-forwarding), but the rules each person sets on
        # their own mailbox need a restricted Gmail scope this product will
        # never ask for. That half stays manual, and says so.
        "title": "Reglas de reenvío puestas por cada usuario",
        "severity": "high",
        "area": "Gmail",
        "why_manual": (
            "La política de reenvío de toda la organización ya se comprueba sola. Lo que no se "
            "puede leer es el reenvío que cada persona se haya configurado en su propio buzón: "
            "eso exigiría un permiso restringido de Gmail, y Vigía no lo pide ni lo va a pedir. "
            "Esa mitad se audita a mano con la Búsqueda en el registro de correo."
        ),
        "instructions": [
            "Consola de Administración > Aplicaciones > Google Workspace > Gmail > Acceso de "
            "usuario final.",
            "Valora desactivar el «Reenvío automático» en toda la organización o en las unidades "
            "organizativas sensibles.",
            "Informes > Búsqueda en el registro de correo: audita el correo reenviado a dominios "
            "externos.",
        ],
        "admin_console_url": "https://admin.google.com/ac/apps/gmail",
        "cis_control": "CIS GWS §3 (Gmail) — Restringir el reenvío automático",
    },
    {
        "id": "manual-marketplace",
        "automated_by": "policy-marketplace",
        "title": "Lista de aplicaciones permitidas de Google Workspace Marketplace",
        "severity": "medium",
        "area": "Aplicaciones",
        "why_manual": (
            "Aparece porque no se ha podido leer automáticamente la lista de aplicaciones "
            "permitidas de Marketplace."
        ),
        "instructions": [
            "Consola de Administración > Aplicaciones > Aplicaciones de Google Workspace "
            "Marketplace > Configuración.",
            "Elige «Permitir que los usuarios instalen solo aplicaciones de la lista de "
            "permitidas».",
            "Revisa las aplicaciones de Marketplace ya instaladas y quita las que no se usen.",
        ],
        "admin_console_url": "https://admin.google.com/ac/appslist/marketplace",
        "cis_control": "CIS GWS §2 — Controlar la instalación de aplicaciones de Marketplace",
    },
    {
        "id": "manual-password-policy",
        "automated_by": "policy-password",
        "title": "Política de longitud y reutilización de contraseñas",
        "severity": "medium",
        "area": "Autenticación",
        "why_manual": (
            "Aparece porque no se ha podido leer automáticamente la política de contraseñas."
        ),
        "instructions": [
            "Consola de Administración > Seguridad > Autenticación > Gestión de contraseñas.",
            "Pon la longitud mínima en 12 caracteres o más y aplícalo en el siguiente inicio de "
            "sesión.",
            "Desactiva la reutilización de contraseñas y evita los cambios periódicos "
            "obligatorios (recomendación del NIST).",
        ],
        "admin_console_url": "https://admin.google.com/ac/security/passwordmanagement",
        "cis_control": "CIS GWS §1 — Exigir una política de contraseñas robusta",
    },
]
