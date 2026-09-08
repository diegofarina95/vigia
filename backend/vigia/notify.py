"""Email alerts over SMTP. Standard library only — no paid API.

Alerts exist so scheduled scans are useful: nobody logs in to check a
dashboard every morning, but a mail saying "a new critical finding
appeared" gets acted on.

The customer's alert is bilingual: every sentence in it comes from the locale
catalogue, under `email.alerta`, and `lang` chooses. The operator's "new
company" notice at the bottom of this file is deliberately NOT — see the note
there.

The `NotifyError` messages stay Spanish literals as well. They are not an
e-mail: they surface in a log line and in the private tailnet console, both
read by the operator.
"""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate

from .config import Settings
from .i18n import DEFAULT_LANG, text
from .wording import contar

log = logging.getLogger(__name__)


def _t(lang: str, clave: str, **params) -> str:
    return text(lang, f"email.alerta.{clave}", **params)


def _severity_label(lang: str, severity: str) -> str:
    """Upper-case severity tag for a plain-text list, or the raw key.

    A severity the catalogue does not know keeps its key rather than printing a
    catalogue path into a customer's inbox.
    """
    etiqueta = _t(lang, f"severidad.{severity}")
    return severity if etiqueta.startswith("email.") else etiqueta


class NotifyError(Exception):
    pass


def smtp_configured(settings: Settings) -> bool:
    return bool(settings.smtp_host and settings.smtp_from)


def send_email(settings: Settings, to: str, subject: str, body: str) -> None:
    if not smtp_configured(settings):
        raise NotifyError("El SMTP no está configurado (define VIGIA_SMTP_HOST y VIGIA_SMTP_FROM).")
    if not to:
        raise NotifyError("No hay dirección de destino.")

    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = to
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=True)
    message.set_content(body)

    try:
        if settings.smtp_ssl:
            server = smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port, timeout=20,
                context=ssl.create_default_context(),
            )
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20)
        with server:
            if settings.smtp_starttls and not settings.smtp_ssl:
                server.starttls(context=ssl.create_default_context())
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise NotifyError(f"Falló el envío SMTP: {exc}") from exc


def _bullet_list(entries: list[dict], limit: int = 10, lang: str = DEFAULT_LANG) -> str:
    lines = [
        f"  - [{_severity_label(lang, e['severity'])}] {e['title']}"
        for e in entries[:limit]
    ]
    if len(entries) > limit:
        lines.append(_t(lang, "y_mas", n=len(entries) - limit))
    return "\n".join(lines)


def scan_alert_body(
    org: dict,
    scan: dict,
    previous_score: int | None,
    summary: dict,
    dashboard_url: str,
    lang: str = DEFAULT_LANG,
) -> tuple[str, str]:
    """Returns (subject, plain-text body) for a scan alert."""
    from .projection import score_explanation

    score = scan.get("score")
    counts = scan.get("counts", {})
    new_criticals = [e for e in summary.get("new", []) if e["severity"] == "critical"]
    explicacion = score_explanation((summary or {}).get("score_change"), summary)

    def asunto(texto: str) -> str:
        return f"[Vigía] {texto} — {org['primary_domain']}"

    if new_criticals:
        # Three words have to agree at once in Spanish, so each number has its
        # own entry rather than a noun with an adjective bolted on.
        subject = asunto(contar(lang, len(new_criticals), "email.alerta.criticos_nuevos"))
    elif summary.get("new"):
        subject = asunto(contar(lang, len(summary["new"]), "email.alerta.nuevos"))
    elif summary.get("worse"):
        subject = asunto(_t(lang, "asunto_empeorado"))
    elif summary.get("coverage_lost"):
        # Its own subject, because it is its own event: Vigía stopped being able
        # to check something. Filing this under "la postura ha empeorado" is how
        # a revoked scope or a single 429 from Google reached the customer as a
        # security alarm.
        subject = asunto(
            _t(lang, "asunto_cobertura_perdida", count=len(summary["coverage_lost"]))
        )
    else:
        subject = asunto(_t(lang, "asunto_informe"))

    # The subject used to be chosen from `worse` alone, so an e-mail whose body
    # read "+2" went out titled "La postura ha empeorado". Two sentences about
    # the same scan, computed from different inputs, neither consulting the other.
    if summary.get("worse") and (explicacion.get("total") or 0) > 0:
        subject = asunto(
            _t(lang, "asunto_puntuacion_al_alza", total=f"{explicacion['total']:+d}")
        )

    delta_line = ""
    if explicacion.get("headline"):
        delta_line = (
            _t(lang, "delta_anterior", cambio=f"{explicacion['total']:+d}")
            if explicacion.get("total")
            else ""
        )
    elif score is not None and previous_score is not None:
        change = score - previous_score
        if change:
            delta_line = _t(lang, "delta_anterior", cambio=f"{change:+d}")
    elif (summary or {}).get("engine_changed"):
        # Say it, rather than just omitting the number. An e-mail that quietly
        # drops the comparison reads as "nothing changed", which is the same
        # false statement by a different route.
        delta_line = _t(lang, "sin_comparativa")

    parts = [
        _t(lang, "cabecera", dominio=org["primary_domain"]),
        "",
        _t(
            lang,
            "puntuacion",
            valor=_t(lang, "sin_puntuacion") if score is None else score,
            delta=delta_line,
        ),
        _t(
            lang,
            "problemas_abiertos",
            detalle=", ".join(
                f"{counts.get(sev, 0)} {_t(lang, f'recuento.{sev}')}"
                for sev in ("critical", "high", "medium", "low")
            ),
        ),
        "",
    ]

    # Why the number moved, split by cause, before the findings — because "35,
    # +2" and "nada ha cambiado en tu organización" are compatible statements and
    # the customer cannot tell without being told.
    if explicacion.get("lines"):
        parts += [_t(lang, "titulo_porque")]
        parts += [f"  {linea}" for linea in explicacion["lines"] if linea]
        parts += [""]

    if summary.get("new"):
        parts += [_t(lang, "titulo_nuevos"), _bullet_list(summary["new"], lang=lang), ""]
    if summary.get("worse"):
        parts += [_t(lang, "titulo_empeorado"), _bullet_list(summary["worse"], lang=lang), ""]
    if summary.get("resolved"):
        parts += [
            _t(lang, "titulo_resueltos"),
            _bullet_list(summary["resolved"], lang=lang),
            "",
        ]

    # Kept apart from everything above, and worded so it cannot be read as a
    # change in the tenant. This block is what the 3 August e-mail should have
    # said instead of congratulating the customer for "resolving"
    # `suspended-with-tokens`, which had merely become readable.
    if summary.get("coverage_gained"):
        abiertos = [e for e in summary["coverage_gained"] if e.get("open")]
        parts += [
            _t(lang, "titulo_cobertura_ganada"),
            _t(lang, "nota_cobertura_ganada"),
            _bullet_list(summary["coverage_gained"], lang=lang),
            "",
        ]
        if abiertos:
            parts += [
                contar(lang, len(abiertos), "email.alerta.cobertura_abierta"),
                _t(lang, "nota_invisible"),
                "",
            ]
    if summary.get("coverage_lost"):
        parts += [
            _t(lang, "titulo_cobertura_perdida"),
            _t(lang, "nota_cobertura_perdida"),
            _bullet_list(summary["coverage_lost"], lang=lang),
            "",
        ]

    parts += [
        _t(lang, "informe_completo", url=dashboard_url),
        "",
        _t(lang, "firma"),
    ]
    return subject, "\n".join(parts)


# ───────────────────────────────────────────── aviso al operador: empresa nueva
#
# Spanish only, on purpose, and the only user-facing text in this module that is
# still a literal. Everything above is read by a customer, who may be reading in
# either language; this goes to VIGIA_OPERATOR_EMAIL, which is one person who
# reads Spanish. Putting it in the catalogue would mean maintaining an English
# half that nobody will ever open, and two wordings that can drift for an
# audience of one.


def nueva_empresa_asunto(org: dict) -> str:
    """Short and scannable in an inbox: the domain is the news."""
    return f"[Vigía] Empresa nueva: {org.get('primary_domain') or 'dominio desconocido'}"


def nueva_empresa_cuerpo(org: dict, scan: dict) -> str:
    """What the operator needs to decide whether to follow up, and nothing else.

    Deliberately NOT in here: the customer's findings, the e-mail addresses of
    their users, or anything else from inside their tenant. This is a business
    notification, so it carries the domain, the administrator who authorised the
    connection — the person to reply to — and the headline numbers. Their staff's
    personal data has no reason to travel to a second inbox, and the retention
    promise on /privacy is easier to keep when it never leaves the database.
    """
    counts = scan.get("counts") or {}
    resultado = scan.get("result") or {}
    personas = resultado.get("people") or []

    severidades = " · ".join(
        f"{counts.get(clave, 0)} {etiqueta}"
        for clave, etiqueta in (
            ("critical", "crítico"),
            ("high", "alto"),
            ("medium", "medio"),
            ("low", "bajo"),
        )
    )
    puntuacion = scan.get("score")
    lineas = [
        f"{org.get('primary_domain')} ha completado su primer análisis de seguridad.",
        "",
        f"Administrador que conectó: {org.get('admin_email') or '(desconocido)'}",
        f"Fecha del análisis:        {scan.get('created_at') or '(desconocida)'}",
        f"Puntuación:                {puntuacion if puntuacion is not None else 'sin determinar'} / 100",
        f"Hallazgos:                 {severidades}",
        f"Cuentas expuestas:         {len(personas)}",
        "",
        "Este aviso se envía una sola vez por organización: los análisis siguientes "
        "de esta misma empresa no generan otro correo.",
    ]
    return "\n".join(lineas)


def avisar_empresa_nueva(settings: Settings, db, org: dict, scan: dict) -> bool:
    """Tell the operator a new organisation ran its first analysis. Never raises.

    Returns True only if an e-mail actually went out.

    Order matters: the flag is claimed BEFORE sending. Claiming after would mean a
    send that succeeds and a write that fails leaves the flag unset, and the next
    scan sends the same alert again. This way the failure mode is a lost alert
    rather than a repeated one, which is the right way round for something whose
    only job is to tell you once.

    A failure here must never surface to the customer: they asked for an analysis,
    not for the operator's mail server to be working.
    """
    try:
        destino = (settings.operator_email or "").strip()
        if not destino:
            log.info("aviso de empresa nueva omitido: sin VIGIA_OPERATOR_EMAIL")
            return False
        if not smtp_configured(settings):
            log.info("aviso de empresa nueva omitido: SMTP sin configurar")
            return False
        if not db.claim_operator_alert(org["id"]):
            return False
        send_email(settings, destino, nueva_empresa_asunto(org), nueva_empresa_cuerpo(org, scan))
        log.info("avisado del alta de %s", org.get("primary_domain"))
        return True
    except Exception:  # noqa: BLE001 — an operator alert never breaks a scan
        log.exception("no se pudo avisar del alta de una empresa")
        return False
