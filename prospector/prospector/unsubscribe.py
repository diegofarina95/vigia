"""The unsubscribe endpoint — the one surface that is NOT on the tailnet.

Everything else in this module is an internal console reachable only over
Tailscale. This cannot be: the person clicking the link is the recipient, on the
public internet, and an unsubscribe link that only works from inside the operator's
private network is not an unsubscribe link. It is a link that fails, in an email
that legally has to carry a working one.

So it is a separate WSGI app, deliberately, with **one** route that changes
anything. Keeping it out of the console app means the public surface is this file
and nothing else: no import screen, no queue, no approve button reachable from
outside, and no chance of a future route accidentally inheriting public exposure.

One click. No login, no confirmation page, no "are you sure". The click itself is
the confirmation, and a confirmation step is how an unsubscribe quietly fails to
happen.

Idempotent: clicking twice, or a mail client prefetching the link, must not error.
Which is also why the token is single-purpose and unguessable rather than the
address in the URL — `?email=info@empresa.es` in a link is an invitation to
unsubscribe somebody else.
"""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from flask import Flask, Response

from .db import connect, is_suppressed, now, suppress, transaction

log = logging.getLogger("prospector.unsubscribe")

_PAGINA = """<!doctype html>
<html lang="{lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{titulo}</title>
<style>
 body{{font-family:ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
 line-height:1.6;max-width:34rem;margin:0 auto;padding:4rem 1.25rem;color:#1c2b36}}
 h1{{font-size:1.5rem;margin:0 0 .75rem}} p{{margin:.5rem 0}}
 .ok{{color:#1f6f4a;font-weight:600}}
 @media (prefers-color-scheme:dark){{body{{background:#0d1f2d;color:#c3d3de}}
 .ok{{color:#7fd1a8}}}}
</style></head><body>
<h1>{titulo}</h1>{cuerpo}
</body></html>"""

_TEXTOS = {
    "es": {
        "titulo": "Baja completada",
        "cuerpo": "<p class='ok'>Hecho. No volverás a recibir ningún correo mío.</p>"
                  "<p>La baja es permanente y afecta a todo el dominio, no solo a esta "
                  "dirección. No hace falta que hagas nada más.</p>",
        "titulo_no": "Enlace no válido",
        "cuerpo_no": "<p>Este enlace de baja no es válido o ya no existe.</p>"
                     "<p>Si sigues recibiendo correos míos, respóndele a cualquiera de "
                     "ellos con la palabra BAJA y lo resuelvo a mano.</p>",
    },
    "en": {
        "titulo": "Unsubscribed",
        "cuerpo": "<p class='ok'>Done. You will not receive any more email from me.</p>"
                  "<p>This is permanent and applies to the whole domain, not just this "
                  "address. There is nothing else you need to do.</p>",
        "titulo_no": "Invalid link",
        "cuerpo_no": "<p>This unsubscribe link is not valid, or no longer exists.</p>"
                     "<p>If you keep receiving email from me, reply to any of it with the "
                     "word UNSUBSCRIBE and I will sort it out by hand.</p>",
    },
}


def _pagina(lang: str, ok: bool) -> str:
    t = _TEXTOS.get(lang, _TEXTOS["es"])
    return _PAGINA.format(
        lang=lang,
        titulo=t["titulo"] if ok else t["titulo_no"],
        cuerpo=t["cuerpo"] if ok else t["cuerpo_no"],
    )


def process_unsubscribe(conn: sqlite3.Connection, token: str) -> tuple[bool, str]:
    """Suppress whoever this token belongs to. Returns (ok, lang).

    Suppresses the **domain**, not just the address: somebody asking not to be
    contacted is asking on behalf of their organisation, and honouring it for one
    mailbox while another one at the same company stays on the list is how the
    same person gets written to twice.
    """
    fila = conn.execute(
        "SELECT s.id, c.email, p.domain, p.country, p.id AS prospect_id "
        "FROM sends s JOIN contacts c ON c.id = s.contact_id "
        "JOIN prospects p ON p.id = c.prospect_id WHERE s.unsubscribe_token = ?",
        (token,),
    ).fetchone()
    if fila is None:
        return False, "es"

    from .templates import lang_for_country

    lang = lang_for_country(fila["country"])

    # Idempotent: a second click, or a mail client prefetching the link, finds it
    # already suppressed and still reports success. Reporting failure there would
    # tell somebody who did unsubscribe that they had not.
    if is_suppressed(conn, domain=fila["domain"], email=fila["email"]):
        return True, lang

    suppress(conn, domain=fila["domain"], reason=f"baja solicitada (envío {fila['id']})")
    with transaction(conn):
        conn.execute(
            "INSERT INTO replies (send_id, received_at, classification, notes) "
            "VALUES (?,?,'unsubscribe','un clic en el enlace de baja')",
            (fila["id"], now()),
        )
        conn.execute(
            "UPDATE sends SET status = 'blocked', blocked_reason = 'suppressed' "
            "WHERE status IN ('queued','approved') AND contact_id IN "
            "(SELECT id FROM contacts WHERE prospect_id = ?)",
            (fila["prospect_id"],),
        )
        conn.execute(
            "UPDATE prospects SET status = 'excluded' WHERE id = ?", (fila["prospect_id"],)
        )
    log.info("baja dominio=%s envio=%s", fila["domain"], fila["id"])
    return True, lang


def create_public_app(db_path: str | Path) -> Flask:
    """The public app. One route that acts, one that reports health."""
    app = Flask(__name__)

    @app.get("/baja/<token>")
    @app.get("/unsubscribe/<token>")
    def baja(token: str) -> Response:
        conn = connect(db_path)
        try:
            ok, lang = process_unsubscribe(conn, token)
        finally:
            conn.close()
        # 200 either way: an error page with a 404 status reads to a mail client
        # like a broken link, and the reader cannot tell the difference.
        return Response(_pagina(lang, ok), 200, {"Content-Type": "text/html; charset=utf-8",
                                                 "Cache-Control": "no-store"})

    @app.get("/salud")
    def salud() -> Response:
        return Response("ok", 200, {"Content-Type": "text/plain"})

    @app.errorhandler(404)
    def no_encontrada(_):  # noqa: ANN001
        return Response(_pagina("es", False), 200,
                        {"Content-Type": "text/html; charset=utf-8"})

    # POST is accepted because some mail clients and security scanners issue one.
    @app.post("/baja/<token>")
    def baja_post(token: str) -> Response:
        return baja(token)

    return app
