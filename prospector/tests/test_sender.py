"""Sending: the allowance, the checks, the retries and the bounces.

No test opens a socket. `SmtpPort` exists so that the thing which could email a
stranger during a test run simply is not there.
"""
from __future__ import annotations

from datetime import date, timedelta

import pytest

from prospector import db
from prospector.config import SenderIdentity, Settings
from prospector.pipeline import import_domains, scan_batch
from prospector.queue import approve, queue_prospect
from prospector.scanner import FakeScanner, build_report
from prospector.sender import (
    PermanentSmtpError,
    TransientSmtpError,
    bounce_rate,
    build_message,
    daily_allowance,
    parse_bounce,
    pre_send_checks,
    record_bounce,
    remaining_today,
    run_queue,
    send_one,
)
from prospector.signals import FakeSignals, SiteSignals
from prospector.templates import seed_templates

SIN_DMARC = {"found": False, "status": "fail", "summary": "No DMARC record."}
IDENT = SenderIdentity(
    name="Diego Fariña", company_number="00000000X",
    postal_address="Calle Ejemplo 1, 15001 A Coruña",
    email="diego@diegofarina.com", reply_to="diego@diegofarina.com",
)
REMITE = {
    "sender_name": IDENT.name,
    "sender_details": f"{IDENT.name} · NIF {IDENT.company_number} · {IDENT.postal_address}",
    "unsubscribe_base_url": "https://example.invalid/baja",
}


def ajustes(**kwargs) -> Settings:
    base = dict(
        bind_host="100.71.97.110", bind_port=8116, db_path="x.db", sender=IDENT,
        smtp_host="localhost", smtp_port=587, smtp_user="", smtp_password="",
        smtp_starttls=True, daily_cap=40, warmup_enabled=True, warmup_start=5,
        warmup_step=5, warmup_step_days=2, min_delay_seconds=90, max_delay_seconds=180,
        unsubscribe_base_url="https://example.invalid/baja",
    )
    return Settings(**{**base, **kwargs})


class SmtpFalso:
    def __init__(self, fallos=()):
        self.enviados = []
        self._fallos = list(fallos)

    def send(self, message):
        if self._fallos:
            fallo = self._fallos.pop(0)
            if fallo is not None:
                raise fallo
        self.enviados.append(message)


@pytest.fixture()
def conn(tmp_path):
    conexion = db.init(tmp_path / "p.db")
    seed_templates(conexion)
    yield conexion
    conexion.close()


def aprobado(conn, dominio="empresa.es", correo=None):
    """One approved send, ready to go out."""
    correo = correo or f"info@{dominio}"
    import_domains(conn, [{"domain": dominio, "email": correo, "sector": "legal",
                           "country": "ES", "company_name": "Empresa SL"}])
    escaner = FakeScanner()
    escaner.add(dominio, build_report(dominio, mx=["a.mx", "b.mx"], dmarc=SIN_DMARC))
    señales = FakeSignals({dominio: SiteSignals(
        domain=dominio, resolves=True,
        html="cdn.shopify.com <form><input type='email'></form>")})
    scan_batch(conn, escaner, señales)
    p = conn.execute("SELECT * FROM prospects WHERE domain = ?", (dominio,)).fetchone()
    r = queue_prospect(conn, p, **REMITE)
    approve(conn, [r.send_id])
    return r.send_id


# --------------------------------------------------------------------------- #
# Warm-up and the daily cap.
# --------------------------------------------------------------------------- #


def test_el_primer_dia_salen_cinco(conn):
    assert daily_allowance(ajustes(), conn) == 5


def test_la_rampa_sube_de_cinco_en_cinco_cada_dos_dias(conn):
    inicio = date(2026, 8, 1)
    with db.transaction(conn):
        conn.execute(
            "INSERT INTO prospects (domain, created_at) VALUES ('x.es', ?)", (db.now(),))
        conn.execute(
            "INSERT INTO contacts (prospect_id, email, address_type, created_at) "
            "VALUES (1,'info@x.es','role',?)", (db.now(),))
        conn.execute(
            "INSERT INTO scans (prospect_id, scanned_at, raw_findings) VALUES (1,?,'{}')",
            (db.now(),))
        conn.execute(
            "INSERT INTO sends (contact_id, scan_id, subject, body, status, queued_at, "
            "sent_at) VALUES (1,1,'s','b','sent',?,?)", (db.now(), inicio.isoformat()))

    s = ajustes()
    assert daily_allowance(s, conn, inicio) == 5
    assert daily_allowance(s, conn, inicio + timedelta(days=1)) == 5
    assert daily_allowance(s, conn, inicio + timedelta(days=2)) == 10
    assert daily_allowance(s, conn, inicio + timedelta(days=4)) == 15
    # …y nunca por encima del tope.
    assert daily_allowance(s, conn, inicio + timedelta(days=400)) == 40


def test_sin_rampa_se_usa_el_tope(conn):
    assert daily_allowance(ajustes(warmup_enabled=False), conn) == 40


def test_lo_ya_enviado_hoy_descuenta(conn):
    sid = aprobado(conn)
    smtp = SmtpFalso()
    send_one(conn, sid, ajustes(), smtp)
    assert remaining_today(ajustes(), conn) == 4


def test_agotado_el_cupo_no_sale_nada(conn):
    sid = aprobado(conn)
    smtp = SmtpFalso()
    assert run_queue(conn, ajustes(warmup_start=0, warmup_step=0), smtp,
                     sleep=lambda _: None) == []
    assert smtp.enviados == []


# --------------------------------------------------------------------------- #
# The checks, every one of them, every time.
# --------------------------------------------------------------------------- #


def test_un_envio_aprobado_y_correcto_pasa(conn):
    assert pre_send_checks(conn, aprobado(conn), ajustes()) is None


def test_no_se_envia_lo_que_no_esta_aprobado(conn):
    sid = aprobado(conn)
    with db.transaction(conn):
        conn.execute("UPDATE sends SET status='queued' WHERE id=?", (sid,))
    assert "no está aprobado" in pre_send_checks(conn, sid, ajustes())


def test_una_supresion_posterior_a_la_aprobacion_detiene_el_envio(conn):
    """The whole reason the checks run again: time passes between the two."""
    sid = aprobado(conn)
    db.suppress(conn, domain="empresa.es", reason="baja")
    assert pre_send_checks(conn, sid, ajustes()) == "suprimido"

    smtp = SmtpFalso()
    resultado = send_one(conn, sid, ajustes(), smtp)
    assert resultado.sent is False and resultado.blocked == "suprimido"
    assert smtp.enviados == []
    assert conn.execute("SELECT status FROM sends WHERE id=?",
                        (sid,)).fetchone()["status"] == "blocked"


def test_sin_enlace_de_baja_en_el_cuerpo_no_sale(conn):
    sid = aprobado(conn)
    with db.transaction(conn):
        conn.execute("UPDATE sends SET body='Hola, sin enlace.' WHERE id=?", (sid,))
    assert "enlace de baja" in pre_send_checks(conn, sid, ajustes())


def test_sin_token_de_baja_no_sale(conn):
    sid = aprobado(conn)
    with db.transaction(conn):
        conn.execute("UPDATE sends SET unsubscribe_token=NULL WHERE id=?", (sid,))
    assert pre_send_checks(conn, sid, ajustes()) == "sin token de baja"


def test_sin_identificacion_del_remitente_no_sale(conn):
    sid = aprobado(conn)
    vacio = SenderIdentity(name="", company_number="", postal_address="",
                           email="", reply_to="")
    assert "faltan datos del remitente" in pre_send_checks(conn, sid, ajustes(sender=vacio))


def test_un_cuerpo_que_no_identifica_al_remitente_no_sale(conn):
    sid = aprobado(conn)
    fila = conn.execute("SELECT unsubscribe_token FROM sends WHERE id=?", (sid,)).fetchone()
    with db.transaction(conn):
        conn.execute("UPDATE sends SET body=? WHERE id=?",
                     (f"Hola. https://example.invalid/baja/{fila['unsubscribe_token']}", sid))
    assert pre_send_checks(conn, sid, ajustes()) == "el cuerpo no identifica al remitente"


def test_una_carta_con_marcadores_sin_rellenar_no_sale(conn):
    sid = aprobado(conn)
    fila = conn.execute("SELECT body FROM sends WHERE id=?", (sid,)).fetchone()
    with db.transaction(conn):
        conn.execute("UPDATE sends SET body=? WHERE id=?",
                     (fila["body"] + "\nHola {company_name}", sid))
    assert "marcadores" in pre_send_checks(conn, sid, ajustes())


def test_una_direccion_personal_no_sale_aunque_este_aprobada(conn):
    sid = aprobado(conn)
    with db.transaction(conn):
        conn.execute("UPDATE contacts SET email='maria.gonzalez@empresa.es' "
                     "WHERE id=(SELECT contact_id FROM sends WHERE id=?)", (sid,))
    assert "dirección de función" in pre_send_checks(conn, sid, ajustes())


def test_no_se_escribe_dos_veces_al_mismo_prospecto(conn):
    sid = aprobado(conn)
    send_one(conn, sid, ajustes(), SmtpFalso())
    # Un segundo borrador para el mismo prospecto, forzado a mano y por lo demás
    # impecable: su cuerpo lleva su propio token, para que la comprobación que
    # salte sea la que se está probando y no una anterior.
    primero = conn.execute("SELECT * FROM sends WHERE id=?", (sid,)).fetchone()
    cuerpo = primero["body"].replace(primero["unsubscribe_token"], "otro-token")
    with db.transaction(conn):
        cur = conn.execute(
            "INSERT INTO sends (contact_id, scan_id, subject, body, status, "
            "unsubscribe_token, queued_at, approved_at) VALUES (?,?,?,?, 'approved', "
            "'otro-token', ?, ?)",
            (primero["contact_id"], primero["scan_id"], primero["subject"], cuerpo,
             db.now(), db.now()),
        )
        segundo = cur.lastrowid
    assert "ya se le escribió" in pre_send_checks(conn, segundo, ajustes())


# --------------------------------------------------------------------------- #
# The message itself.
# --------------------------------------------------------------------------- #


def test_el_mensaje_lleva_cabecera_de_baja_de_un_clic(conn):
    sid = aprobado(conn)
    fila = conn.execute(
        "SELECT s.*, c.email FROM sends s JOIN contacts c ON c.id=s.contact_id "
        "WHERE s.id=?", (sid,)).fetchone()
    mensaje = build_message(fila, ajustes())
    assert mensaje["List-Unsubscribe"].startswith("<https://")
    assert mensaje["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"
    assert fila["unsubscribe_token"] in mensaje["List-Unsubscribe"]


def test_el_mensaje_es_texto_plano(conn):
    """No HTML: it cannot carry a tracking pixel, which is the point."""
    sid = aprobado(conn)
    fila = conn.execute(
        "SELECT s.*, c.email FROM sends s JOIN contacts c ON c.id=s.contact_id "
        "WHERE s.id=?", (sid,)).fetchone()
    mensaje = build_message(fila, ajustes())
    assert mensaje.get_content_type() == "text/plain"
    assert not mensaje.is_multipart()
    assert "<img" not in mensaje.get_content()


# --------------------------------------------------------------------------- #
# Retries.
# --------------------------------------------------------------------------- #


def test_un_fallo_transitorio_se_reintenta(conn):
    sid = aprobado(conn)
    smtp = SmtpFalso([TransientSmtpError("451 try again"), None])
    resultado = send_one(conn, sid, ajustes(), smtp, sleep=lambda _: None)
    assert resultado.sent is True and resultado.attempts == 2


def test_un_fallo_permanente_no_se_reintenta(conn):
    sid = aprobado(conn)
    smtp = SmtpFalso([PermanentSmtpError("550 no such user")])
    resultado = send_one(conn, sid, ajustes(), smtp, sleep=lambda _: None)
    assert resultado.sent is False and resultado.attempts == 1
    assert conn.execute("SELECT status FROM sends WHERE id=?",
                        (sid,)).fetchone()["status"] == "failed"


def test_se_rinde_tras_los_intentos_configurados(conn):
    sid = aprobado(conn)
    smtp = SmtpFalso([TransientSmtpError("451")] * 3)
    resultado = send_one(conn, sid, ajustes(), smtp, max_attempts=3, sleep=lambda _: None)
    assert resultado.sent is False and resultado.attempts == 3


# --------------------------------------------------------------------------- #
# The batch.
# --------------------------------------------------------------------------- #


def test_la_tanda_espera_entre_envios(conn):
    for d in ("a.es", "b.es", "c.es"):
        aprobado(conn, d)
    esperas = []
    run_queue(conn, ajustes(), SmtpFalso(), sleep=esperas.append)
    # Two gaps for three messages, and none before the first.
    assert len(esperas) == 2
    assert all(90 <= e <= 180 for e in esperas)


def test_la_tanda_solo_envia_lo_aprobado(conn):
    aprobado(conn, "a.es")
    import_domains(conn, [{"domain": "b.es", "email": "info@b.es", "sector": "legal"}])
    smtp = SmtpFalso()
    resultados = run_queue(conn, ajustes(), smtp, sleep=lambda _: None)
    assert len(resultados) == 1 and len(smtp.enviados) == 1


# --------------------------------------------------------------------------- #
# Bounces.
# --------------------------------------------------------------------------- #


def test_un_rebote_duro_se_reconoce_y_suprime(conn):
    sid = aprobado(conn)
    send_one(conn, sid, ajustes(), SmtpFalso())
    rebote = record_bounce(
        conn, "Final-Recipient: rfc822; info@empresa.es\nStatus: 5.1.1\n"
              "550 5.1.1 User unknown")
    assert rebote is not None and rebote.hard is True
    assert db.is_suppressed(conn, email="info@empresa.es")


def test_un_rebote_blando_no_suprime(conn):
    sid = aprobado(conn)
    send_one(conn, sid, ajustes(), SmtpFalso())
    rebote = record_bounce(
        conn, "Final-Recipient: rfc822; info@empresa.es\nStatus: 4.2.2 mailbox full")
    assert rebote is not None and rebote.hard is False
    assert not db.is_suppressed(conn, email="info@empresa.es")


def test_un_rebote_que_no_se_entiende_se_trata_como_blando():
    """Auto-suppressing on a message we did not understand removes prospects for
    no reason, and the removal is permanent."""
    rebote = parse_bounce("algo raro ha pasado con info@empresa.es")
    assert rebote is not None and rebote.hard is False


def test_un_rebote_sin_direccion_no_hace_nada():
    assert parse_bounce("mensaje sin ninguna direccion") is None
    assert parse_bounce("") is None


def test_no_se_confunde_al_postmaster_con_el_destinatario():
    rebote = parse_bounce(
        "From: mailer-daemon@servidor.com\nTo: postmaster@servidor.com\n"
        "Final-Recipient: rfc822; info@empresa.es\nStatus: 5.1.1")
    assert rebote is not None and rebote.address == "info@empresa.es"


def test_la_tasa_de_rebote_se_calcula(conn):
    sid = aprobado(conn)
    send_one(conn, sid, ajustes(), SmtpFalso())
    assert bounce_rate(conn) == 0.0
    record_bounce(conn, "Final-Recipient: rfc822; info@empresa.es\nStatus: 5.1.1")
    assert bounce_rate(conn) == 1.0


def test_sin_envios_la_tasa_de_rebote_es_cero(conn):
    assert bounce_rate(conn) == 0.0


# --------------------------------------------------------------------------- #
# Placeholder sender details: explore the console, send nothing.
# --------------------------------------------------------------------------- #


def test_con_datos_de_relleno_la_consola_arranca_pero_no_se_envia(conn):
    """The convenience of starting without real details must not become a letter
    that identifies the sender falsely — which is worse than one that does not
    identify them at all, because it looks deliberate."""
    relleno = SenderIdentity(
        name="Diego Fariña", company_number="NIF-PENDIENTE",
        postal_address="DIRECCION-PENDIENTE", email="diego@diegofarina.com",
        reply_to="diego@diegofarina.com")
    s = ajustes(sender=relleno)
    s.validate()  # arranca: no lanza

    sid = aprobado(conn)
    motivo = pre_send_checks(conn, sid, s)
    assert motivo is not None and "relleno" in motivo

    smtp = SmtpFalso()
    resultado = send_one(conn, sid, s, smtp)
    assert resultado.sent is False
    assert smtp.enviados == []


def test_un_nif_de_verdad_no_se_confunde_con_relleno():
    real = SenderIdentity(name="Diego Fariña", company_number="12345678Z",
                          postal_address="Rúa Real 1, 15003 A Coruña",
                          email="d@x.com", reply_to="d@x.com")
    assert real.placeholders() == []
    assert real.ready_to_send is True
