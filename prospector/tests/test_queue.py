"""The review queue.

The tests are almost all about refusal, and about one property in particular:
**every prospect that does not get queued gets blocked with a reason.** A prospect
that vanishes between the scan and the queue is indistinguishable from a bug.
"""
from __future__ import annotations

import pytest

from prospector import db
from prospector.pipeline import import_domains, scan_batch
from prospector.queue import (
    BLOCK_REASONS,
    approve,
    edit_send,
    queue_batch,
    queue_prospect,
    skip,
    suppress_prospect,
)
from prospector.scanner import FakeScanner, build_report
from prospector.signals import FakeSignals, SiteSignals
from prospector.templates import RenderError, seed_templates

SIN_DMARC = {"found": False, "status": "fail", "summary": "No DMARC record."}
REMITE = {
    "sender_name": "Diego Fariña",
    "sender_details": "Diego Fariña · NIF 00000000X · Calle Ejemplo 1, A Coruña",
    "unsubscribe_base_url": "https://example.invalid/baja",
}
BUEN_SITIO = "cdn.shopify.com <form><input type='email'></form>"


@pytest.fixture()
def conn(tmp_path):
    conexion = db.init(tmp_path / "p.db")
    seed_templates(conexion)
    yield conexion
    conexion.close()


def montar(conn, dominio="empresa.es", *, correo="info@empresa.es", sector="legal",
           html=BUEN_SITIO, dmarc=None, pais="ES"):
    """One prospect, imported, scanned and qualified."""
    import_domains(conn, [{"domain": dominio, "email": correo, "sector": sector,
                           "country": pais, "company_name": "Empresa SL"}])
    escaner = FakeScanner()
    escaner.add(dominio, build_report(dominio, mx=["a.mx", "b.mx"],
                                      dmarc=dmarc if dmarc is not None else SIN_DMARC))
    señales = FakeSignals({dominio: SiteSignals(domain=dominio, resolves=True, html=html)})
    scan_batch(conn, escaner, señales)
    return conn.execute("SELECT * FROM prospects WHERE domain = ?", (dominio,)).fetchone()


# --------------------------------------------------------------------------- #
# The happy path.
# --------------------------------------------------------------------------- #


def test_un_prospecto_bueno_se_encola(conn):
    p = montar(conn)
    r = queue_prospect(conn, p, **REMITE)
    assert r.queued and r.blocked is None

    envio = conn.execute("SELECT * FROM sends WHERE id = ?", (r.send_id,)).fetchone()
    assert envio["status"] == "queued"
    assert envio["sent_at"] is None
    assert "{" not in envio["body"]


def test_encolar_guarda_la_base_legal_y_la_justificacion(conn):
    """The answer to "why did you write to me" has to be a row, not a recollection."""
    p = montar(conn)
    r = queue_prospect(conn, p, **REMITE)
    envio = conn.execute("SELECT * FROM sends WHERE id = ?", (r.send_id,)).fetchone()
    assert envio["legal_basis"] == "legitimate_interest"
    assert "dmarc-missing" in envio["justification"]
    assert envio["justification"].strip() != "dmarc-missing:"


def test_cada_envio_lleva_su_propio_token_de_baja(conn):
    for d in ("una.es", "otra.es"):
        montar(conn, d, correo=f"info@{d}")
    filas = list(conn.execute("SELECT * FROM prospects WHERE status = 'scanned'"))
    resultados = queue_batch(conn, filas, **REMITE)
    tokens = {
        conn.execute("SELECT unsubscribe_token FROM sends WHERE id = ?",
                     (r.send_id,)).fetchone()["unsubscribe_token"]
        for r in resultados if r.queued
    }
    assert len(tokens) == 2 and all(tokens)


def test_el_enlace_de_baja_del_cuerpo_es_el_token_del_envio(conn):
    p = montar(conn)
    r = queue_prospect(conn, p, **REMITE)
    envio = conn.execute("SELECT * FROM sends WHERE id = ?", (r.send_id,)).fetchone()
    assert envio["unsubscribe_token"] in envio["body"]


# --------------------------------------------------------------------------- #
# Every way of being refused, each with a reason.
# --------------------------------------------------------------------------- #


def test_un_dominio_limpio_se_bloquea_no_desaparece(conn):
    p = montar(conn, "limpia.es", correo="info@limpia.es",
               dmarc={"found": True, "policy": "reject", "rua": ["mailto:a@b.es"]})
    r = queue_prospect(conn, p, **REMITE)
    assert r.blocked == "clean" and r.reason_text


def test_un_prospecto_sin_calificar_se_bloquea_con_su_puntuacion(conn):
    p = montar(conn, "barpepe.es", correo="info@barpepe.es", sector="hosteleria",
               html="<html>carta</html>")
    r = queue_prospect(conn, p, **REMITE)
    assert r.blocked == "unqualified"
    assert "puntuación" in r.reason_text


def test_sin_direccion_de_funcion_se_bloquea(conn):
    p = montar(conn, "empresa.es", correo="maria.gonzalez@empresa.es")
    r = queue_prospect(conn, p, **REMITE)
    assert r.blocked == "no-contact"


def test_un_dominio_suprimido_no_se_encola(conn):
    p = montar(conn)
    db.suppress(conn, domain="empresa.es", reason="pidió no ser contactada")
    assert queue_prospect(conn, p, **REMITE).blocked == "suppressed"


def test_una_direccion_suprimida_no_se_encola(conn):
    p = montar(conn)
    db.suppress(conn, email="info@empresa.es", reason="baja")
    assert queue_prospect(conn, p, **REMITE).blocked == "suppressed"


def test_no_se_escribe_dos_veces_al_mismo_prospecto(conn):
    p = montar(conn)
    r = queue_prospect(conn, p, **REMITE)
    with db.transaction(conn):
        conn.execute("UPDATE sends SET status='sent', sent_at=? WHERE id=?",
                     (db.now(), r.send_id))
    p = conn.execute("SELECT * FROM prospects WHERE domain='empresa.es'").fetchone()
    assert queue_prospect(conn, p, **REMITE).blocked == "already-contacted"


def test_un_borrador_pendiente_no_cuenta_como_contacto(conn):
    """Only `sent` counts. Otherwise a draft nobody approved makes the domain
    permanently unreachable."""
    p = montar(conn)
    queue_prospect(conn, p, **REMITE)
    p = conn.execute("SELECT * FROM prospects WHERE domain='empresa.es'").fetchone()
    assert queue_prospect(conn, p, **REMITE).blocked != "already-contacted"


def test_sin_escanear_se_bloquea(conn):
    import_domains(conn, [{"domain": "nueva.es", "email": "info@nueva.es"}])
    p = conn.execute("SELECT * FROM prospects WHERE domain='nueva.es'").fetchone()
    assert queue_prospect(conn, p, **REMITE).blocked == "not-scanned"


def test_una_carta_que_no_se_puede_completar_se_bloquea(conn):
    p = montar(conn)
    with db.transaction(conn):
        conn.execute("UPDATE templates SET body = body || ' {company_name} {domain}'")
        conn.execute("UPDATE prospects SET company_name = NULL WHERE id = ?", (p["id"],))
    p = conn.execute("SELECT * FROM prospects WHERE id = ?", (p["id"],)).fetchone()
    r = queue_prospect(conn, p, **REMITE)
    assert r.blocked == "render-failed"
    assert "company_name" in r.reason_text
    assert conn.execute("SELECT COUNT(*) FROM sends").fetchone()[0] == 0


def test_todos_los_motivos_de_bloqueo_tienen_explicacion():
    """The blocked view shows words, not slugs."""
    assert all(BLOCK_REASONS.values())


def test_ningun_prospecto_se_pierde_en_silencio(conn):
    """The property, over a mixed batch: queued + blocked == everybody."""
    montar(conn, "buena.es", correo="info@buena.es")
    montar(conn, "limpia.es", correo="info@limpia.es",
           dmarc={"found": True, "policy": "reject", "rua": ["mailto:a@b.es"]})
    montar(conn, "personal.es", correo="maria.gonzalez@personal.es")
    montar(conn, "floja.es", correo="info@floja.es", sector="hosteleria",
           html="<html>x</html>")

    filas = list(conn.execute("SELECT * FROM prospects ORDER BY domain"))
    resultados = queue_batch(conn, filas, **REMITE)
    assert len(resultados) == len(filas)
    assert all(r.queued or r.blocked for r in resultados)
    assert [r.domain for r in resultados if r.queued] == ["buena.es"]
    assert {r.domain: r.blocked for r in resultados if r.blocked} == {
        "limpia.es": "clean", "personal.es": "no-contact", "floja.es": "unqualified",
    }


# --------------------------------------------------------------------------- #
# What a person does to the queue.
# --------------------------------------------------------------------------- #


def test_aprobar_no_envia(conn):
    """The distinction the whole product rests on."""
    p = montar(conn)
    r = queue_prospect(conn, p, **REMITE)
    assert approve(conn, [r.send_id]) == 1
    envio = conn.execute("SELECT * FROM sends WHERE id = ?", (r.send_id,)).fetchone()
    assert envio["status"] == "approved"
    assert envio["sent_at"] is None
    assert envio["approved_at"] and envio["approved_by"]


def test_aprobar_en_bloque_cuenta_lo_que_movio(conn):
    for d in ("a.es", "b.es", "c.es"):
        montar(conn, d, correo=f"info@{d}")
    filas = list(conn.execute("SELECT * FROM prospects WHERE status='scanned'"))
    ids = [r.send_id for r in queue_batch(conn, filas, **REMITE) if r.queued]
    assert approve(conn, ids) == 3


def test_aprobar_dos_veces_no_resucita_nada(conn):
    """A double-click on a bulk button must not undo a skip."""
    p = montar(conn)
    r = queue_prospect(conn, p, **REMITE)
    skip(conn, r.send_id, "no me convence")
    assert approve(conn, [r.send_id]) == 0
    assert conn.execute("SELECT status FROM sends WHERE id=?",
                        (r.send_id,)).fetchone()["status"] == "skipped"


def test_aprobar_una_lista_vacia_no_hace_nada(conn):
    assert approve(conn, []) == 0


def test_editar_un_borrador(conn):
    p = montar(conn)
    r = queue_prospect(conn, p, **REMITE)
    envio = conn.execute("SELECT * FROM sends WHERE id=?", (r.send_id,)).fetchone()
    nuevo = envio["body"].replace("Hola,", "Buenos días,")
    assert edit_send(conn, r.send_id, "Otro asunto", nuevo)
    envio = conn.execute("SELECT * FROM sends WHERE id=?", (r.send_id,)).fetchone()
    assert envio["subject"] == "Otro asunto" and "Buenos días" in envio["body"]


def test_editar_no_puede_borrar_el_enlace_de_baja(conn):
    """The edit box is exactly where a legal requirement gets deleted by accident."""
    p = montar(conn)
    r = queue_prospect(conn, p, **REMITE)
    with pytest.raises(RenderError, match="baja"):
        edit_send(conn, r.send_id, "asunto", "Hola, sin enlace de baja.")


def test_no_se_edita_lo_ya_aprobado(conn):
    p = montar(conn)
    r = queue_prospect(conn, p, **REMITE)
    approve(conn, [r.send_id])
    envio = conn.execute("SELECT * FROM sends WHERE id=?", (r.send_id,)).fetchone()
    assert edit_send(conn, r.send_id, "x", envio["body"]) is False


def test_suprimir_cancela_lo_que_estuviera_en_cola(conn):
    p = montar(conn)
    r = queue_prospect(conn, p, **REMITE)
    suppress_prospect(conn, p["id"], reason="me lo pidieron")
    envio = conn.execute("SELECT * FROM sends WHERE id=?", (r.send_id,)).fetchone()
    assert envio["status"] == "blocked" and envio["blocked_reason"] == "suppressed"
    assert db.is_suppressed(conn, domain="empresa.es")


def test_suprimir_es_para_siempre_aunque_se_reimporte(conn):
    p = montar(conn)
    suppress_prospect(conn, p["id"])
    import_domains(conn, [{"domain": "empresa.es", "email": "info@empresa.es",
                           "sector": "legal"}])
    p = conn.execute("SELECT * FROM prospects WHERE domain='empresa.es'").fetchone()
    assert queue_prospect(conn, p, **REMITE).blocked == "suppressed"
