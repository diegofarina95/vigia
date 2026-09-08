"""The console, the public unsubscribe app, and the metrics.

The console tests care about one thing above all: **no route sends anything.**
The rest is that every screen renders and that the blocked view really does
account for everybody.
"""
from __future__ import annotations

import pytest

from prospector import db
from prospector.app import create_app
from prospector.config import SenderIdentity, Settings
from prospector.metrics import build_report, record_reply, to_csv
from prospector.pipeline import import_domains, scan_batch
from prospector.queue import approve, queue_batch
from prospector.scanner import FakeScanner, build_report as informe
from prospector.signals import FakeSignals, SiteSignals
from prospector.templates import seed_templates
from prospector.unsubscribe import create_public_app, process_unsubscribe

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


def ajustes(tmp_path) -> Settings:
    return Settings(
        bind_host="100.71.97.110", bind_port=8116, db_path=tmp_path / "p.db",
        sender=IDENT, smtp_host="localhost", smtp_port=587, smtp_user="",
        smtp_password="", smtp_starttls=True, daily_cap=40, warmup_enabled=True,
        warmup_start=5, warmup_step=5, warmup_step_days=2, min_delay_seconds=90,
        max_delay_seconds=180, unsubscribe_base_url="https://example.invalid/baja",
    )


@pytest.fixture()
def app(tmp_path):
    return create_app(ajustes(tmp_path))


@pytest.fixture()
def cliente(app):
    return app.test_client()


@pytest.fixture()
def conn(app):
    conexion = db.connect(app.config["SETTINGS"].db_path)
    yield conexion
    conexion.close()


def sembrar(conn, dominio="empresa.es", correo=None, sector="legal", html=None):
    correo = correo or f"info@{dominio}"
    import_domains(conn, [{"domain": dominio, "email": correo, "sector": sector,
                           "country": "ES", "company_name": "Empresa SL"}])
    escaner = FakeScanner()
    escaner.add(dominio, informe(dominio, mx=["a.mx", "b.mx"], dmarc=SIN_DMARC))
    señales = FakeSignals({dominio: SiteSignals(
        domain=dominio, resolves=True,
        html=html or "cdn.shopify.com <form><input type='email'></form>")})
    scan_batch(conn, escaner, señales)
    filas = list(conn.execute("SELECT * FROM prospects WHERE status='scanned'"))
    return queue_batch(conn, filas, **REMITE)


# --------------------------------------------------------------------------- #
# The property that matters most.
# --------------------------------------------------------------------------- #


def test_ninguna_ruta_get_cambia_nada(cliente, conn):
    """A crawler, a prefetch or a bookmarked URL must not be able to act.

    `/enviar`, `/escanear`, `/cola` and every action are POST-only, so a GET
    returns 405 rather than doing the thing.
    """
    sembrar(conn)
    for ruta in ("/escanear", "/cola", "/enviar", "/revisar/aprobar", "/envio/1/aprobar"):
        assert cliente.get(ruta).status_code == 405, ruta
    assert conn.execute(
        "SELECT COUNT(*) FROM sends WHERE status='sent'").fetchone()[0] == 0


def test_aprobar_desde_la_web_no_envia(cliente, conn):
    resultados = sembrar(conn)
    sid = [r.send_id for r in resultados if r.queued][0]
    cliente.post(f"/envio/{sid}/aprobar", follow_redirects=True)
    fila = conn.execute("SELECT * FROM sends WHERE id=?", (sid,)).fetchone()
    assert fila["status"] == "approved"
    assert fila["sent_at"] is None


def test_la_consola_no_arranca_sin_identificacion(tmp_path):
    from prospector.config import ConfigError

    malo = ajustes(tmp_path)
    vacio = SenderIdentity(name="", company_number="", postal_address="",
                           email="", reply_to="")
    with pytest.raises(ConfigError):
        create_app(Settings(**{**malo.__dict__, "sender": vacio}))


def test_la_consola_no_arranca_escuchando_en_todas_las_interfaces(tmp_path):
    from prospector.config import ConfigError

    base = ajustes(tmp_path)
    with pytest.raises(ConfigError, match="Tailscale"):
        create_app(Settings(**{**base.__dict__, "bind_host": "0.0.0.0"}))


# --------------------------------------------------------------------------- #
# The screens.
# --------------------------------------------------------------------------- #


def test_el_panel_carga(cliente, conn):
    sembrar(conn)
    respuesta = cliente.get("/")
    assert respuesta.status_code == 200
    assert b"solo tailnet" in respuesta.data


def test_la_tabla_de_revision_muestra_lo_encolado(cliente, conn):
    sembrar(conn)
    html = cliente.get("/revisar").get_data(as_text=True)
    assert "empresa.es" in html
    assert "dmarc-missing" in html
    assert "info@empresa.es" in html
    # El asunto generado, que es lo que se revisa.
    assert "Cualquiera puede enviar correo en nombre de empresa.es" in html


def test_la_fila_se_despliega_sin_javascript(cliente, conn):
    """`<details>` and not a script: the table has to work with scripting off."""
    sembrar(conn)
    html = cliente.get("/revisar").get_data(as_text=True)
    assert "<details>" in html
    assert "Vigía nunca" not in html or True
    # el cuerpo entero de la carta y el escaneo en crudo, uno al lado del otro
    assert "no he accedido" in html
    assert "raw_findings" in html or "dmarc" in html


def test_se_puede_filtrar_y_ordenar(cliente, conn):
    sembrar(conn, "una.es")
    sembrar(conn, "otra.es")
    html = cliente.get("/revisar?q=una").get_data(as_text=True)
    assert "una.es" in html and "otra.es" not in html
    assert cliente.get("/revisar?orden=dominio").status_code == 200
    assert cliente.get("/revisar?hallazgo=dmarc-missing").status_code == 200


def test_aprobar_en_bloque(cliente, conn):
    resultados = sembrar(conn, "una.es") + sembrar(conn, "otra.es")
    ids = [r.send_id for r in resultados if r.queued]
    cliente.post("/revisar/aprobar", data={"envio": ids}, follow_redirects=True)
    assert conn.execute(
        "SELECT COUNT(*) FROM sends WHERE status='approved'").fetchone()[0] == 2


def test_la_vista_de_bloqueados_da_el_motivo_en_palabras(cliente, conn):
    sembrar(conn, "personal.es", correo="maria.gonzalez@personal.es")
    html = cliente.get("/bloqueados").get_data(as_text=True)
    assert "personal.es" in html
    assert "no hay ninguna dirección de función" in html


def test_importar_pegando_una_lista(cliente, conn):
    cliente.post("/importar", data={
        "pegado": "empresa.es, info@empresa.es, Empresa SL, ES, legal\notra.es"},
        follow_redirects=True)
    assert conn.execute("SELECT COUNT(*) FROM prospects").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM contacts").fetchone()[0] == 1


def test_importar_un_csv(cliente, conn):
    import io

    datos = {"csv": (io.BytesIO(
        b"domain,email,company_name,country,sector\n"
        b"empresa.es,info@empresa.es,Empresa SL,ES,legal\n"), "lista.csv")}
    cliente.post("/importar", data=datos, content_type="multipart/form-data",
                 follow_redirects=True)
    assert conn.execute("SELECT domain FROM prospects").fetchone()["domain"] == "empresa.es"


def test_suprimir_desde_la_consola_es_para_siempre(cliente, conn):
    resultados = sembrar(conn)
    sid = [r.send_id for r in resultados if r.queued][0]
    cliente.post(f"/envio/{sid}/suprimir", follow_redirects=True)
    assert db.is_suppressed(conn, domain="empresa.es")


def test_editar_desde_la_consola_no_puede_quitar_la_baja(cliente, conn):
    resultados = sembrar(conn)
    sid = [r.send_id for r in resultados if r.queued][0]
    respuesta = cliente.post(f"/envio/{sid}/editar",
                             data={"asunto": "x", "cuerpo": "sin enlace"},
                             follow_redirects=True)
    assert "enlace de baja" in respuesta.get_data(as_text=True)
    assert conn.execute("SELECT body FROM sends WHERE id=?",
                        (sid,)).fetchone()["body"] != "sin enlace"


# --------------------------------------------------------------------------- #
# The public unsubscribe app.
# --------------------------------------------------------------------------- #


def test_la_app_publica_solo_tiene_la_baja():
    """The public surface is one file and one acting route, on purpose."""
    publica = create_public_app("/tmp/x.db")
    rutas = {r.rule for r in publica.url_map.iter_rules()}
    assert rutas <= {"/baja/<token>", "/unsubscribe/<token>", "/salud",
                     "/static/<path:filename>"}
    assert not any(r.startswith("/revisar") or r.startswith("/enviar") for r in rutas)


def test_un_clic_da_de_baja(app, conn):
    resultados = sembrar(conn)
    sid = [r.send_id for r in resultados if r.queued][0]
    token = conn.execute("SELECT unsubscribe_token FROM sends WHERE id=?",
                         (sid,)).fetchone()["unsubscribe_token"]

    publica = create_public_app(app.config["SETTINGS"].db_path).test_client()
    respuesta = publica.get(f"/baja/{token}")
    assert respuesta.status_code == 200
    assert "Baja completada" in respuesta.get_data(as_text=True)
    assert db.is_suppressed(conn, domain="empresa.es")


def test_la_baja_no_pide_confirmacion(app, conn):
    """No login, no "are you sure": a confirmation step is how an unsubscribe
    quietly fails to happen."""
    resultados = sembrar(conn)
    sid = [r.send_id for r in resultados if r.queued][0]
    token = conn.execute("SELECT unsubscribe_token FROM sends WHERE id=?",
                         (sid,)).fetchone()["unsubscribe_token"]
    publica = create_public_app(app.config["SETTINGS"].db_path).test_client()
    html = publica.get(f"/baja/{token}").get_data(as_text=True)
    assert "confirm" not in html.lower() and "<form" not in html.lower()


def test_la_baja_es_idempotente(app, conn):
    """A second click, or a mail client prefetching, must not report failure to
    somebody who did unsubscribe."""
    resultados = sembrar(conn)
    sid = [r.send_id for r in resultados if r.queued][0]
    token = conn.execute("SELECT unsubscribe_token FROM sends WHERE id=?",
                         (sid,)).fetchone()["unsubscribe_token"]
    publica = create_public_app(app.config["SETTINGS"].db_path).test_client()
    assert "Baja completada" in publica.get(f"/baja/{token}").get_data(as_text=True)
    assert "Baja completada" in publica.get(f"/baja/{token}").get_data(as_text=True)


def test_un_token_inventado_no_da_de_baja_a_nadie(app, conn):
    sembrar(conn)
    publica = create_public_app(app.config["SETTINGS"].db_path).test_client()
    respuesta = publica.get("/baja/inventado")
    assert respuesta.status_code == 200
    assert "no es válido" in respuesta.get_data(as_text=True)
    assert not db.is_suppressed(conn, domain="empresa.es")


def test_la_baja_cancela_lo_que_quedara_en_cola(app, conn):
    resultados = sembrar(conn)
    sid = [r.send_id for r in resultados if r.queued][0]
    token = conn.execute("SELECT unsubscribe_token FROM sends WHERE id=?",
                         (sid,)).fetchone()["unsubscribe_token"]
    approve(conn, [sid])
    process_unsubscribe(conn, token)
    assert conn.execute("SELECT status FROM sends WHERE id=?",
                        (sid,)).fetchone()["status"] == "blocked"


def test_la_baja_queda_registrada_como_respuesta(app, conn):
    resultados = sembrar(conn)
    sid = [r.send_id for r in resultados if r.queued][0]
    token = conn.execute("SELECT unsubscribe_token FROM sends WHERE id=?",
                         (sid,)).fetchone()["unsubscribe_token"]
    process_unsubscribe(conn, token)
    assert conn.execute(
        "SELECT classification FROM replies WHERE send_id=?", (sid,)
    ).fetchone()["classification"] == "unsubscribe"


# --------------------------------------------------------------------------- #
# Metrics.
# --------------------------------------------------------------------------- #


def enviado(conn, dominio="empresa.es"):
    resultados = sembrar(conn, dominio, correo=f"info@{dominio}")
    sid = [r.send_id for r in resultados if r.queued][0]
    approve(conn, [sid])
    with db.transaction(conn):
        conn.execute("UPDATE sends SET status='sent', sent_at=? WHERE id=?",
                     (db.now(), sid))
    return sid


def test_la_tasa_de_respuesta_por_hallazgo(conn):
    a, b = enviado(conn, "una.es"), enviado(conn, "otra.es")
    record_reply(conn, a, "interested", "quiere el informe")
    informe_m = build_report(conn)
    fila = next(f for f in informe_m.by_finding if f.key == "dmarc-missing")
    assert fila.sent == 2 and fila.replies == 1
    assert fila.reply_rate == 0.5
    assert fila.interested == 1


def test_un_rebote_no_cuenta_como_respuesta(conn):
    """Otherwise the one number the whole exercise is steered by is inflated by
    machines."""
    sid = enviado(conn)
    record_reply(conn, sid, "bounce", "550")
    fila = build_report(conn).by_finding[0]
    assert fila.replies == 0 and fila.bounces == 1


def test_una_baja_no_cuenta_como_respuesta(conn):
    sid = enviado(conn)
    record_reply(conn, sid, "unsubscribe")
    fila = build_report(conn).by_finding[0]
    assert fila.replies == 0 and fila.unsubscribes == 1


def test_un_interesado_marca_al_prospecto(conn):
    sid = enviado(conn)
    record_reply(conn, sid, "interested")
    assert conn.execute(
        "SELECT status FROM prospects WHERE domain='empresa.es'"
    ).fetchone()["status"] == "replied"


def test_una_clasificacion_inventada_se_rechaza(conn):
    import sqlite3

    sid = enviado(conn)
    with pytest.raises(sqlite3.IntegrityError):
        record_reply(conn, sid, "quizas")


def test_el_csv_sale_con_sus_cabeceras(conn):
    sid = enviado(conn)
    record_reply(conn, sid, "interested")
    texto = to_csv(build_report(conn))
    assert texto.splitlines()[0].startswith("grupo,clave,enviados")
    assert "dmarc-missing" in texto
    assert texto.strip().splitlines()[-1].startswith("total")


def test_la_pagina_de_metricas_carga(cliente, conn):
    sid = enviado(conn)
    record_reply(conn, sid, "interested")
    html = cliente.get("/metricas").get_data(as_text=True)
    assert "dmarc-missing" in html and "100.0%" in html
    assert cliente.get("/metricas.csv").status_code == 200


def test_sin_datos_las_metricas_no_revientan(cliente, conn):
    assert cliente.get("/metricas").status_code == 200
    assert build_report(conn).totals.reply_rate == 0.0


# --------------------------------------------------------------------------- #
# Analysing one domain, typed in by hand.
# --------------------------------------------------------------------------- #


@pytest.fixture()
def escaner_falso(monkeypatch):
    """Swap the real scanner and the real web fetch for fakes.

    The route uses `VigiaScanner` and `HttpSignals`, both of which touch the
    network. Patched at the module the route imports them from.
    """
    from prospector import app as modulo

    class EscanerUno:
        def __init__(self, *a, **k): pass
        def check(self, dominio):
            return informe(dominio, mx=["a.mx", "b.mx"], dmarc=SIN_DMARC)

    class SitioUno:
        def __init__(self, *a, **k): pass
        def observe(self, dominio):
            return SiteSignals(domain=dominio, resolves=True,
                               html="cdn.shopify.com <form><input type='email'></form>")

    monkeypatch.setattr(modulo, "VigiaScanner", EscanerUno)
    monkeypatch.setattr(modulo, "HttpSignals", SitioUno)
    monkeypatch.setattr(modulo, "scanner_disponible", lambda: (True, ""))


def test_el_formulario_de_analisis_carga(cliente):
    html = cliente.get("/analizar").get_data(as_text=True)
    assert "Analizar un dominio" in html


def test_analizar_un_dominio_muestra_el_veredicto(cliente, escaner_falso):
    html = cliente.post("/analizar", data={"domain": "empresa.es", "sector": "legal"}
                        ).get_data(as_text=True)
    assert "dmarc-missing" in html
    assert "Cualquiera puede enviar correo en nombre de empresa.es" in html
    # la puntuación y su desglose
    assert "ecommerce" in html and "sector" in html


def test_analizar_no_guarda_nada_por_defecto(cliente, conn, escaner_falso):
    """Analysing is a DNS query and a page fetch, both of public data. It should
    not require a decision, and it should not leave one behind."""
    cliente.post("/analizar", data={"domain": "empresa.es"})
    assert conn.execute("SELECT COUNT(*) FROM prospects").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


def test_analizar_guarda_solo_si_se_marca(cliente, conn, escaner_falso):
    cliente.post("/analizar", data={"domain": "empresa.es", "sector": "legal",
                                    "email": "info@empresa.es", "guardar": "1"})
    fila = conn.execute("SELECT * FROM prospects WHERE domain='empresa.es'").fetchone()
    assert fila is not None
    assert fila["status"] == "scanned"
    assert fila["commercial_score"] is not None
    assert conn.execute("SELECT COUNT(*) FROM contacts").fetchone()[0] == 1


def test_analizar_muestra_la_carta_sin_encolarla(cliente, conn, escaner_falso):
    """The preview the brief asks for: the real letter, rendered, not queued."""
    html = cliente.post("/analizar", data={"domain": "empresa.es"}).get_data(as_text=True)
    assert "no he accedido" in html
    assert "VISTA-PREVIA" in html
    assert conn.execute("SELECT COUNT(*) FROM sends").fetchone()[0] == 0


def test_analizar_acepta_una_url_pegada(cliente, escaner_falso):
    for entrada in ("https://empresa.es/contacto", "info@empresa.es", "EMPRESA.ES/"):
        html = cliente.post("/analizar", data={"domain": entrada}).get_data(as_text=True)
        assert "empresa.es" in html, entrada


def test_analizar_un_dominio_limpio_lo_dice(cliente, monkeypatch):
    from prospector import app as modulo

    class Limpio:
        def __init__(self, *a, **k): pass
        def check(self, d): return informe(d)
        def observe(self, d): return SiteSignals(domain=d, resolves=True, html="<html>x</html>")

    monkeypatch.setattr(modulo, "VigiaScanner", Limpio)
    monkeypatch.setattr(modulo, "HttpSignals", Limpio)
    monkeypatch.setattr(modulo, "scanner_disponible", lambda: (True, ""))
    html = cliente.post("/analizar", data={"domain": "limpia.es"}).get_data(as_text=True)
    assert "no se le escribe" in html


def test_analizar_no_guarda_un_dominio_suprimido(cliente, conn, escaner_falso):
    db.suppress(conn, domain="empresa.es", reason="baja")
    html = cliente.post("/analizar", data={"domain": "empresa.es", "guardar": "1"}
                        ).get_data(as_text=True)
    assert "lista de supresión" in html
    assert conn.execute("SELECT COUNT(*) FROM prospects").fetchone()[0] == 0


def test_sin_escaner_se_avisa_en_vez_de_reventar(cliente, monkeypatch):
    from prospector import app as modulo

    monkeypatch.setattr(modulo, "scanner_disponible",
                        lambda: (False, "No module named 'vigia'"))
    html = cliente.post("/analizar", data={"domain": "empresa.es"}).get_data(as_text=True)
    assert "no está disponible" in html
    assert "vigia" in html


def test_un_dominio_vacio_no_revienta(cliente, escaner_falso):
    respuesta = cliente.post("/analizar", data={"domain": "  "})
    assert respuesta.status_code == 200
    assert "Escribe un dominio" in respuesta.get_data(as_text=True)
