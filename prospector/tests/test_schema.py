"""The schema, and the guarantees it enforces rather than documents."""
from __future__ import annotations

import json
import sqlite3

import pytest

from prospector import db
from prospector.catalog import CATALOG, RULES
from prospector.prioritise import select_primary_finding
from prospector.scanner import build_report


@pytest.fixture()
def conn(tmp_path):
    conexion = db.init(tmp_path / "prospector.db")
    yield conexion
    conexion.close()


def test_se_crean_todas_las_tablas(conn):
    tablas = {
        r["name"]
        for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {
        "prospects", "contacts", "scans", "findings_catalog",
        "templates", "sends", "suppressions", "replies",
    } <= tablas


def test_migrar_dos_veces_no_rompe_nada(tmp_path):
    ruta = tmp_path / "p.db"
    db.init(ruta).close()
    conexion = db.init(ruta)          # otra vez, como en cada arranque
    assert conexion.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    conexion.close()


def test_el_catalogo_se_siembra_en_los_dos_idiomas(conn):
    total = conn.execute("SELECT COUNT(*) FROM findings_catalog").fetchone()[0]
    assert total == len(CATALOG) == len(RULES) * 2


def test_sembrar_dos_veces_actualiza_en_vez_de_duplicar(conn):
    antes = conn.execute("SELECT COUNT(*) FROM findings_catalog").fetchone()[0]
    db.seed_catalog(conn)
    assert conn.execute("SELECT COUNT(*) FROM findings_catalog").fetchone()[0] == antes


# --------------------------------------------------------------------------- #
# Suppressions. Permanent means the database refuses, not that the code is
# careful.
# --------------------------------------------------------------------------- #


def test_una_supresion_no_se_puede_borrar(conn):
    db.suppress(conn, domain="empresa.com", reason="pidió no ser contactada")
    with pytest.raises(sqlite3.IntegrityError, match="permanent"):
        with db.transaction(conn):
            conn.execute("DELETE FROM suppressions")
    assert db.is_suppressed(conn, domain="empresa.com")


def test_una_supresion_no_se_puede_editar(conn):
    db.suppress(conn, email="info@empresa.com", reason="baja")
    with pytest.raises(sqlite3.IntegrityError, match="permanent"):
        with db.transaction(conn):
            conn.execute("UPDATE suppressions SET email = 'otra@x.com'")
    assert db.is_suppressed(conn, email="info@empresa.com")


def test_suprimir_un_dominio_suprime_cualquier_direccion_suya(conn):
    """Somebody asking not to be contacted is asking for their organisation, not
    for the one mailbox that happened to receive the message."""
    db.suppress(conn, domain="empresa.com", reason="baja")
    assert db.is_suppressed(conn, email="info@empresa.com")
    assert db.is_suppressed(conn, email="cualquier.otra@empresa.com")
    assert not db.is_suppressed(conn, email="info@otra-empresa.com")


def test_la_supresion_ignora_mayusculas(conn):
    db.suppress(conn, email="Info@Empresa.COM", reason="baja")
    assert db.is_suppressed(conn, email="info@empresa.com")


def test_suprimir_dos_veces_es_idempotente(conn):
    db.suppress(conn, domain="empresa.com", reason="baja")
    db.suppress(conn, domain="empresa.com", reason="baja otra vez")
    assert conn.execute("SELECT COUNT(*) FROM suppressions").fetchone()[0] == 1


def test_una_supresion_vacia_se_rechaza(conn):
    with pytest.raises(ValueError):
        db.suppress(conn, reason="ninguno")


# --------------------------------------------------------------------------- #
# Enumerations are constraints, so a typo fails loudly instead of hiding a row.
# --------------------------------------------------------------------------- #


def test_un_estado_invalido_se_rechaza(conn):
    pid = db.add_prospect(conn, domain="empresa.com")
    with pytest.raises(sqlite3.IntegrityError):
        with db.transaction(conn):
            conn.execute("UPDATE prospects SET status = 'inventado' WHERE id = ?", (pid,))


def test_un_tipo_de_direccion_invalido_se_rechaza(conn):
    pid = db.add_prospect(conn, domain="empresa.com")
    with pytest.raises(sqlite3.IntegrityError):
        with db.transaction(conn):
            conn.execute(
                "INSERT INTO contacts (prospect_id, email, address_type, created_at) "
                "VALUES (?,?,?,?)",
                (pid, "info@empresa.com", "otro", db.now()),
            )


# --------------------------------------------------------------------------- #
# Transactions.
# --------------------------------------------------------------------------- #


def test_una_transaccion_fallida_no_deja_nada_a_medias(conn):
    with pytest.raises(RuntimeError):
        with db.transaction(conn):
            conn.execute(
                "INSERT INTO prospects (domain, created_at) VALUES ('a.com', ?)", (db.now(),)
            )
            raise RuntimeError("algo se tuerce a mitad")
    assert conn.execute("SELECT COUNT(*) FROM prospects").fetchone()[0] == 0


# --------------------------------------------------------------------------- #
# Writing a prospect, a contact and a scan.
# --------------------------------------------------------------------------- #


def test_un_dominio_repetido_no_crea_un_segundo_prospecto(conn):
    primero = db.add_prospect(conn, domain="Empresa.com", company_name="Empresa")
    segundo = db.add_prospect(conn, domain="empresa.com")
    assert primero == segundo
    assert conn.execute("SELECT COUNT(*) FROM prospects").fetchone()[0] == 1


def test_el_contacto_se_clasifica_al_entrar(conn):
    pid = db.add_prospect(conn, domain="empresa.com")
    db.add_contact(conn, pid, "info@empresa.com")
    db.add_contact(conn, pid, "maria.gonzalez@empresa.com")
    filas = {
        r["email"]: (r["address_type"], r["is_valid"])
        for r in conn.execute("SELECT email, address_type, is_valid FROM contacts")
    }
    assert filas["info@empresa.com"] == ("role", 1)
    # Stored, not discarded: the blocked view has to be able to say what it refused.
    assert filas["maria.gonzalez@empresa.com"] == ("personal", 0)


def test_un_escaneo_guarda_el_informe_entero_y_el_hallazgo(conn):
    pid = db.add_prospect(conn, domain="empresa.com")
    report = build_report("empresa.com", dmarc={"found": False, "status": "fail",
                                                "summary": "No DMARC record."})
    finding = select_primary_finding(report)
    sid = db.record_scan(conn, pid, report, finding)

    fila = conn.execute("SELECT * FROM scans WHERE id = ?", (sid,)).fetchone()
    assert fila["primary_finding_code"] == "dmarc-missing"
    assert fila["severity"] == 1
    assert json.loads(fila["all_finding_codes"]) == ["dmarc-missing"]
    # The evidence, verbatim, as it was on the day.
    assert json.loads(fila["raw_findings"])["dmarc"]["found"] is False
    assert conn.execute(
        "SELECT status FROM prospects WHERE id = ?", (pid,)
    ).fetchone()["status"] == "scanned"


def test_un_dominio_limpio_se_guarda_como_excluido(conn):
    pid = db.add_prospect(conn, domain="limpia.com")
    report = build_report("limpia.com")
    db.record_scan(conn, pid, report, select_primary_finding(report))
    assert conn.execute(
        "SELECT status FROM prospects WHERE id = ?", (pid,)
    ).fetchone()["status"] == "excluded"


def test_no_se_puede_encolar_un_envio_a_un_contacto_inexistente(conn):
    with pytest.raises(sqlite3.IntegrityError):
        with db.transaction(conn):
            conn.execute(
                "INSERT INTO sends (contact_id, scan_id, subject, body, queued_at) "
                "VALUES (999, 999, 's', 'b', ?)", (db.now(),)
            )


def test_el_rango_de_la_tabla_y_el_del_catalogo_coinciden(conn):
    """`severity_rank` lives in two tables, so a test has to make them agree.

    `finding_codes` is what a scan points at; `findings_catalog` carries the copy
    the brief's schema names. A disagreement would mean the queue sorted by one
    number and the email was chosen by the other.
    """
    filas = conn.execute(
        "SELECT c.code, c.lang, c.severity_rank AS catalogo, f.severity_rank AS codigo "
        "FROM findings_catalog c JOIN finding_codes f ON f.code = c.code"
    ).fetchall()
    assert filas
    for fila in filas:
        assert fila["catalogo"] == fila["codigo"], f"{fila['code']}/{fila['lang']}"


def test_un_escaneo_no_puede_apuntar_a_un_hallazgo_inexistente(conn):
    pid = db.add_prospect(conn, domain="empresa.com")
    with pytest.raises(sqlite3.IntegrityError):
        with db.transaction(conn):
            conn.execute(
                "INSERT INTO scans (prospect_id, scanned_at, raw_findings, "
                "primary_finding_code) VALUES (?,?,?,?)",
                (pid, db.now(), "{}", "inventado"),
            )


# --------------------------------------------------------------------------- #
# Commercial qualification: the gate into the send queue.
# --------------------------------------------------------------------------- #


def test_la_calificacion_se_guarda_con_su_desglose(conn):
    from prospector.qualify import score_prospect
    from prospector.signals import SiteSignals

    pid = db.add_prospect(conn, domain="tienda.es", sector="legal")
    score = score_prospect(
        build_report("tienda.es", mx=["a.mx", "b.mx"]),
        SiteSignals(domain="tienda.es", resolves=True,
                    html="cdn.shopify.com <form><input type='email'></form>"),
        sector="legal",
    )
    db.record_qualification(conn, pid, score)

    fila = conn.execute("SELECT * FROM prospects WHERE id = ?", (pid,)).fetchone()
    assert fila["commercial_score"] == score.total
    assert fila["qualified"] == 1
    guardado = json.loads(fila["score_breakdown"])
    assert {s["name"] for s in guardado["signals"]} >= {"ecommerce", "sector"}
    assert guardado["threshold"] == score.threshold


def test_solo_los_calificados_entran_en_la_cola(conn):
    """Everything else stays in the database, scanned and searchable, and is
    simply never contacted."""
    from prospector.qualify import score_prospect
    from prospector.signals import SiteSignals

    for dominio, sector, html in (
        ("buena.es", "legal", "cdn.shopify.com <form><input type='email'>"),
        ("floja.es", "hosteleria", "<html>hola</html>"),
    ):
        pid = db.add_prospect(conn, domain=dominio, sector=sector)
        informe = build_report(dominio, mx=["a.mx", "b.mx"],
                               dmarc={"found": False, "status": "fail", "summary": "x"})
        db.record_scan(conn, pid, informe, select_primary_finding(informe))
        db.record_qualification(
            conn, pid,
            score_prospect(informe,
                           SiteSignals(domain=dominio, resolves=True, html=html),
                           sector=sector),
        )

    en_cola = [r["domain"] for r in db.qualified_prospects(conn)]
    assert en_cola == ["buena.es"]
    # …y la floja sigue ahí, escaneada, con su hallazgo.
    floja = conn.execute("SELECT * FROM prospects WHERE domain = 'floja.es'").fetchone()
    assert floja["status"] == "scanned" and floja["qualified"] == 0


def test_una_base_anterior_gana_las_columnas_nuevas(tmp_path):
    """A database created before qualification existed must not need deleting."""
    ruta = tmp_path / "vieja.db"
    antigua = sqlite3.connect(ruta)
    antigua.executescript(
        "CREATE TABLE prospects (id INTEGER PRIMARY KEY, domain TEXT NOT NULL UNIQUE,"
        " company_name TEXT, country TEXT, sector TEXT, source TEXT,"
        " created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new');"
    )
    antigua.execute(
        "INSERT INTO prospects (domain, created_at) VALUES ('previa.es', '2026-01-01')"
    )
    antigua.commit()
    antigua.close()

    conexion = db.init(ruta)
    columnas = {r["name"] for r in conexion.execute("PRAGMA table_info(prospects)")}
    assert {"commercial_score", "score_breakdown", "qualified", "scored_at"} <= columnas
    fila = conexion.execute("SELECT * FROM prospects WHERE domain='previa.es'").fetchone()
    assert fila["qualified"] == 0 and fila["commercial_score"] is None
    conexion.close()
