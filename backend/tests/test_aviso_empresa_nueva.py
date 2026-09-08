"""The operator is told once when a company runs its first analysis. Once.

The whole value of this alert is that it arrives exactly one time per customer, so
these tests are mostly about the ways "once" breaks:

 · the second scan of the same company,
 · two scans finishing in the same instant,
 · the retention purge deleting the first scan months later, which is why the flag
   is a column and not `COUNT(scans) == 1`,
 · a mail server that is down, which must not turn a finished analysis into an
   error for the customer who asked for one.

`avisar_empresa_nueva` swallows everything, so a test that only checked it "did not
raise" would pass with the feature entirely broken. Each test here asserts what
actually happened: an e-mail captured, or a flag moved, or neither.
"""
from __future__ import annotations

import os
import threading

import pytest

from vigia import notify


@pytest.fixture()
def entorno(tmp_path, monkeypatch):
    """A real database and a settings object with SMTP that looks configured."""
    monkeypatch.setenv("VIGIA_DB_PATH", str(tmp_path / "aviso.db"))
    monkeypatch.setenv("VIGIA_CONTACT_EMAIL", "diego@diegofarina.com")
    monkeypatch.setenv("VIGIA_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("VIGIA_SMTP_FROM", "vigia@example.com")
    from vigia.config import load_settings
    from vigia.db import Database

    settings = load_settings()
    db = Database(str(tmp_path / "aviso.db"))   # se inicializa al construirse
    org = db.upsert_org(
        primary_domain="empresa-nueva.example",
        admin_email="admin@empresa-nueva.example",
        refresh_token_enc="cifrado",
    )
    return settings, db, org


@pytest.fixture()
def enviados(monkeypatch):
    """Capture outgoing mail instead of sending it."""
    capturados: list[tuple[str, str, str]] = []

    def falso(settings, to, subject, body):
        capturados.append((to, subject, body))

    monkeypatch.setattr(notify, "send_email", falso)
    return capturados


def _escaneo(score=37):
    return {
        "id": 1,
        "score": score,
        "counts": {"critical": 2, "high": 5, "medium": 6, "low": 2},
        "created_at": "2026-08-04T18:00:00+00:00",
        "result": {"people": [{"email": "x"}, {"email": "y"}]},
    }


# ─────────────────────────────────────────────────────────────── el caso feliz


def test_avisa_del_primer_analisis(entorno, enviados):
    settings, db, org = entorno
    assert notify.avisar_empresa_nueva(settings, db, org, _escaneo()) is True
    assert len(enviados) == 1
    destino, asunto, cuerpo = enviados[0]
    assert destino == "diego@diegofarina.com"
    assert "empresa-nueva.example" in asunto
    assert "empresa-nueva.example" in cuerpo
    assert "admin@empresa-nueva.example" in cuerpo
    assert "37" in cuerpo


def test_el_asunto_lleva_el_dominio_para_poder_filtrar(entorno, enviados):
    settings, db, org = entorno
    notify.avisar_empresa_nueva(settings, db, org, _escaneo())
    asunto = enviados[0][1]
    assert asunto.startswith("[Vigía]")
    assert "empresa-nueva.example" in asunto


# ──────────────────────────────────────────────────────────────────── una vez


def test_no_avisa_del_segundo_analisis(entorno, enviados):
    settings, db, org = entorno
    notify.avisar_empresa_nueva(settings, db, org, _escaneo())
    assert notify.avisar_empresa_nueva(settings, db, org, _escaneo(41)) is False
    assert len(enviados) == 1, "el segundo análisis de la misma empresa volvió a avisar"


def test_dos_analisis_simultaneos_avisan_una_sola_vez(entorno, enviados):
    """Two threads, one claim. The database decides, not a read-then-write race."""
    settings, db, org = entorno
    resultados: list[bool] = []
    barrera = threading.Barrier(2)

    def correr():
        barrera.wait()
        resultados.append(notify.avisar_empresa_nueva(settings, db, org, _escaneo()))

    hilos = [threading.Thread(target=correr) for _ in range(2)]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()

    assert sum(resultados) == 1, f"dos hilos, {sum(resultados)} avisos"
    assert len(enviados) == 1


def test_borrar_los_escaneos_no_reabre_el_aviso(entorno, enviados):
    """Why the flag is a column.

    Counting scans would make a purged first scan look like a first scan again, and
    the customer would be announced as new months after arriving.
    """
    settings, db, org = entorno
    notify.avisar_empresa_nueva(settings, db, org, _escaneo())
    with db._connect() as conn:  # noqa: SLF001 — simulating the purge, not using it
        conn.execute("DELETE FROM scans WHERE org_id = ?", (org["id"],))
    assert notify.avisar_empresa_nueva(settings, db, org, _escaneo()) is False
    assert len(enviados) == 1


def test_otra_empresa_si_genera_su_propio_aviso(entorno, enviados):
    settings, db, org = entorno
    notify.avisar_empresa_nueva(settings, db, org, _escaneo())
    otra = db.upsert_org(
        primary_domain="segunda.example",
        admin_email="admin@segunda.example",
        refresh_token_enc="cifrado",
    )
    assert notify.avisar_empresa_nueva(settings, db, otra, _escaneo()) is True
    assert len(enviados) == 2
    assert "segunda.example" in enviados[1][1]


# ──────────────────────────────────────────────────────── cuando algo no está


def test_sin_smtp_no_avisa_y_no_gasta_el_aviso(entorno, enviados, monkeypatch):
    """A missing mail server must not burn the one alert this customer gets."""
    settings, db, org = entorno
    monkeypatch.setattr(notify, "smtp_configured", lambda _s: False)
    assert notify.avisar_empresa_nueva(settings, db, org, _escaneo()) is False
    assert enviados == []
    # And once SMTP works, the alert is still available.
    monkeypatch.setattr(notify, "smtp_configured", lambda _s: True)
    assert notify.avisar_empresa_nueva(settings, db, org, _escaneo()) is True
    assert len(enviados) == 1


def test_sin_direccion_de_operador_no_avisa(entorno, enviados):
    settings, db, org = entorno
    sin_destino = settings.__class__(**{**vars(settings), "operator_email": ""})
    assert notify.avisar_empresa_nueva(sin_destino, db, org, _escaneo()) is False
    assert enviados == []


def test_un_fallo_de_correo_no_rompe_el_analisis(entorno, monkeypatch):
    """The customer asked for an analysis, not for our mail server to be up."""
    settings, db, org = entorno

    def explota(*_a, **_k):
        raise notify.NotifyError("el servidor de correo rechazó la conexión")

    monkeypatch.setattr(notify, "send_email", explota)
    assert notify.avisar_empresa_nueva(settings, db, org, _escaneo()) is False


# ───────────────────────────────────────────────── qué NO viaja en el correo


def test_el_correo_no_lleva_datos_personales_del_tenant(entorno, enviados):
    """Only the domain and the administrator who authorised the connection.

    The addresses of the customer's staff stay in the database. A business alert
    does not need them, and the retention promise on /privacy is easier to keep
    when personal data never reaches a second inbox.
    """
    settings, db, org = entorno
    escaneo = _escaneo()
    escaneo["result"]["people"] = [
        {"email": "victima1@empresa-nueva.example"},
        {"email": "victima2@empresa-nueva.example"},
    ]
    escaneo["findings"] = [{"id": "x", "accounts": ["victima1@empresa-nueva.example"]}]
    notify.avisar_empresa_nueva(settings, db, org, escaneo)
    cuerpo = enviados[0][2]
    assert "victima1@" not in cuerpo
    assert "victima2@" not in cuerpo
    # The count is fine; the identities are not.
    assert "2" in cuerpo


def test_el_correo_no_lleva_el_token(entorno, enviados):
    settings, db, org = entorno
    notify.avisar_empresa_nueva(settings, db, org, _escaneo())
    cuerpo = enviados[0][2]
    assert "cifrado" not in cuerpo
    assert "refresh" not in cuerpo.lower()


# ────────────────────────────── el cliente lee en dos idiomas; el operador, no


def test_el_aviso_al_operador_se_queda_en_castellano_a_proposito(entorno, enviados):
    """La decisión, escrita como prueba para que se tenga que volver a tomar.

    Los correos de `notify` que lee un cliente son bilingües: cada frase sale del
    catálogo, bajo `email.alerta`. Este no. Va a VIGIA_OPERATOR_EMAIL, que es una
    sola persona que lee castellano, y mantener una mitad en inglés que nadie va a
    abrir son dos redacciones que se pueden desviar para un público de uno.

    Si algún día el aviso pasa al catálogo, esta prueba falla y obliga a decidirlo
    en lugar de arrastrarlo.
    """
    settings, db, org = entorno
    notify.avisar_empresa_nueva(settings, db, org, _escaneo())
    asunto, cuerpo = enviados[0][1], enviados[0][2]
    assert "Empresa nueva" in asunto
    assert "ha completado su primer análisis de seguridad" in cuerpo
    assert "Administrador que conectó" in cuerpo
    # Y no es una clave de catálogo a medio resolver.
    assert "email." not in cuerpo


def test_la_alerta_de_escaneo_del_cliente_si_habla_los_dos_idiomas():
    """El correo que sí lee el cliente. La misma fila, dos idiomas, un solo número.

    Comprueba lo que rompería de verdad: que una frase se quedara sin traducir y
    llegara al cliente como «email.alerta.titulo_nuevos».
    """
    org = {"primary_domain": "empresa-nueva.example"}
    scan = {"score": 41, "counts": {"critical": 2, "high": 1, "medium": 0, "low": 3}}
    resumen = {
        "has_baseline": True,
        "new": [{"severity": "critical", "title": "Superadministrador sin 2FA"}],
        "worse": [],
        "resolved": [],
        "coverage_lost": [{"severity": "info", "title": "Registro de acceso"}],
    }
    asuntos = {}
    for lang in ("es", "en"):
        asunto, cuerpo = notify.scan_alert_body(
            org, scan, 38, resumen, "https://ejemplo/panel", lang
        )
        asuntos[lang] = asunto
        assert "email.alerta" not in asunto and "email.alerta" not in cuerpo, lang
        assert asunto.startswith("[Vigía] ")
        # El dominio y la puntuación no dependen del idioma.
        assert "empresa-nueva.example" in asunto
        assert "41/100" in cuerpo and "+3" in cuerpo
    assert asuntos["es"] != asuntos["en"]
    assert "1 hallazgo CRÍTICO nuevo" in asuntos["es"]
    assert "1 new CRITICAL finding" in asuntos["en"]


# ─────────────────────────────────── las empresas que ya estaban no son nuevas


def test_una_empresa_preexistente_no_se_anuncia_como_nueva(tmp_path, monkeypatch):
    """The migration's backfill, tested through it rather than around it.

    Adding the column to a database that already has customers must not turn their
    next analysis into an arrival notice. Simulated the way it really happens: the
    column is dropped from a populated database and the migration is re-run.
    """
    monkeypatch.setenv("VIGIA_CONTACT_EMAIL", "diego@diegofarina.com")
    monkeypatch.setenv("VIGIA_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("VIGIA_SMTP_FROM", "vigia@example.com")
    from vigia.config import load_settings
    from vigia.db import Database

    ruta = str(tmp_path / "vieja.db")
    db = Database(ruta)
    antigua = db.upsert_org(
        primary_domain="cliente-de-siempre.example",
        admin_email="admin@cliente-de-siempre.example",
        refresh_token_enc="cifrado",
    )
    # Deliberately NO scans: this is the case the first version of the backfill
    # missed. The retention purge deletes old scans, so a customer connected months
    # ago can legitimately have none on record — and the production database turned
    # out to be exactly that, one organisation with zero stored scans.

    # Back to before the feature existed: the column gone, the org kept.
    with db._connect() as conn:  # noqa: SLF001
        conn.execute("ALTER TABLE orgs DROP COLUMN operator_alerted_at")
    Database(ruta)  # re-running the migration is what re-adds it, and backfills

    capturados: list[tuple] = []
    monkeypatch.setattr(
        notify, "send_email", lambda s, to, subject, body: capturados.append((to, subject))
    )
    fresca = Database(ruta)
    org = fresca.get_org(antigua["id"]) if hasattr(fresca, "get_org") else antigua
    assert notify.avisar_empresa_nueva(load_settings(), fresca, org, _escaneo()) is False
    assert capturados == [], "un cliente con historial se anunció como empresa nueva"
