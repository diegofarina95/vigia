"""The ruler does not belong to the subject.

Three configuration areas came off the panel. Two of them are cosmetic and one is
not, and this file is about telling them apart.

**The thresholds are the substantive one.** They were per-org, editable from the
panel, so the tenant being measured could move its own yardstick: set
`dormant_days` to 3650 and the dormant-accounts finding stops existing. Every
claim this product makes rests on measuring against CIS, so a knob that lets the
measured party choose the number is not a feature with a bad default — it is a
hole in the only thing the report is selling.

Removing the form would not have closed it. `PUT /api/settings` had to go too, and
`effective_settings` had to stop applying the rows that are already stored. Both
are asserted below, because "we took the button away" is exactly the kind of fix
that gets undone by somebody restoring a panel.

**Recurring scans are the cosmetic one, with a sharp edge.** The code stays — it
is the monthly-monitoring product — but a schedule with no screen to stop it from
is a schedule that mails a customer forever, from a domain whose deliverability
reputation is not a thing to lend. So the product default is `off` and no org may
be left due.
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture()
def app(tmp_path):
    os.environ["VIGIA_DB_PATH"] = str(tmp_path / "vara.db")
    from vigia import create_app

    return create_app()


# ------------------------------------------------- los umbrales son fijos

def test_the_four_thresholds_are_the_cis_values():
    """The values themselves, so a careless edit to a default is a failing test
    rather than a quietly different report."""
    from vigia.config import DEFAULT_DKIM_SELECTORS, load_settings

    s = load_settings()
    assert 2 <= s.super_admin_threshold <= 4, "CIS recomienda entre 2 y 4 superadministradores"
    assert s.dormant_days == 90
    assert s.widely_granted_threshold == 10
    # One list, for the scan and for the public checker alike. It used to be two:
    # the scan checked `google` only, the public checker checked seven, and the same
    # domain could be "no verificado" in a paying customer's report and "correcto"
    # in the free tool on the same afternoon. Auditing ten real domains found three
    # publishing their key under a selector neither list had.
    assert s.dkim_selectors == list(DEFAULT_DKIM_SELECTORS)
    assert "google" in DEFAULT_DKIM_SELECTORS
    assert {"k2", "k3", "selector1"} <= set(DEFAULT_DKIM_SELECTORS)


def test_stored_overrides_are_kept_but_never_applied(app):
    """Not deleted, not honoured. The rows survive so nothing is lost; they are
    ignored so the measurement cannot be tuned by what is being measured."""
    from vigia.services import effective_settings, get_db

    with app.app_context():
        db = get_db()
        org = db.upsert_org("x.com", "jefe@x.com", b"k")
        db.set_org_settings(org["id"], {"dormant_days": 3650, "dkim_selectors": ["mio"]})

        # Still there…
        assert db.get_org_settings(org["id"])["dormant_days"] == 3650
        # …and completely without effect.
        aplicado = effective_settings(db.get_org(org["id"]))
        assert aplicado.dormant_days == 90
        from vigia.config import DEFAULT_DKIM_SELECTORS

        assert aplicado.dkim_selectors == list(DEFAULT_DKIM_SELECTORS)


def test_there_is_no_route_that_writes_a_threshold(app):
    """The form is gone; this is about the endpoint behind it. A button removed
    while its route stays is still a feature."""
    reglas = {(str(r), tuple(sorted((r.methods or set()) - {"HEAD", "OPTIONS"})))
              for r in app.url_map.iter_rules()}
    metodos = {ruta: metodos for ruta, metodos in reglas}
    assert metodos.get("/api/settings") == ("GET",), metodos.get("/api/settings")

    cliente = app.test_client()
    with app.app_context():
        from vigia.services import get_db

        org = get_db().upsert_org("x.com", "jefe@x.com", b"k")
    with cliente.session_transaction() as ses:
        ses["org_id"] = org["id"]
    assert cliente.put("/api/settings", json={"dormant_days": 3650}).status_code == 405


# --------------------------------------- la programación, oculta y apagada

def test_the_product_default_is_off(app):
    """A new org must not come out of `upsert_org` with a live schedule.

    This is the one that mattered. `upsert_org` inserted the literal `'weekly'`,
    so every org started scheduled from its first second — including a stranger
    connecting to try the free scan, who would then receive mail with no screen to
    stop it from.
    """
    from vigia.services import get_db

    with app.app_context():
        db = get_db()
        org = db.upsert_org("nueva.com", "jefe@nueva.com", b"k")
        assert db.get_org(org["id"])["schedule_frequency"] == "off"
        # And the alert address is still recorded, so the feature is one word away.
        assert db.get_org(org["id"])["alert_email"] == "jefe@nueva.com"


def test_an_off_org_is_never_due(app):
    """The mechanism, not just the default: `orgs_due` builds cutoffs only for
    `daily` and `weekly`, so `off` cannot be selected. Asserted rather than read,
    because this is what stops a hidden schedule from mailing anybody."""
    from datetime import datetime, timedelta, timezone

    from vigia.jobs import due_cutoffs
    from vigia.services import get_db

    with app.app_context():
        db = get_db()
        org = db.upsert_org("x.com", "jefe@x.com", b"k")
        # Even a year later, and even having run long ago.
        db.set_schedule(org["id"], "off", "avisos@x.com", True)
        futuro = datetime.now(timezone.utc) + timedelta(days=365)
        assert db.orgs_due(due_cutoffs(futuro)) == []


def test_the_scheduler_ui_routes_are_gone_but_the_engine_is_not(app):
    """The distinction this whole file is about: no screen, no write endpoints,
    and every piece of machinery intact so putting it back is wiring."""
    rutas = {str(r): tuple(sorted((r.methods or set()) - {"HEAD", "OPTIONS"}))
             for r in app.url_map.iter_rules()}
    assert rutas.get("/api/schedule") == ("GET",)
    assert "/api/notify/test" not in rutas

    # Intact.
    from vigia import jobs
    from vigia.services import get_db

    for nombre in ("run_due_scans", "start_scheduler", "due_cutoffs", "FREQUENCIES"):
        assert hasattr(jobs, nombre), nombre
    with app.app_context():
        db = get_db()
        for nombre in ("set_schedule", "orgs_due", "claim_scheduled_run"):
            assert hasattr(db, nombre), nombre
        org = db.upsert_org("x.com", "jefe@x.com", b"k")
        db.set_schedule(org["id"], "weekly", "avisos@x.com", True)
        assert db.get_org(org["id"])["schedule_frequency"] == "weekly", (
            "el motor tiene que seguir funcionando para cuando vuelva la interfaz"
        )


# ------------------------------------------------- dominios: solo automáticos

def test_domains_sync_but_cannot_be_added_by_hand(app):
    """The DNS checks keep running over whatever is stored — including rows added
    by hand before today, which are deliberately left in place. What is gone is
    the ability to add one."""
    rutas = {str(r): tuple(sorted((r.methods or set()) - {"HEAD", "OPTIONS"}))
             for r in app.url_map.iter_rules()}
    assert rutas.get("/api/domains") == ("GET",), rutas.get("/api/domains")

    from vigia.services import get_db

    with app.app_context():
        db = get_db()
        org = db.upsert_org("x.com", "jefe@x.com", b"k")
        # The storage layer is untouched, so an existing custom row still works…
        db.add_domain(org["id"], "heredado.com")
        guardados = {d["domain"] for d in db.list_domains(org["id"])}
        assert "heredado.com" in guardados

    cliente = app.test_client()
    with cliente.session_transaction() as ses:
        ses["org_id"] = org["id"]
    # …and the API cannot create another.
    assert cliente.post("/api/domains", json={"domain": "nuevo.com"}).status_code == 405
    assert cliente.delete("/api/domains/heredado.com").status_code == 405


def test_a_custom_domain_is_still_scanned(tmp_path):
    """Not deleting the data is only half the promise; the other half is that it
    is still checked. Mock mode, so no real token is needed to build a context."""
    os.environ["VIGIA_DB_PATH"] = str(tmp_path / "dom.db")
    os.environ["MOCK_MODE"] = "1"
    from vigia import create_app
    from vigia.services import build_scan_context, get_db

    app = create_app()
    try:
        with app.app_context():
            db = get_db()
            org = db.upsert_org("x.com", "jefe@x.com", b"k")
            db.add_domain(org["id"], "heredado.com")
            ctx = build_scan_context(db.get_org(org["id"]))
            # Through the method that actually feeds the DNS checks, not through a
            # private attribute: what has to keep working is that the domain
            # reaches the list of things SPF/DKIM/DMARC are run against.
            assert "heredado.com" in ctx.email_domains(), (
                "un dominio añadido a mano en su día tiene que seguir comprobándose"
            )
    finally:
        os.environ.pop("MOCK_MODE", None)


# ------------------------------------ nada del informe apunta a lo retirado

def test_no_output_channel_points_at_a_panel_that_no_longer_exists():
    """The DKIM finding used to say "añádelo en Opciones de escaneo", which is now
    an instruction to use a screen that is not there. It appears in the PDF, the
    CSV and the finding catalogue, so all four channels are swept at once."""
    import pathlib

    raiz = pathlib.Path(__file__).resolve().parents[1]
    objetivos = [
        *(raiz / "vigia").rglob("*.py"),
        *(raiz / "vigia" / "locales").rglob("*.json"),
        *(raiz / "scripts").rglob("*.py"),
    ]
    FRASES = ("Opciones de escaneo", "Scan options", "panel Dominios", "Domains panel")
    encontrados = []
    for archivo in objetivos:
        for numero, linea in enumerate(archivo.read_text().splitlines(), 1):
            for frase in FRASES:
                if frase in linea:
                    encontrados.append(f"{archivo.relative_to(raiz)}:{numero}: {frase}")
    assert encontrados == [], "textos que apuntan a paneles retirados:\n  " + "\n  ".join(encontrados)


def test_the_dkim_finding_explains_the_single_selector_instead_of_looking_broken():
    """The accepted consequence, in words. A tenant signing with its own selector
    reads as "no verificado", and that has to look like a stated limit rather than
    a malfunction — with a way out that is a person."""
    from vigia.dns_email_auth import check_dkim, dkim_verdict
    from vigia.i18n import localize_finding

    class SinNada:
        def txt(self, name):
            return []

    estado, resumen = dkim_verdict(check_dkim("example.com", SinNada(), ["google"]))
    assert estado == "undetermined", "nunca `fail`: no encontrarlo no prueba que no exista"
    assert "google" in resumen
    assert "no significa que no firmes" in resumen
    assert "diego@diegofarina.com" in resumen

    # And through the catalogue, which replaces `remediation` wholesale on read.
    for lang in ("es", "en"):
        traducido = localize_finding(
            {"id": "email-dkim", "title": "x", "severity": "medium",
             "status": "undetermined", "details": {}},
            lang,
        )
        assert "diego@diegofarina.com" in traducido["remediation"], lang
        assert "google" in traducido["remediation"], lang
