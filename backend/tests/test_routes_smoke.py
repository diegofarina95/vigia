"""Every route, actually called.

This file exists because 577 tests passed while `/api/report` and
`/api/report/csv` both returned 500 in production. The four-channel test wrote
the day before compared the PDF, the CSV, the dashboard and the e-mail and found
them in agreement — by importing `build_html_report` and `findings_csv_rows`
directly. Nothing ever asked Flask for those URLs, so when a refactor deleted
the import line in the route module the renderers still agreed perfectly with
each other and the customer got an Internal Server Error.

A test that reaches into a module to fetch the function the route uses is
testing the function. The route is the product.

So: hit every registered rule with a real session and assert it does not 500.
Deliberately shallow — the content is covered elsewhere — and deliberately
automatic over `url_map`, so a route added tomorrow is covered without anybody
adding it here. That last property is the whole point: the bug was not that
somebody wrote a bad test, it was that nobody thought to write one.
"""
from __future__ import annotations

import os

import pytest

#: Routes that must not be called blind: they mutate, send mail, redirect off to
#: Google, or take a scan that costs real API calls. Each is exercised
#: elsewhere; listing them here is a decision, not an oversight.
NO_LLAMAR = {
    "auth.google_start",       # redirects to accounts.google.com
    "auth.google_callback",    # needs a code from Google
    "auth.disconnect",         # deletes the org
    "api.run_scan",            # hits the Google APIs for real
    "api.notify_test",         # sends mail
    "api.billing_checkout",
    "tailnet.",                # the private console has its own suite and gate
}


def _saltar(endpoint: str) -> bool:
    return any(
        endpoint == nombre or endpoint.startswith(nombre)
        for nombre in NO_LLAMAR
    )


@pytest.fixture(scope="module")
def aplicacion(tmp_path_factory):
    directorio = tmp_path_factory.mktemp("rutas")
    os.environ["VIGIA_DB_PATH"] = str(directorio / "rutas.db")
    os.environ["VIGIA_CONTACT_EMAIL"] = "diego@diegofarina.com"
    from vigia import create_app

    app = create_app()
    app.config.update(TESTING=False)   # we want the real 500, not a raised error
    return app


@pytest.fixture(scope="module")
def con_escaneo(aplicacion):
    """An org with one stored scan, so the report routes have something to
    render rather than short-circuiting on 404."""
    from tests.fakes import FakeContext
    from vigia.scan import collect_findings, evaluated_result, remaining_manual_checks
    from vigia.scoring import compute_score, severity_counts
    from vigia.services import get_db

    usuarios = [
        {"primaryEmail": "jefe@x.com", "orgUnitPath": "/", "isAdmin": True,
         "isDelegatedAdmin": False, "isEnrolledIn2Sv": False, "isEnforcedIn2Sv": True,
         "suspended": False, "archived": False, "lastLoginTime": "1970-01-01T00:00:00.000Z"},
    ]
    with aplicacion.app_context():
        db = get_db()
        org = db.upsert_org("x.com", "jefe@x.com", b"clave")
        ctx = FakeContext(users=usuarios)
        findings = collect_findings(ctx, label="rutas")
        rendered = [f.to_dict() for f in findings]
        score = compute_score(findings)
        counts = severity_counts(findings)
        db.insert_scan(
            org["id"], score=score, counts=counts, findings=rendered,
            manual_checks=remaining_manual_checks(findings),
            engine_version="v1-rutas",
            result=evaluated_result(rendered, score, counts, ctx),
        )
    return org


def _rutas(aplicacion):
    for regla in aplicacion.url_map.iter_rules():
        if "GET" not in (regla.methods or set()):
            continue
        if _saltar(regla.endpoint):
            continue
        if regla.arguments:            # needs a parameter we cannot invent
            continue
        yield regla.endpoint, str(regla)


def test_there_are_routes_to_check(aplicacion):
    """Guards the guard: an empty parametrisation would pass silently."""
    assert len(list(_rutas(aplicacion))) >= 12


def pytest_generate_tests(metafunc):  # noqa: D103
    if "ruta" not in metafunc.fixturenames:
        return
    os.environ.setdefault("VIGIA_DB_PATH", "/tmp/vigia-rutas-collect.db")
    from vigia import create_app

    app = create_app()
    metafunc.parametrize(
        "ruta",
        [pytest.param(camino, id=endpoint) for endpoint, camino in _rutas(app)],
    )


def test_every_route_answers_without_a_server_error(aplicacion, con_escaneo, ruta):
    """The one assertion that would have caught the missing import.

    Not "returns 200": an unauthenticated 401 or a 402 for a paid feature is a
    correct answer. Anything in the 5xx range is the application breaking, and
    that is what a customer saw.
    """
    cliente = aplicacion.test_client()
    with cliente.session_transaction() as sesion:
        sesion["org_id"] = con_escaneo["id"]

    respuesta = cliente.get(ruta)
    assert respuesta.status_code < 500, (
        f"{ruta} devolvió {respuesta.status_code}\n"
        f"{respuesta.get_data(as_text=True)[:600]}"
    )


def test_the_report_and_csv_routes_specifically(aplicacion, con_escaneo):
    """Named on their own because these are the two that broke, and because
    "does not 500" is a weaker claim than "produced the document"."""
    cliente = aplicacion.test_client()
    with cliente.session_transaction() as sesion:
        sesion["org_id"] = con_escaneo["id"]

    informe = cliente.get("/api/report")
    assert informe.status_code == 200, informe.get_data(as_text=True)[:400]
    html = informe.get_data(as_text=True)
    assert "Resumen para dirección" in html
    assert "Quieres que lo arreglemos" in html
    assert "Datos analizados" in html

    csv = cliente.get("/api/report/csv")
    assert csv.status_code == 200, csv.get_data(as_text=True)[:400]
    lineas = csv.get_data(as_text=True).strip().splitlines()
    assert len(lineas) > 1, "el CSV no tiene ni una fila de datos"
    assert lineas[0].startswith("id,")


def test_an_anonymous_caller_gets_401_not_500(aplicacion):
    """The other half: breaking on the unauthenticated path is just as visible,
    and that is the path the whole internet can reach."""
    cliente = aplicacion.test_client()
    for ruta in ("/api/report", "/api/report/csv", "/api/scan/latest", "/api/settings"):
        respuesta = cliente.get(ruta)
        assert respuesta.status_code == 401, f"{ruta} → {respuesta.status_code}"


def test_nothing_is_behind_a_paywall(aplicacion, con_escaneo):
    """`VIGIA_PRO_OVERRIDE=1` was not technical debt — it was the correct
    configuration for a product whose analysis is free and whose revenue is the
    remediation. But it was implemented as a bridge over plan logic that stayed
    in place, and an override nobody remembers the reason for eventually gets
    removed for tidiness. That day, prospects meet a paywall.

    So the concept is gone rather than bridged, and this asserts it stays gone —
    with no override set anywhere in this test environment.
    """
    import os

    assert "VIGIA_PRO_OVERRIDE" not in os.environ

    cliente = aplicacion.test_client()
    with cliente.session_transaction() as sesion:
        sesion["org_id"] = con_escaneo["id"]

    for ruta in ("/api/report", "/api/report/csv", "/api/scans", "/api/schedule"):
        respuesta = cliente.get(ruta)
        assert respuesta.status_code != 402, f"{ruta} sigue detrás de un muro de pago"
        assert respuesta.status_code < 500, f"{ruta} → {respuesta.status_code}"


def test_the_plan_concept_is_not_in_the_code():
    """A grep, deliberately: the point of block 6 was to delete the concept, and
    a reintroduction would come back as a helper somebody thought was harmless."""
    import pathlib

    raiz = pathlib.Path(__file__).resolve().parents[1] / "vigia"
    prohibidos = ("is_pro(", "pro_override", "gate_scan", "gate_history",
                  "locked_count", "pro_required")
    hallado = []
    for archivo in raiz.rglob("*.py"):
        texto = archivo.read_text()
        for termino in prohibidos:
            if termino in texto:
                hallado.append(f"{archivo.relative_to(raiz)}: {termino}")
    assert hallado == [], "el concepto de plan ha vuelto:\n" + "\n".join(hallado)


def test_the_landing_does_not_advertise_a_tier_that_does_not_exist():
    """The backend half of this was done days ago — no plans, no gates, every route
    open. The shop window kept selling the other thing anyway: a two-column
    Gratis/Pro table ending in "el pago abre pronto; el control de acceso ya está
    funcionando", which was false in three ways at once.

    Half the Pro column was already free (full detail, history, PDF export).
    "Escaneos periódicos automáticos" had just been taken OFF the product. And
    "vista multiempresa (para MSP)" never existed. Promising any of that to an
    audience whose entire reason for reading is deciding whether to trust me is the
    most expensive sentence on the site.

    So this checks the React landing, which no Python import reaches — the same
    reason the read-only wording drifted there for weeks.
    """
    import pathlib
    import re

    landing = (
        pathlib.Path(__file__).resolve().parents[2]
        / "frontend" / "src" / "pages" / "Landing.tsx"
    )
    assert landing.is_file(), f"no está {landing} — ¿se movió el frontend?"
    # Block comments stripped first, because what matters is what SHIPS, not what
    # is documented — and the comment in that file explaining why the tier was
    # removed necessarily quotes the strings being forbidden. The first version of
    # this test failed on its own explanation, which is the same mistake as the
    # HTML comment that shipped the word "mensual" inside the report.
    fuente = re.sub(r"/\*.*?\*/", " ", landing.read_text(), flags=re.S)
    texto = re.sub(r"\s+", " ", fuente)

    PROHIBIDO = (
        "PRO_FEATURES",                  # la lista de funciones de pago
        "pasa a Pro",                    # el titular
        "El pago abre pronto",           # la promesa que no se puede cumplir
        "Escaneos periódicos automáticos",  # función retirada del producto
        "Vista multiempresa",            # función que nunca existió
    )
    vuelto = [t for t in PROHIBIDO if t in texto]
    assert vuelto == [], (
        "el escaparate vuelve a vender un nivel que no existe: " + ", ".join(vuelto)
    )

    # Y la afirmación positiva, para que el test falle también si alguien borra el
    # bloque entero en vez de arreglarlo: la página tiene que decir que es gratis.
    assert "El análisis es gratis" in texto
    assert "no hay tarjeta" in texto
