"""The ten invariants, run over the real engine.

Eight bugs in three days, all the same bug: the tool asserting what it cannot
know. Individually they looked like eight unrelated mistakes — a stale cache, a
thin CSV, a delta comparing the wrong row, an account missing from an
aggregation. What they have in common is that nothing in the codebase *forbade*
any of them, so each one had to be found by a human reading a report.

This file is the forbidding. Each test states a property the report must have
regardless of the tenant, and runs it against the demo tenant driven by the real
engine — not a fixture, because six of the eight bugs would have slipped past a
fixture that a human wrote from the same misunderstanding that caused them.

The numbering matches the brief so a failure can be argued about by number.
"""
from __future__ import annotations

import re

import pytest

from vigia.config import load_settings
from vigia.demo import build_demo_payload
from vigia.scoring import (
    OPEN_STATUSES,
    SEVERITY_WEIGHTS,
    is_inventory,
    is_org_scope,
    people_at_risk,
    score_breakdown,
)

DIRECCION = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")


@pytest.fixture(scope="module")
def escaneo():
    """The demo tenant, produced by `collect_findings` — the same path a real
    scan takes. `build_demo_payload` runs every registered check."""
    return build_demo_payload(load_settings())


@pytest.fixture(scope="module")
def hallazgos(escaneo):
    return escaneo["scan"]["findings"]


def abiertos(findings):
    return [
        f for f in findings
        if f.get("status") in OPEN_STATUSES and not f.get("manual")
    ]


def nombrados_en(finding) -> set[str]:
    encontrados: set[str] = set()
    for item in finding.get("affected_items") or []:
        encontrados |= set(DIRECCION.findall(str(item)))
    return encontrados


# ----------------------------------------------------------------- 1

def test_1_super_admins_and_delegated_admins_are_disjoint(hallazgos):
    """The first bug: one account listed simultaneously as a delegated admin,
    as a super admin without 2SV, and inside the super-admin count."""
    from vigia.checks.consistency import check_consistency

    assert check_consistency(hallazgos) == []


# ----------------------------------------------------------------- 2

def test_2_a_composite_cannot_fail_while_its_atomic_equivalent_passes(hallazgos):
    """The report that said "Super admin with no 2FA that has never signed in:
    FAIL" directly above "Super admin without 2-Step Verification: PASS"."""
    por_id = {f["id"]: f for f in hallazgos}
    parejas = [
        ("composite-superadmin-dormant-no-2sv", "composite-superadmin-no-2sv"),
        ("composite-superadmin-no-2sv-no-recovery", "composite-superadmin-no-2sv"),
        ("composite-dormant-no-2sv", "2sv-users"),
    ]
    for especifico, general in parejas:
        a, b = por_id.get(especifico), por_id.get(general)
        if not a or not b or a["status"] != "fail":
            continue
        assert b["status"] != "pass", (
            f"{especifico} falla mientras {general} pasa: no pueden ser ambas ciertas"
        )
        assert set(a.get("accounts") or []) <= set(b.get("accounts") or []), (
            f"las cuentas de {especifico} deben ser un subconjunto de {general}"
        )


# ----------------------------------------------------------------- 3

def test_3_everyone_a_finding_names_reaches_the_summaries(escaneo, hallazgos):
    """The account that vanished: `david@` sat on the backup-codes card and in
    neither "people at risk" nor the score table, because the check filled
    `affected_items` and only half of `accounts`."""
    en_riesgo = {row["account"] for row in people_at_risk(hallazgos)}
    en_tabla = {row["account"] for row in score_breakdown(hallazgos)["accounts"]}

    for finding in abiertos(hallazgos):
        if is_org_scope(finding) or is_inventory(finding):
            continue
        fuera = nombrados_en(finding) - set(finding.get("accounts") or [])
        assert not fuera, f"{finding['id']} nombra a {fuera} y no los declara"

        if SEVERITY_WEIGHTS.get(finding.get("severity"), 0) == 0:
            continue
        for cuenta in finding.get("accounts") or []:
            assert cuenta in en_riesgo, f"{finding['id']} acusa a {cuenta}, ausente del resumen"
            assert cuenta in en_tabla, f"{cuenta} no aparece en la tabla de puntuación"


# ----------------------------------------------------------------- 4

def test_4_nothing_scores_on_a_source_that_was_read_incompletely():
    """The invariant that would have caught the token truncation on day one.

    Driven against the real engine with the user directory deliberately cut
    short: before the inheritance in `_inherit_uncertainty`, nine findings
    flipped from fail or warn to PASS — a green tick earned by not looking.
    """
    from tests.fakes import FakeContext
    from vigia.scan import collect_findings
    from vigia.scoring import is_scorable

    usuarios = [
        {"primaryEmail": f"u{i}@x.com", "orgUnitPath": "/", "isAdmin": i == 0,
         "isDelegatedAdmin": False, "isEnrolledIn2Sv": False, "isEnforcedIn2Sv": True,
         "suspended": False, "archived": False, "lastLoginTime": "1970-01-01T00:00:00.000Z"}
        for i in range(4)
    ]
    entero = collect_findings(FakeContext(users=usuarios), label="entero")
    cortado = collect_findings(
        FakeContext(users=usuarios, complete={"users": False}), label="cortado"
    )

    antes = {f.id: f.status for f in entero}
    despues = {f.id: f.status for f in cortado}

    volteados = [k for k, v in antes.items()
                 if v in ("fail", "warn") and despues.get(k) == "pass"]
    assert volteados == [], f"leer menos produjo un «correcto»: {volteados}"

    # And nothing resting on the short source may contribute weight.
    for finding in cortado:
        fuentes = tuple(finding.depends_on) or ()
        data = finding.to_dict()
        if "users" in (fuentes or ("users",)) and finding.status != "undetermined":
            continue  # its own sources were fine
        if finding.details.get("incomplete_sources"):
            assert not is_scorable(data), f"{finding.id} puntúa sobre datos incompletos"


def test_4b_an_unmeasured_source_is_not_complete():
    """`ctx.complete()` used to answer True for anything nobody had recorded,
    which turned every unwired source into an assertion and made any future
    guard unfireable."""
    from tests.fakes import FakeContext

    ctx = FakeContext()
    ctx.coverage.pop("login")
    assert ctx.complete("login") is False
    assert ctx.measured("login") is False
    assert ctx.complete("inventada") is False


# ----------------------------------------------------------------- 5

def test_5_no_delta_and_no_continuity_across_engine_versions(tmp_path):
    """Four deploys of this gate did nothing, because it read the wrong row and
    because one of the two callers walked around it."""
    from vigia.db import Database
    from vigia.delta import gated_summary

    db = Database(str(tmp_path / "inv.db"))
    org = db.upsert_org("cliente.com", "admin@cliente.com", b"x")
    for score, engine in ((30, "v1-viejo"), (40, "v1-nuevo")):
        db.insert_scan(org["id"], score=score, counts={}, findings=[],
                       manual_checks=[], engine_version=engine)

    filas = db.latest_scans(org["id"], limit=2)
    actual, anterior = filas[0], db.scan_before(org["id"], filas[0]["id"])

    assert anterior["id"] == filas[1]["id"], "el anterior tiene que ser el anterior"
    previo, resumen = gated_summary(actual, anterior)
    assert previo is None, "no se compara puntuación entre motores distintos"
    assert resumen["engine_changed"] is True
    assert resumen["new"] == [] and resumen["resolved"] == []
    assert "no son comparables" in resumen["note"]


def test_5b_both_channels_use_the_same_gate():
    """The e-mail used to mail a delta the dashboard refused to compute. A gate
    one of two callers can walk around is not a gate."""
    import inspect

    from vigia import jobs
    from vigia.api import routes

    assert "gated_summary" in inspect.getsource(jobs._scan_one)
    assert "annotate_changes" not in inspect.getsource(jobs._scan_one)
    assert "gated_summary" in inspect.getsource(routes._scan_with_delta)


# ----------------------------------------------------------------- 6

def test_6_the_demo_shows_no_check_the_real_engine_does_not_run(hallazgos):
    from vigia.checks import ALL_CHECKS

    reales = set()
    for modulo in ALL_CHECKS:
        reales.add(modulo.CHECK_ID)
    ids = {f["id"] for f in hallazgos}
    # Every demo finding id must belong to a registered module, by prefix or by
    # the composite/consistency naming the engine itself produces.
    permitidos = tuple(reales) + ("composite-", "internal-consistency", "policy-",
                                  "email-", "mail-", "dns-", "2sv-", "oauth-",
                                  "login-", "audit-", "admin-login-", "alert-",
                                  "super-admin-", "delegated-", "dormant-",
                                  "never-", "suspended-", "recovery-")
    for fid in ids:
        assert fid.startswith(permitidos), f"la demo muestra {fid}, que el motor no produce"


# ----------------------------------------------------------------- 7

def test_7_every_finding_has_a_translation_key_in_both_languages(hallazgos):
    import json
    import pathlib

    base = pathlib.Path(__file__).resolve().parents[1] / "vigia" / "locales"
    catalogos = {
        lang: json.loads((base / f"{lang}.json").read_text())["findings"]
        for lang in ("es", "en")
    }
    sin_clave = {
        lang: sorted(
            f["id"] for f in hallazgos
            if f["id"] not in cat and not f["id"].endswith("-error")
        )
        for lang, cat in catalogos.items()
    }
    assert sin_clave["es"] == sin_clave["en"], "los dos idiomas deben cubrir lo mismo"
    assert sin_clave["es"] == [], f"sin traducción: {sin_clave['es']}"


# ----------------------------------------------------------------- 8

def test_8_an_organization_finding_never_names_individual_accounts(hallazgos):
    """One console toggle listed all seventeen employees as personally at
    fault, which buried the handful who really were."""
    for finding in hallazgos:
        if not is_org_scope(finding):
            continue
        assert not (finding.get("accounts") or []), f"{finding['id']} enumera cuentas"


# ----------------------------------------------------------------- 9

def test_9_an_inventory_never_raises_anybodys_severity(hallazgos):
    """"You have eight super admins" is a fact about the company's shape. It
    must not put a bullet on eight people's rows."""
    inventarios = [f for f in hallazgos if is_inventory(f)]
    assert inventarios, "la fixture debe contener al menos un inventario"

    filas = {row["account"]: row for row in people_at_risk(hallazgos)}
    for finding in inventarios:
        for cuenta in finding.get("accounts") or []:
            fila = filas.get(cuenta)
            if fila is None:
                continue
            ids = {problema["id"] for problema in fila["issues"]}
            assert finding["id"] not in ids, (
                f"{finding['id']} es un inventario y aparece en la fila de {cuenta}"
            )


# ---------------------------------------------------------------- 10

def test_10_the_score_table_adds_up_to_the_score_shown(escaneo, hallazgos):
    desglose = score_breakdown(hallazgos)
    total = sum(r["weight"] for r in desglose["accounts"]) + sum(
        r["weight"] for r in desglose["findings"]
    )
    ganado = sum(r["earned"] for r in desglose["accounts"]) + sum(
        r["earned"] for r in desglose["findings"]
    )
    assert round(total, 4) == round(desglose["total_weight"], 4)
    assert round(ganado, 4) == round(desglose["earned_weight"], 4)
    esperado = None if total == 0 else round(100 * ganado / total)
    assert desglose["score"] == esperado

    # …and the number the reader sees on the cover is that number.
    assert escaneo["scan"]["score"] == desglose["score"], (
        "la portada y la tabla de cálculo imprimen puntuaciones distintas"
    )


# --------------------- one evaluated object, four projections

def _fila_guardada(tmp_path):
    """A real scan, stored, so the channels are compared over ONE row."""
    import os

    os.environ["VIGIA_DB_PATH"] = str(tmp_path / "canales.db")
    from tests.fakes import FakeContext
    from vigia.db import Database
    from vigia.scan import collect_findings, evaluated_result, remaining_manual_checks
    from vigia.scoring import compute_score, severity_counts

    usuarios = [
        {"primaryEmail": "jefe@x.com", "orgUnitPath": "/", "isAdmin": True,
         "isDelegatedAdmin": False, "isEnrolledIn2Sv": False, "isEnforcedIn2Sv": True,
         "suspended": False, "archived": False, "lastLoginTime": "1970-01-01T00:00:00.000Z"},
        {"primaryEmail": "ana@x.com", "orgUnitPath": "/", "isAdmin": False,
         "isDelegatedAdmin": False, "isEnrolledIn2Sv": True, "isEnforcedIn2Sv": True,
         "suspended": False, "archived": False, "lastLoginTime": "2026-08-01T09:00:00.000Z"},
    ]
    ctx = FakeContext(users=usuarios)
    findings = collect_findings(ctx, label="canales")
    rendered = [f.to_dict() for f in findings]
    score = compute_score(findings)

    db = Database(str(tmp_path / "canales.db"))
    org = db.upsert_org("x.com", "jefe@x.com", b"k")
    return db, org, db.insert_scan(
        org["id"], score=score, counts=severity_counts(findings),
        findings=rendered, manual_checks=remaining_manual_checks(findings),
        engine_version="v1-prueba",
        result=evaluated_result(rendered, score, severity_counts(findings), ctx),
    )


def test_the_four_channels_agree_about_the_same_stored_scan(tmp_path):
    """The CSV exported 45 findings while the screen showed 50, five times in a
    row. Four readers of one row, each rebuilding it their own way."""
    from vigia.notify import scan_alert_body
    from vigia.projection import project
    from vigia.report import build_html_report, findings_csv_rows

    db, org, fila = _fila_guardada(tmp_path)
    resultado = project(fila)

    # 1. dashboard
    panel = {f["id"]: f["status"] for f in fila["findings"]}
    # 2. CSV
    filas = findings_csv_rows(fila)
    csv = {r[0]: r[3] for r in filas[1:]}
    # 3. PDF
    fila_pdf = dict(fila)
    fila_pdf["result"] = resultado
    html = build_html_report(
        dict(org), fila_pdf, None, {"has_baseline": False}, [],
        actions=resultado["actions"], breakdown=resultado["breakdown"],
        people=resultado["people_at_risk"],
    )
    # 4. e-mail
    _, cuerpo = scan_alert_body(
        dict(org), fila, None, {"has_baseline": False, "new": [], "worse": [], "resolved": []},
        "https://ejemplo/panel",
    )

    assert set(panel) == set(csv), (
        f"el CSV y la pantalla no listan lo mismo: solo pantalla={set(panel)-set(csv)}, "
        f"solo CSV={set(csv)-set(panel)}"
    )
    assert panel == csv, "el CSV y la pantalla discrepan sobre algún estado"

    # The PDF prints titles, not ids, so compare on what it actually renders —
    # and compare the COUNT too, which is what the CSV bug was about.
    import html as _html

    for finding in fila["findings"]:
        titulo = _html.escape(finding["title"], quote=True)
        assert titulo in html or finding["title"] in html, (
            f"{finding['id']} («{finding['title']}») está en la pantalla y no en el PDF"
        )
    bloques = html.count("<h3 style=\"margin-top:1.5mm\">")
    assert bloques >= len(fila["findings"]), (
        f"el PDF renderiza {bloques} tarjetas para {len(fila['findings'])} hallazgos"
    )

    # And the one number the reader compares across channels.
    assert str(fila["score"]) in cuerpo
    assert resultado["breakdown"]["score"] == fila["score"], (
        "la tabla de cálculo y la puntuación guardada no coinciden"
    )


def test_the_purge_cannot_make_two_scores_appear_on_one_page(tmp_path):
    """From the second day, the 24-hour purge removed the accounts the read-time
    recomputation counted, so the header printed one score and the derivation
    table another. Measured on a real row: 50 against 38."""
    import copy

    from vigia.projection import project
    from vigia.retention import strip_addresses

    db, org, fila = _fila_guardada(tmp_path)
    guardado = project(fila)["breakdown"]["score"]

    purgada = copy.deepcopy(fila)
    strip_addresses(purgada["findings"], "2026-08-03T00:00:00Z")
    # The stored result travels with the row and is NOT re-derived from the
    # purged findings.
    assert project(purgada)["breakdown"]["score"] == guardado
    assert project(purgada)["breakdown"]["score"] == purgada["score"]


def test_an_old_row_without_a_stored_result_still_projects(tmp_path):
    """Rows predating the column must not crash, and must use the same
    derivation function rather than a second implementation."""
    from vigia.projection import project

    db, org, fila = _fila_guardada(tmp_path)
    viejo = dict(fila)
    viejo["result"] = {}
    derivado = project(viejo)
    assert derivado["derived_at_read_time"] is True
    assert derivado["breakdown"]["score"] is not None


def test_the_coverage_line_says_what_was_not_read():
    from vigia.projection import coverage_line

    completo = coverage_line({"coverage": {
        "users": {"records": 17, "complete": True},
        "login": {"records": 423, "complete": True, "window_days": 174},
    }})
    assert "17 usuarios" in completo and "174 días" in completo
    assert "parcial" not in completo

    corto = coverage_line({"coverage": {
        "users": {"records": 3, "complete": False},
    }})
    assert "cobertura parcial" in corto and "usuarios" in corto


# ------------------------------- the test alert cannot be aimed elsewhere

def test_no_route_can_send_mail_to_an_address_from_the_request(tmp_path):
    """Replaces `test_the_test_alert_only_ever_goes_to_the_saved_address`.

    That endpoint took a recipient from the request body, so any authenticated
    customer could send mail from this domain to anybody — sender abuse on the
    same domain the outreach goes out from. It was fixed to use only the stored
    address, and now the endpoint is gone entirely along with the alerts panel it
    served.

    Removing the test with the route would have thrown away the invariant. The
    invariant is not "that endpoint behaves"; it is "no endpoint mails a
    body-supplied address", and that is what is asserted here — over the live
    url_map, so a route added tomorrow is covered without anybody remembering.
    """
    import os

    os.environ["VIGIA_DB_PATH"] = str(tmp_path / "aviso.db")
    os.environ["VIGIA_SMTP_HOST"] = "smtp.invalido"
    from vigia import create_app
    from vigia.services import get_db

    app = create_app()
    with app.app_context():
        org = get_db().upsert_org("x.com", "jefe@x.com", b"k")

    rutas = {str(r) for r in app.url_map.iter_rules()}
    assert "/api/notify/test" not in rutas, "el correo de prueba ha vuelto sin revisar esto"

    cliente = app.test_client()
    with cliente.session_transaction() as ses:
        ses["org_id"] = org["id"]

    # Every POST that takes a body, offered an address it must refuse to use.
    postables = [
        str(r)
        for r in app.url_map.iter_rules()
        if "POST" in (r.methods or set()) and not r.arguments and "tailnet" not in str(r)
    ]
    assert postables, "no hay rutas POST que comprobar"
    for ruta in postables:
        respuesta = cliente.post(ruta, json={"alert_email": "victima@ajena.com",
                                             "email": "victima@ajena.com",
                                             "to": "victima@ajena.com"})
        # 501 is a real answer: billing is deliberately not implemented. What
        # this test is about is the address, not the status — the 5xx sweep is
        # `test_routes_smoke`'s job.
        assert respuesta.status_code != 500, f"{ruta} → 500"
        cuerpo = respuesta.get_data(as_text=True)
        assert "victima@ajena.com" not in cuerpo, (
            f"{ruta} ha devuelto la dirección del cuerpo: puede estar usándola"
        )


def test_no_template_writes_the_retention_window_by_hand():
    """/privacy hardcoded "24 horas" five times while /help/data read the
    setting. Change the variable and two pages of the same product contradict
    each other about a data-protection commitment — in the document a reviewer
    at Google reads during verification."""
    import pathlib
    import re

    raiz = pathlib.Path(__file__).resolve().parents[1] / "vigia"
    # A claim ABOUT RETENTION, not any mention of a duration: "12-24 h de
    # sesion" is a different subject, and a comment explaining this very rule
    # is not a promise to a customer.
    RETENCION = re.compile(r"retenci[o\u00f3]n|se borran|borrado autom|deleted after")
    COMENTARIO = ("#", "*", chr(34) * 3, chr(39) * 3)
    sospechosas = []
    for archivo in raiz.rglob("*.py"):
        if archivo.name in ("config.py", "retention.py"):
            continue          # where the number legitimately lives / is documented
        for numero, linea in enumerate(archivo.read_text().splitlines(), 1):
            limpia = linea.strip()
            if limpia.startswith(COMENTARIO) or not RETENCION.search(limpia):
                continue
            if re.search(r"\b24\s*(horas|h\b)", limpia) and "{" not in limpia:
                sospechosas.append(f"{archivo.relative_to(raiz)}:{numero}: {limpia}")
    assert sospechosas == [], "retención escrita a mano:\n" + "\n".join(sospechosas)


def test_the_privacy_page_and_the_data_page_agree_on_the_window():
    from vigia import legal

    for horas in (24, 720):
        privacidad = legal.privacy_html("/vigia", "diego@diegofarina.com", horas)
        datos = legal.data_help_html("/vigia", "diego@diegofarina.com", horas)
        assert f"{horas} horas" in privacidad, horas
        assert f"{horas} horas" in datos, horas
        # …and neither still asserts the old default.
        if horas != 24:
            assert "24 horas" not in privacidad
            assert "24 horas" not in datos


# --------------------- the page that stands between a prospect and Google

def test_the_interstitial_names_the_warning_before_google_shows_it():
    """A non-technical reader meets "Google has not verified this application"
    and reads it as phishing — reasonably, because that is what phishing looks
    like. The prospect who stops there is not recovered by report quality."""
    from vigia import legal

    html = legal.connect_html("/vigia", "diego@diegofarina.com", 24)

    # It names the warning, and says what it does and does not mean.
    assert "no ha verificado esta aplicación" in html
    assert "no dice que la aplicación sea insegura" in html
    assert "Configuración avanzada" in html, "hay que decirle dónde pulsar"

    # The argument that actually unlocks the consent.
    assert "No puede leer tus correos" in html
    assert "solo lectura" in html
    # A way out as visible as the way forward.
    assert "Prefiero no conectar" in html
    # And the things a stranger needs before handing over a tenant.
    assert "/vigia/privacy" in html and "/vigia/terms" in html
    assert "diego@diegofarina.com" in html
    assert "24 horas" in html, "la retención también se lee de la configuración"


def test_the_landing_button_goes_through_the_interstitial():
    """Otherwise the page exists and nobody sees it."""
    import pathlib

    landing = (
        pathlib.Path(__file__).resolve().parents[2]
        / "frontend" / "src" / "pages" / "Landing.tsx"
    ).read_text()
    assert "/connect" in landing
    assert "api/auth/google/start" not in landing, "salta la página intermedia"


# ------------------------ the report has to be answerable

def test_the_report_ends_with_a_way_to_reply(tmp_path, monkeypatch):
    """Free report → paid remediation, and the document used to end with a score
    and no way to answer it."""
    # With no contact address configured the block is correctly absent, so the
    # test declares one rather than the report inventing one.
    monkeypatch.setenv("VIGIA_CONTACT_EMAIL", "diego@diegofarina.com")
    from vigia.projection import project
    from vigia.report import build_html_report

    db, org, fila = _fila_guardada(tmp_path)
    resultado = project(fila)
    fila = dict(fila)
    fila["result"] = resultado
    html = build_html_report(
        dict(org), fila, None, {"has_baseline": False}, [],
        actions=resultado["actions"], breakdown=resultado["breakdown"],
        people=resultado["people_at_risk"],
    )
    assert "¿Quieres que lo arreglemos?" in html
    assert "mailto:" in html
    # The prefilled mail carries the two things that make a reply useful.
    assert "x.com" in html
    assert "diego@diegofarina.com" in html
    # The follow-up offer, worded as MY commitment rather than the tool's. It used
    # to say "seguimiento mensual: el escaneo se repite solo", which described the
    # recurring-scan feature — and that came off the panel, so the sentence was
    # selling something the product no longer does.
    assert "repetimos la revisión cada cierto tiempo" in html
    assert "mensual" not in html, "el informe vuelve a prometer seguimiento automático"
    assert "se repite solo" not in html, "la misma promesa con otras palabras"
    # …and no price, because that conversation is not a PDF's job.
    assert "€" not in html and "EUR" not in html


def test_the_dashboard_has_the_same_block():
    """The contact block, now checked in BOTH languages.

    It used to grep `Dashboard.tsx` for three Spanish sentences. Those moved to
    `content/panel.ts` when the interface became bilingual, so the assertion had to
    follow the text to where the text now lives — and following it made the test
    stronger: the English dashboard could have promised the monthly monitoring this
    guards against and the Spanish-only version would not have noticed.

    `mailto:` stays asserted against the component, because the link is built there
    and not in the catalogue.
    """
    import pathlib

    raiz = pathlib.Path(__file__).resolve().parents[2] / "frontend" / "src"
    catalogo = (raiz / "content" / "panel.ts").read_text()
    panel = (raiz / "pages" / "Dashboard.tsx").read_text()

    assert "mailto:" in panel, "el panel ya no ofrece escribir"

    # Spanish
    assert "¿Quieres que lo arreglemos?" in catalogo
    assert "repetimos la revisión cada cierto tiempo" in catalogo
    # English
    assert "Would you like us to fix it?" in catalogo

    for palabra in ("mensual", "monthly"):
        assert palabra not in catalogo, (
            f"el panel vuelve a prometer seguimiento automático ({palabra})"
        )


# ------------------- a time window is measured, never written by hand

def test_no_check_writes_a_time_window_into_its_own_text():
    """`audit-risky-changes` said "registro de auditoría (~180 días)" while
    reading at most three pages, and the OAuth card said "los últimos ~180 días"
    while covering six. A number in a template is a promise nobody checks; the
    same rule the retention window already follows."""
    import pathlib
    import re

    # THE WHOLE TREE, not just the package. The first version of this test
    # scanned only `vigia/*.py`, so it passed while the translation catalogue —
    # which lives in `scripts/build_locales.py` and compiles into
    # `vigia/locales/*.json` — carried "(~180 días)" and OVERWROTE the measured
    # label on every read. Third time a catalogue string has eaten a
    # measurement; a test that cannot see the catalogue cannot catch it.
    backend = pathlib.Path(__file__).resolve().parents[1]
    # A window ASSERTED as this check's own coverage. Statements about what
    # Google retains ("Google conserva los eventos unos 180 días") are facts
    # about Google, and are allowed next to the measured figure.
    VENTANA = re.compile(r"(scope|alcance|Basado en|ventana leída)[^\n]*?~?\d+\s*d[íi]as?")
    SOBRE_GOOGLE = re.compile(r"conserva|retiene|Google (guarda|mantiene)|que conserva Google")
    COMENTARIO = ("#", "*", chr(34) * 3, chr(39) * 3)
    objetivos = [
        *(backend / "vigia").rglob("*.py"),
        *(backend / "scripts").rglob("*.py"),
        *(backend / "vigia" / "locales").rglob("*.json"),
    ]
    sospechosas = []
    for archivo in objetivos:
        for numero, linea in enumerate(archivo.read_text().splitlines(), 1):
            limpia = linea.strip()
            if limpia.startswith(COMENTARIO):
                continue
            if SOBRE_GOOGLE.search(limpia) or "{" in limpia or "window_label" in limpia:
                continue
            if VENTANA.search(limpia):
                sospechosas.append(f"{archivo.relative_to(backend)}:{numero}: {limpia}")
    assert sospechosas == [], "ventana escrita a mano:\n" + "\n".join(sospechosas)


def test_the_scope_label_reads_the_measured_window():
    from tests.fakes import FakeContext
    from vigia.checks.util import window_label

    ctx = FakeContext()
    ctx.coverage["admin"].records = 483
    ctx.coverage["admin"].oldest = "2026-02-06T00:00:00Z"
    ctx.coverage["admin"].newest = "2026-08-03T00:00:00Z"
    etiqueta = window_label(ctx, "admin", "registro de auditoría")
    assert "178 días leídos" in etiqueta and "483 eventos" in etiqueta

    # An unmeasured source says so rather than inventing a number.
    ctx.coverage.pop("login")
    assert "sin medir" in window_label(ctx, "login", "registro de acceso")


# --------------------------- a known limit must not read as a malfunction

def test_the_coverage_line_states_the_limit_without_shouting():
    """"LEÍDO A MEDIAS" in capitals on the first data line of the report is
    correct, honest, and read by a customer as a broken tool. A known limit and
    a fault should not look the same; the figure is what tells them apart."""
    from vigia.projection import coverage_line

    linea = coverage_line({"coverage": {
        "users": {"records": 17, "complete": True},
        "token": {"records": 16, "complete": False, "window_days": 6},
    }})
    assert "cobertura parcial en autorizaciones OAuth: 6 de 180 días" in linea
    assert "LEÍDO A MEDIAS" not in linea
    assert linea.upper() != linea, "sin mayúsculas de alarma"


def test_a_complete_read_says_nothing_about_partiality():
    from vigia.projection import coverage_line

    linea = coverage_line({"coverage": {"users": {"records": 17, "complete": True}}})
    assert "parcial" not in linea


# ------------- the incremental read, and the window that grows

def test_the_second_scan_reads_only_what_is_new(tmp_path):
    """Re-reading Google's whole 180-day token window on every scan bought six
    days at 20 000 events, so three findings stopped saying anything. Measured
    against the real API: 13.6 s for the initial sweep, 0.36 s and ONE page for
    the next one, complete."""
    from vigia.config import load_settings
    from vigia.google_client.grants import Coverage, dehydrate, fold
    from vigia.scan import ScanContext

    class Almacen:
        def __init__(self):
            self.estado = {"grants": {}, "watermark": "", "oldest": ""}

        def load(self):
            return dict(self.estado)

        def save(self, grants, watermark, oldest):
            anterior = self.estado["oldest"]
            self.estado = {
                "grants": grants,
                "watermark": watermark,
                # never move the earliest event forward
                "oldest": min(x for x in (anterior, oldest) if x) if (anterior and oldest)
                else (oldest or anterior),
            }

    def evento(app, cuenta, cuando):
        return {
            "id": {"time": cuando},
            "actor": {"email": cuenta},
            "events": [{"name": "authorize", "parameters": [
                {"name": "client_id", "value": app},
                {"name": "app_name", "value": app.upper()},
            ]}],
        }

    class Informes:
        """First call returns an old app and reports the cap was hit; the second
        returns only what is newer than the watermark, in one page."""

        def __init__(self):
            self.llamadas = []

        def token_grants(self, max_pages=20, start_time=""):
            self.llamadas.append(start_time)
            if not start_time:
                grants = fold([evento("vieja", "a@x.com", "2026-07-28T10:00:00.000Z")])
                return grants, Coverage(
                    source="token", pages=20, records=20000, complete=False,
                    oldest="2026-07-28T10:00:00.000Z", newest="2026-08-03T10:00:00.000Z",
                    reason="se alcanzó el tope de 20 páginas",
                )
            grants = fold([evento("nueva", "b@x.com", "2026-08-03T12:00:00.000Z")])
            return grants, Coverage(
                source="token", pages=1, records=1, complete=True,
                oldest="2026-08-03T12:00:00.000Z", newest="2026-08-03T12:00:00.000Z",
            )

    almacen, informes = Almacen(), Informes()

    def contexto():
        return ScanContext(None, informes, load_settings(), grant_store=almacen)

    primero = contexto()
    uno = primero.token_grants()
    assert set(uno) == {"vieja"}
    assert primero.coverage["token"].complete is False

    segundo = contexto()
    dos = segundo.token_grants()

    # The second read asked only for what came after the watermark…
    assert informes.llamadas == ["", "2026-08-03T10:00:00.000Z"]
    # …and the old application is STILL THERE: accumulated, not re-fetched.
    assert set(dos) == {"vieja", "nueva"}
    cobertura = segundo.coverage["token"]
    assert cobertura.complete is True, "todo lo anterior a la marca ya está en mano"
    # The window grew backwards-anchored: it keeps the earliest event ever seen.
    assert cobertura.oldest == "2026-07-28T10:00:00.000Z"
    assert cobertura.newest == "2026-08-03T12:00:00.000Z"


def test_the_stored_fold_survives_a_round_trip():
    from vigia.google_client.grants import dehydrate, fold, rehydrate

    original = fold([{
        "id": {"time": "2026-08-01T10:00:00.000Z"},
        "actor": {"email": "ana@x.com"},
        "events": [{"name": "authorize", "parameters": [
            {"name": "client_id", "value": "crm"},
            {"name": "app_name", "value": "CRM"},
            {"name": "scope", "multiValue": ["https://www.googleapis.com/auth/gmail.modify"]},
        ]}],
    }])
    vuelta = rehydrate(dehydrate(original))
    assert set(vuelta) == {"crm"}
    assert vuelta["crm"].name == "CRM"
    assert vuelta["crm"].scopes == original["crm"].scopes
    assert vuelta["crm"].still_granted_for("ana@x.com") is True


def test_a_corrupt_stored_row_is_dropped_rather_than_guessed():
    from vigia.google_client.grants import rehydrate

    assert rehydrate({"x": "no soy un dict"}) == {}
    recuperado = rehydrate({"x": {"name": "X", "users": {"a@x.com": {"authorized": "basura"}}}})
    assert recuperado["x"].still_granted_for("a@x.com") is False


def test_suspended_tokens_does_not_inherit_a_source_it_does_not_need():
    """It said "no suspended account has grants pending to revoke" AND carried
    an inherited "cannot verify" from the token feed. With zero suspended
    accounts the question is answered from the directory alone."""
    from tests.fakes import FakeContext
    from vigia.checks import check_suspended_tokens
    from vigia.scan import _inherit_uncertainty

    ctx = FakeContext(
        users=[{"primaryEmail": "a@x.com", "suspended": False, "archived": False,
                "isAdmin": False, "isDelegatedAdmin": False}],
        complete={"token": False},
    )
    producidos = check_suspended_tokens.run(ctx)
    final = _inherit_uncertainty(producidos, check_suspended_tokens.SOURCES, ctx)
    assert [f.status for f in final] == ["pass"]
    assert final[0].depends_on == ("users",)
    assert "ESTE VEREDICTO NO SE SOSTIENE" not in final[0].description


def test_the_measured_window_survives_translation():
    """`localize_finding` replaces `scope_label` from the catalogue, so a
    measurement written into it is deleted on the way out — which is exactly
    what the CSV was showing: "(~180 días)" over a label that said 178 measured.
    `coverage_note` is a field for that reason, and this keeps it one."""
    import pathlib as _p

    from vigia.i18n import localize_finding

    finding = {
        "id": "audit-admin-log",
        "title": "x",
        "severity": "info",
        "status": "pass",
        "scope_label": "registro de auditoria de administracion",
        "coverage_note": "178 dia(s) leidos, 483 eventos",
        "details": {},
    }
    for lang in ("es", "en"):
        traducido = localize_finding(finding, lang)
        assert traducido["coverage_note"] == "178 dia(s) leidos, 483 eventos", lang
        assert "180" not in (traducido.get("scope_label") or ""), lang

    base = _p.Path(__file__).resolve().parents[1] / "vigia" / "locales"
    for lang in ("es", "en"):
        crudo = (base / (lang + ".json")).read_text()
        assert "180 d" not in crudo, lang + ": el catalogo trae una ventana escrita"


def test_the_csv_exports_the_measured_window_as_its_own_column():
    from vigia.report import findings_csv_rows

    filas = findings_csv_rows({"findings": [{
        "id": "audit-admin-log", "title": "x", "severity": "info", "status": "pass",
        "scope_label": "registro de auditoria de administracion",
        "coverage_note": "178 dia(s) leidos, 483 eventos",
        "affected_items": [], "accounts": [], "details": {},
    }]})
    assert "ventana_leida" in filas[0]
    columna = filas[0].index("ventana_leida")
    assert filas[1][columna] == "178 dia(s) leidos, 483 eventos"
