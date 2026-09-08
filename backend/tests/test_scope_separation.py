"""Organization settings are not personal failings.

Written after a real report listed all seventeen employees of a tenant as
"at risk", each with seven problems, and not one of the seven was about them:
they were console toggles. A list that points at everybody points at nobody,
and it was the section that told the customer where to start.

The rule under test is a declaration, not an inference — `scope_type` on the
finding — because the previous rule ("does it name accounts?") is exactly what
let the policy checks quietly enrol the whole payroll.
"""
import pytest

from vigia.checks.finding import ACCOUNT_SCOPE, ORG_SCOPE, Finding
from vigia.scoring import compute_score, is_org_scope, people_at_risk, score_breakdown

PLANTILLA = [f"p{i}@empresa.com" for i in range(17)]


def ajuste(fid, severity="high", status="fail"):
    """A console setting: no names attached."""
    return Finding(id=fid, title=fid, severity=severity, status=status,
                   scope_type=ORG_SCOPE).to_dict()


def persona(fid, cuentas, severity="high", status="fail"):
    return Finding(id=fid, title=fid, severity=severity, status=status,
                   scope_type=ACCOUNT_SCOPE, accounts=list(cuentas)).to_dict()


# ------------------------------------------------- the two cases asked for

def test_bad_settings_and_clean_people_blame_nobody():
    findings = [ajuste(f"policy-{n}") for n in range(7)]
    findings.append(persona("2sv-users", [], status="pass"))

    assert people_at_risk(findings) == []
    score = compute_score(findings)
    assert score is not None and score < 20, "los ajustes rotos deben doler igual"


def test_clean_settings_and_bad_people_name_only_those_people():
    findings = [ajuste(f"policy-{n}", status="pass") for n in range(7)]
    findings.append(persona("2sv-users", PLANTILLA[:3]))

    en_riesgo = {row["account"] for row in people_at_risk(findings)}
    assert en_riesgo == set(PLANTILLA[:3])
    assert compute_score(findings) is not None


def test_a_console_toggle_does_not_weigh_once_per_employee():
    """The seventeen-times bug: one setting scored as seventeen exposures, so
    a single toggle outweighed everything else in the report."""
    uno = [ajuste("policy-drive-sharing")]
    breakdown = score_breakdown(uno)
    assert len(breakdown["findings"]) == 1
    assert breakdown["total_weight"] == 6           # one high, once
    assert breakdown["accounts"] == []


# ------------------------------------------------------- the declaration

def test_an_organization_finding_may_not_name_accounts():
    with pytest.raises(ValueError, match="no puede enumerar cuentas"):
        Finding(id="policy-x", title="x", severity="high", status="fail",
                scope_type=ORG_SCOPE, accounts=["a@x.com"])


def test_every_policy_check_declares_organization_scope():
    """A new check must not be able to slip back into the people block just by
    forgetting the field: the default is `accounts`, so this is the guard."""
    from vigia.checks import check_policies

    for check in check_policies.CHECKS:
        assert check.finding_id.startswith("policy-")

    import inspect
    fuente = inspect.getsource(check_policies._finding)
    assert "scope_type=ORG_SCOPE" in fuente
    assert "accounts=[]" in fuente


@pytest.mark.parametrize("modulo", [
    "check_email_auth", "check_mail_transport", "check_audit_log", "check_oauth_apps",
])
def test_the_other_tenant_wide_modules_declare_it_too(modulo):
    """DNS records, the audit log and the third-party apps authorised in the
    tenant are all facts about the organization, not about a person."""
    import importlib
    import inspect

    fuente = inspect.getsource(importlib.import_module(f"vigia.checks.{modulo}"))
    assert fuente.count("scope_type=ORG_SCOPE") == fuente.count("Finding(")


def test_old_scans_without_the_field_still_render():
    """Stored scans predate the field. They keep the old rule rather than
    silently changing a number the customer already saw."""
    viejo = {"id": "policy-password", "title": "x", "severity": "high",
             "status": "fail", "accounts": ["a@x.com", "b@x.com"]}
    assert is_org_scope(viejo) is False
    assert {r["account"] for r in people_at_risk([viejo])} == {"a@x.com", "b@x.com"}

    sin_cuentas = {"id": "email-spf", "title": "x", "severity": "high", "status": "fail"}
    assert is_org_scope(sin_cuentas) is True


# --------------------------------------------- the ceiling on the people block

def test_headcount_cannot_drown_the_settings():
    """A 2 000-seat tenant with every toggle open must not score well just
    because its people block is enormous by comparison."""
    grande = [persona("2sv-users", [f"u{i}@x.com" for i in range(500)])]
    grande += [ajuste(f"policy-{n}") for n in range(20)]

    breakdown = score_breakdown(grande)
    assert breakdown["people_weight"] <= breakdown["org_weight"]
    assert breakdown["people_scale"] < 1


def test_a_small_tenant_is_not_rescaled_at_all():
    """The cap must be inert where the people block is already the smaller of
    the two, which is the common case."""
    pequeno = [persona("2sv-users", ["a@x.com"]), ajuste("p1"), ajuste("p2"), ajuste("p3")]
    assert score_breakdown(pequeno)["people_scale"] == 1.0


# ------------------------------------ never "no change" when the engine moved

def test_the_report_refuses_to_compare_across_engine_versions():
    """Going from 30 checks to 44 and printing "0 new, 0 worse, 0 resolved" is
    the most confident lie the report can tell: the reader reads it as
    "nothing moved", when what moved was the yardstick.

    Checked in BOTH languages, and against the catalogue rather than against a
    Spanish literal: the sentence moved into `report.cambios_motor`, so a test that
    hard-codes one language would only prove half the report refuses to compare.
    """
    from vigia.i18n import SUPPORTED_LANGS, catalog, text
    from vigia.report import _changes

    # The claim itself, per language, read where the translator can see it.
    for lang, marca in (("es", "no son comparables"), ("en", "not comparable")):
        assert marca in catalog(lang)["report"]["cambios_motor"]

    for lang in SUPPORTED_LANGS:
        html = _changes({
            "has_baseline": True,
            "engine_changed": True,
            "previous_engine": "v1-aa204d7c",
            "engine_version": "v1-97c51d85",
            "new": [], "worse": [], "resolved": [],
        }, lang)
        assert text(
            lang, "report.cambios_motor", antes="v1-aa204d7c", ahora="v1-97c51d85"
        ) in html
        assert "v1-aa204d7c" in html and "v1-97c51d85" in html
        assert "<table>" not in html, f"{lang}: ninguna tabla de ceros"


def test_a_same_engine_comparison_still_shows_the_table():
    from vigia.i18n import SUPPORTED_LANGS, text
    from vigia.report import _changes

    for lang in SUPPORTED_LANGS:
        html = _changes({
            "has_baseline": True, "engine_changed": False,
            "new": [{"title": "algo"}], "worse": [], "resolved": [],
        }, lang)
        assert "<table>" in html and "algo" in html
        # The row label comes from the catalogue, in the language asked for.
        assert text(lang, "report.nuevos") in html


# ------------------------- a per-tenant document in a shared cache

def test_every_api_response_forbids_being_stored():
    """Cloudflare caches by file extension and `.csv` is on its default list.
    `/api/report.csv` sat at the edge for four hours and was served to anyone
    who requested that URL — no cookie, HTTP 200 — with the customer's
    employee addresses in it. The stale export was the symptom; a per-tenant
    document in a shared cache was the defect."""
    import os

    os.environ.setdefault("VIGIA_DB_PATH", "/tmp/vigia-cache-test.db")
    from vigia import create_app

    app = create_app()
    client = app.test_client()
    for path in ("/api/me", "/api/report.csv", "/api/scan/latest", "/api/demo/scan"):
        response = client.get(path)
        cache = response.headers.get("Cache-Control", "")
        assert "no-store" in cache, f"{path} se puede cachear: {cache!r}"
        assert response.headers.get("CDN-Cache-Control") == "no-store", path


def test_the_static_bundle_is_still_cacheable():
    """The fix has to be surgical: hashed assets SHOULD be cached, and making
    the whole site uncacheable would trade a leak for a slow product."""
    import os

    os.environ.setdefault("VIGIA_DB_PATH", "/tmp/vigia-cache-test.db")
    from vigia import create_app

    response = create_app().test_client().get("/privacy")
    assert "no-store" not in (response.headers.get("Cache-Control") or "")


# ------------- everybody a finding names has to reach the summary

def _account_findings_name_everyone(findings):
    """The invariant: an account-scope finding in fail/warn may not print a
    person on its card and leave them out of `accounts`, because `accounts` is
    what "people at risk" and the score table are built from."""
    import re

    from vigia.scoring import is_inventory, is_org_scope

    direccion = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
    fallos = []
    for f in findings:
        if f.get("manual") or f.get("status") not in ("fail", "warn"):
            continue
        if is_org_scope(f) or is_inventory(f):
            continue
        nombrados = set()
        for item in f.get("affected_items") or []:
            nombrados |= set(direccion.findall(str(item)))
        fuera = nombrados - set(f.get("accounts") or [])
        if fuera:
            fallos.append((f["id"], sorted(fuera)))
    return fallos


def test_the_demo_scan_names_everybody_it_accuses():
    """Run over the real engine, not a fixture: the defect this guards was a
    single check filling `affected_items` and not `accounts`, and a synthetic
    finding would never have caught it."""
    from vigia.config import load_settings
    from vigia.demo import build_demo_payload
    from vigia.scoring import people_at_risk

    payload = build_demo_payload(load_settings())
    findings = payload["scan"]["findings"]

    assert _account_findings_name_everyone(findings) == []

    # …and the other half of the invariant: everyone named does arrive.
    en_riesgo = {row["account"] for row in people_at_risk(findings)}
    from vigia.scoring import is_inventory, is_org_scope

    for f in findings:
        if f.get("manual") or f.get("status") not in ("fail", "warn"):
            continue
        if is_org_scope(f) or is_inventory(f) or not f.get("accounts"):
            continue
        faltan = set(f["accounts"]) - en_riesgo
        assert not faltan, f"{f['id']} acusa a {faltan} y no salen en personas en riesgo"


def test_the_coherence_engine_catches_the_backup_codes_shape():
    """The exact defect, as a regression: six people on the card, two in
    `accounts`, four of them invisible to every summary in the report."""
    from vigia.checks.consistency import check_consistency

    roto = [{
        "id": "2sv-backup-codes",
        "title": "Códigos de respaldo",
        "severity": "high",
        "status": "fail",
        "scope_type": "accounts",
        "accounts": ["jefe@x.com"],
        "affected_items": [
            "jefe@x.com (superadministrador): 1 generación(es)",
            "david@x.com (usuario): 1 generación(es)",
        ],
    }]
    problemas = check_consistency(roto)
    assert any("david@x.com" in p for p in problemas), problemas


def test_a_finding_that_lists_only_the_people_it_names_is_coherent():
    from vigia.checks.consistency import check_consistency

    bien = [{
        "id": "2sv-backup-codes", "title": "x", "severity": "high", "status": "fail",
        "scope_type": "accounts",
        "accounts": ["jefe@x.com", "david@x.com"],
        "affected_items": ["jefe@x.com: 1", "david@x.com: 1"],
    }]
    assert check_consistency(bien) == []


# --------------------- "I saw nothing" is not "I could not look"

def _ctx_con_ventana(completa: bool):
    """A scan context whose token window is or is not complete."""
    from vigia.google_client.grants import Coverage, fold

    class Settings:
        widely_granted_threshold = 10

    class Ctx:
        settings = Settings()

        def __init__(self):
            self.coverage = {
                "token": Coverage(
                    source="token", pages=20, records=20000, complete=completa,
                    oldest="2026-07-27T00:00:00Z", newest="2026-08-03T00:00:00Z",
                    reason="" if completa else "se alcanzó el tope de 20 páginas",
                )
            }

        def token_grants(self):
            return fold([])

        def admin_events(self):
            return []

        def complete(self, source):
            c = self.coverage.get(source)
            return True if c is None else c.complete

    return Ctx()


def test_an_incomplete_oauth_window_never_reads_as_a_pass():
    """The old code took five pages of a feed that emits ~1600 events a day,
    covering two days, and printed "based on the last ~180 days". With no
    high-risk app in those two days the card said Correcto — a pass earned by
    not looking."""
    from vigia.checks import check_oauth_apps

    parcial = {f.id: f for f in check_oauth_apps.run(_ctx_con_ventana(False))}
    assert parcial["oauth-high-risk"].status == "undetermined"
    assert parcial["oauth-widely-granted"].status == "undetermined"
    assert "VENTANA INCOMPLETA" in parcial["oauth-high-risk"].description
    # And it says which window it did read, not just that it fell short.
    assert "7 días" in parcial["oauth-high-risk"].description


def test_a_complete_window_reaches_a_verdict():
    from vigia.checks import check_oauth_apps

    completo = {f.id: f for f in check_oauth_apps.run(_ctx_con_ventana(True))}
    assert completo["oauth-high-risk"].status == "pass"
    assert "VENTANA INCOMPLETA" not in completo["oauth-high-risk"].description


def test_the_delegation_finding_does_not_depend_on_the_token_window():
    """Domain-wide delegation is read from the admin audit log. Blocking it on
    the token feed's coverage would be over-reporting, which erodes trust in
    the partial flag exactly as fast as under-reporting does."""
    from vigia.checks import check_oauth_apps

    parcial = {f.id: f for f in check_oauth_apps.run(_ctx_con_ventana(False))}
    assert "VENTANA INCOMPLETA" not in parcial["oauth-dwd"].description


def test_folding_collapses_the_feed_and_keeps_what_the_checks_need():
    """60 000 events fold to nine applications in this tenant: the raw list was
    never what any check needed, which is why the page cap could be raised
    without the memory becoming the problem."""
    from vigia.google_client.grants import fold

    eventos = []
    for i in range(500):                      # el mismo token renovándose
        eventos.append({
            "id": {"time": "2026-08-01T10:00:00.000Z"},
            "actor": {"email": "ana@x.com"},
            "events": [{"name": "authorize", "parameters": [
                {"name": "client_id", "value": "app-1"},
                {"name": "app_name", "value": "CRM"},
                {"name": "scope", "multiValue": ["https://www.googleapis.com/auth/gmail.modify"]},
            ]}],
        })
    grants = fold(eventos)
    assert len(grants) == 1
    assert grants["app-1"].name == "CRM"
    assert grants["app-1"].accounts == {"ana@x.com"}


def test_domains_are_paginated():
    """An agency tenant carries its clients' domains. One unpaginated call
    meant SPF, DKIM and DMARC were checked on the first page only and the rest
    appeared nowhere — not failing, not pending, absent."""
    import inspect

    from vigia.google_client.directory import DirectoryClient

    fuente = inspect.getsource(DirectoryClient.list_domains)
    assert "pageToken" in fuente and "nextPageToken" in fuente
    assert "MAX_PAGES" in fuente
