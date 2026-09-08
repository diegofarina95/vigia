from datetime import datetime, timedelta, timezone

from vigia.jobs import due_cutoffs
from vigia.report import build_html_report, findings_csv_rows

ORG = {"primary_domain": "example.com"}

SCAN = {
    "created_at": "2026-07-21T10:00:00+00:00",
    "score": 42,
    "counts": {"critical": 1, "high": 2, "medium": 0, "low": 1},
    "findings": [
        {
            "id": "2sv-delegated-admins",
            "title": "Admin accounts without 2SV",
            "severity": "critical",
            "status": "fail",
            "description": "Bad news",
            "affected_items": ["a@example.com", "b@example.com"],
            "remediation": "Enroll them",
            "cis_control": "CIS GWS §1",
            "change": "new",
        },
        {
            "id": "email-spf",
            "title": "SPF records",
            "severity": "high",
            "status": "pass",
            "description": "All good",
            "affected_items": [],
            "remediation": "",
            "cis_control": "",
            "change": "resolved",
        },
    ],
    "manual_checks": [
        {
            "id": "manual-drive",
            "title": "Drive sharing",
            "area": "Drive",
            "why_manual": "Restricted scope",
            "instructions": ["Open console", "Check setting"],
        }
    ],
}

SUMMARY = {
    "has_baseline": True,
    "new": [{"id": "2sv-delegated-admins", "title": "Admin accounts without 2SV", "severity": "critical"}],
    "worse": [],
    "improved": [],
    "resolved": [{"id": "email-spf", "title": "SPF records", "severity": "high"}],
}


ACTIONS = [
    {
        "id": "enforce_2sv_org",
        "title": "Enforce 2-Step Verification for the whole organization",
        "console_path": "Security > Authentication > 2-Step Verification",
        "console_url": "https://admin.google.com/ac/security/2sv",
        "minutes": 15,
        "user_impact": "Quien no tenga segundo factor se queda fuera hasta que lo registre.",
        "findings_closed": 3,
        "criticals_closed": 1,
        "highs_closed": 2,
        "accounts_affected": 9,
        "score_gain": 22,
        "finding_ids": ["2sv-delegated-admins"],
        "finding_titles": ["Admin accounts without 2SV"],
        "leverage": 0.2,
    }
]

BREAKDOWN = {
    "score": 42,
    "total_weight": 16,
    "earned_weight": 6.0,
    "lost_weight": 10.0,
    "accounts": [
        {
            "account": "ghost@example.com",
            "severity": "critical",
            "status": "fail",
            "finding_id": "2sv-delegated-admins",
            "weight": 10,
            "credit": 0.0,
            "earned": 0.0,
            "also_in": ["never-logged-in"],
        }
    ],
    "findings": [
        {"id": "email-spf", "title": "SPF", "severity": "high", "status": "pass",
         "weight": 6, "earned": 6.0}
    ],
    "excluded": [
        {"id": "email-dkim", "severity": "medium", "status": "undetermined",
         "reason": "no se ha podido determinar"}
    ],
    "weights": {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0},
    "credits": {"pass": 1.0, "warn": 0.5, "fail": 0.0},
}

PEOPLE = [
    {
        "account": "ghost@example.com",
        "worst": "critical",
        "weight": 16,
        "issues": [
            {"id": "2sv-delegated-admins", "title": "Admin accounts without 2SV", "severity": "critical"},
            {"id": "never-logged-in", "title": "Never signed in", "severity": "low"},
        ],
    }
]


def test_report_contains_key_sections():
    html = build_html_report(
        ORG, SCAN, previous_score=60, summary=SUMMARY,
        domains=[{"domain": "example.com", "source": "google"}],
        actions=ACTIONS, breakdown=BREAKDOWN, people=PEOPLE,
    )
    assert "<!doctype html>" in html.lower()
    assert "example.com" in html
    assert "42/100" in html  # score now a secondary metric, not the headline
    assert "18 respecto al anterior" in html  # 42 - 60, con flecha ▼
    assert "Admin accounts without 2SV" in html
    # Renombrado: "en tu organización", porque hay una segunda tabla para los
    # cambios de cobertura y confundirlas es el fallo que se estaba arreglando.
    assert "Cambios en tu organización" in html
    assert "Comprobaciones manuales" in html
    assert "Cómo se ha calculado la puntuación" in html  # auditable breakdown
    assert "@page" in html  # print CSS for PDF export
    assert "print-color-adjust: exact" in html  # severity colour survives printing


def test_report_leads_with_counts_and_people_not_the_score():
    html = build_html_report(
        ORG, SCAN, 60, SUMMARY, [], actions=ACTIONS, breakdown=BREAKDOWN, people=PEOPLE
    )
    headline = html[: html.index("Arregla esto primero")]
    # The severity tiles and the people sentence come before the score label.
    assert "cuenta en riesgo" in headline or "cuentas en riesgo" in headline
    assert headline.index("crítico") < headline.index("puntuación de postura")


def test_fix_first_block_states_impact_effort_and_user_warning():
    html = build_html_report(ORG, SCAN, 60, SUMMARY, [], actions=ACTIONS, people=PEOPLE)
    assert "Arregla esto primero" in html
    assert "cierra 3" in html and "hallazgos" in html
    assert "1 crítico" in html and "2 altos" in html
    assert "afecta a 9" in html
    assert "puntuación +22" in html
    assert "unos 15 minutos" in html
    assert "Aviso para los usuarios" in html
    assert "se queda fuera" in html


def test_people_section_lists_everyone_no_truncation():
    many = [
        {
            "account": f"user{i}@example.com",
            "worst": "high",
            "weight": 6,
            "issues": [{"id": "x", "title": "No 2SV", "severity": "high"}],
        }
        for i in range(13)
    ]
    html = build_html_report(ORG, SCAN, None, None, [], people=many)
    assert "Personas en riesgo (13)" in html
    for i in range(13):
        assert f"user{i}@example.com" in html  # the printed report never truncates


def test_breakdown_shows_account_rows_and_exclusions():
    html = build_html_report(ORG, SCAN, 60, SUMMARY, [], breakdown=BREAKDOWN)
    assert "ghost@example.com" in html
    assert "una sola vez, con la peor severidad" in html
    assert "no se ha podido determinar" in html  # exclusions are shown, not hidden


def test_report_escapes_html_injection():
    scan = dict(SCAN)
    scan["findings"] = [
        {
            "id": "x",
            "title": "<script>alert(1)</script>",
            "severity": "low",
            "status": "warn",
            "description": "",
            "affected_items": ["<img onerror=x>"],
            "remediation": "",
            "cis_control": "",
        }
    ]
    html = build_html_report(ORG, scan, None, None, [])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_report_handles_missing_score_and_no_baseline():
    """Point 5: the first scan must say so explicitly, not leave a gap."""
    scan = dict(SCAN, score=None)
    html = build_html_report(ORG, scan, None, {"has_baseline": False}, [])
    assert "—" in html
    assert "Primer escaneo: todavía no hay comparativa" in html


def test_the_reports_chrome_answers_in_english_too():
    """The armature of the report — section titles, labels, the sentences that
    explain a number — used to be Spanish f-strings. An English report therefore
    arrived with Spanish scaffolding around English findings, which is the same
    defect as an untranslated finding, one layer out.

    Read from the catalogue on purpose: the assertion is "the report says what the
    catalogue says, in the language asked for", not "the report says this string".
    """
    from vigia.i18n import text

    ingles = build_html_report(
        ORG, SCAN, 60, SUMMARY, [{"domain": "example.com", "source": "google"}],
        actions=ACTIONS, breakdown=BREAKDOWN, people=PEOPLE, lang="en",
    )
    espanol = build_html_report(
        ORG, SCAN, 60, SUMMARY, [{"domain": "example.com", "source": "google"}],
        actions=ACTIONS, breakdown=BREAKDOWN, people=PEOPLE, lang="es",
    )
    assert '<html lang="en">' in ingles and '<html lang="es">' in espanol

    for clave in (
        "informe_postura", "arregla_primero", "arregla_primero_nota",
        "puntuacion_postura", "cambios_organizacion", "puntuacion_calculo",
        "resumen_direccion", "lo_mas_grave", "por_donde_empezar",
        "comprobaciones_manuales_nota", "personas_orden", "generado_por",
    ):
        en, es = text("en", f"report.{clave}"), text("es", f"report.{clave}")
        assert en != es, f"report.{clave} no está traducida"
        assert en in ingles, f"falta la versión inglesa de report.{clave}"
        assert es in espanol, f"falta la versión española de report.{clave}"
        assert es not in ingles, f"el informe inglés arrastra el español de report.{clave}"

    # The counted phrases agree with their number in both languages, and never
    # print the "(s)" of a template that could not see the count.
    assert text("en", "report.personas_riesgo", n=1) in ingles
    assert "1 account at risk" in ingles          # singular noun, not "1 accounts"
    assert "closes 3 findings (1 critical, 2 high)" in ingles
    assert "(s)" not in ingles


def test_csv_rows_shape():
    rows = findings_csv_rows(SCAN)
    assert rows[0][0] == "id" and "afectados" in rows[0]
    assert len(rows) == 3  # header + 2 findings
    assert rows[1][0] == "2sv-delegated-admins"
    header = rows[0]
    assert rows[1][header.index("num_afectados")] == "2"
    assert rows[1][header.index("afectados")] == "a@example.com | b@example.com"
    assert "regresion" in header


def test_due_cutoffs_are_earlier_for_daily_than_weekly():
    now = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
    cutoffs = due_cutoffs(now)
    assert set(cutoffs) == {"daily", "weekly"}
    assert cutoffs["weekly"] < cutoffs["daily"] < now.isoformat()
    # A scan from 25h ago is due for daily...
    day_old = (now - timedelta(hours=25)).isoformat()
    assert day_old <= cutoffs["daily"]
    # ...but not for weekly.
    assert not day_old <= cutoffs["weekly"]
