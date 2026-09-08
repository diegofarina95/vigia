"""The first page has one job and a short window to do it in.

A stranger who opens an unsolicited twenty-page PDF gives it about a minute.
Everything here defends that minute: three numbers, three different problems in
language a non-technical reader can act on, three cheap fixes, and an honest
closing line.
"""
import pytest

from vigia import executive
from vigia.i18n import SUPPORTED_LANGS, catalog, text


def f(fid, severity, status="fail", accounts=(), **extra):
    return {
        "id": fid,
        "title": extra.pop("title", fid),
        "severity": severity,
        "status": status,
        "accounts": list(accounts),
        "manual": False,
        "details": extra.pop("details", {}),
        **extra,
    }


# ------------------------------------------------------- three DIFFERENT things

def test_the_three_lines_do_not_all_describe_the_same_people():
    """The composites overlap by construction: "super admin without 2SV",
    "…dormant without 2SV" and "…with bad recovery" can be the same three
    accounts. Spending all three lines on one group tells the reader a third
    of what the page could."""
    mismos = ["a@x.com", "b@x.com", "c@x.com"]
    findings = [
        f("composite-superadmin-no-2sv-no-recovery", "critical", accounts=mismos),
        f("composite-superadmin-dormant-no-2sv", "critical", accounts=mismos),
        f("composite-superadmin-no-2sv", "critical", accounts=mismos),
        f("policy-drive-sharing", "high", details={"exposed": 17}),
        f("email-spf", "high"),
    ]
    elegidos = [h["id"] for h in executive.headline_findings(findings)]
    assert len(elegidos) == 3
    assert elegidos[0] == "composite-superadmin-no-2sv-no-recovery"
    assert "policy-drive-sharing" in elegidos and "email-spf" in elegidos


def test_a_finding_about_new_people_is_kept_even_if_it_is_less_severe():
    findings = [
        f("composite-superadmin-no-2sv", "critical", accounts=["a@x.com"]),
        f("composite-superadmin-dormant", "high", accounts=["a@x.com"]),   # mismo
        f("2sv-users", "high", accounts=["z@x.com"]),                       # nuevo
    ]
    elegidos = [h["id"] for h in executive.headline_findings(findings)]
    assert "composite-superadmin-dormant" not in elegidos
    assert "2sv-users" in elegidos


def test_a_failure_outranks_a_warning_of_higher_severity():
    """A warning is by definition something that might be nothing. Ranking on
    raw severity put "somebody changed a setting, probably fine" (critical,
    warn) above "the internal mailing lists are readable from outside"
    (medium, fail), so a warning is discounted by half — the same 50% the
    score already applies."""
    findings = [
        f("audit-risky-changes", "critical", status="warn"),
        f("policy-groups-sharing", "medium"),
        f("email-spf", "high"),
    ]
    orden = [h["id"] for h in executive.headline_findings(findings)]
    assert orden[0] == "email-spf", orden          # high fail (6) gana
    assert orden[1] == "audit-risky-changes", orden  # critical warn (5)
    assert orden[2] == "policy-groups-sharing"      # medium fail (3)


def test_the_three_lines_cover_three_different_subjects():
    """Two lines about the super admins is one point made twice, and it pushes
    out the settings that are wide open."""
    findings = [
        f("recovery-super-admins", "critical", accounts=["a@x.com"]),
        f("composite-superadmin-no-2sv", "critical", accounts=["b@x.com"]),
        f("composite-superadmin-dormant", "high", accounts=["c@x.com"]),
        f("policy-groups-sharing", "medium"),
        f("email-spf", "high"),
    ]
    temas = [executive.TEMA.get(h["id"]) for h in executive.headline_findings(findings)]
    assert len(set(temas)) == 3, temas


def test_an_inventory_is_never_a_headline():
    """"You have eight super admins" is a fact about the company's shape, not
    the thing you phone someone about at nine in the morning."""
    findings = [
        f("super-admin-count", "high", status="warn", accounts=[f"a{i}@x.com" for i in range(8)]),
        f("policy-password", "medium", details={"exposed": 17}),
    ]
    assert [h["id"] for h in executive.headline_findings(findings)] == ["policy-password"]


def test_passing_and_manual_findings_never_appear():
    findings = [
        f("email-spf", "high", status="pass"),
        dict(f("policy-password", "medium"), manual=True),
        f("email-dmarc", "medium"),
    ]
    assert [h["id"] for h in executive.headline_findings(findings)] == ["email-dmarc"]


# --------------------------------------------------------------- the language

@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
@pytest.mark.parametrize("fid", sorted(executive.PLAIN))
def test_every_written_sentence_avoids_the_vocabulary_of_the_trade(fid, lang):
    """A sentence the reader has to decode is a sentence they skip.

    In both languages: the English cover is read by the same kind of person, and
    "the accounts have no 2SV enrolment" is as opaque in English as in Spanish.
    """
    frase = executive.plain_sentence(f(fid, "high", accounts=["a@x.com"]), lang)
    jerga = ("2SV", "OAuth", "OU", "unidad organizativa", "organizational unit",
             "SPF", "DMARC", "IMAP", "token", "scope", "API", "DKIM")
    encontrada = [t for t in jerga if t in frase]
    assert not encontrada, f"{lang}/{fid} usa jerga: {encontrada}"
    assert frase.endswith("."), f"{lang}/{fid}"
    assert "{" not in frase, f"{lang}/{fid}: plantilla sin interpolar"
    assert len(frase) < 300, f"{lang}/{fid} no cabe en una línea leída de un vistazo"


def test_every_written_sentence_exists_in_both_catalogues():
    """`PLAIN` is now a list of ids and the sentences live in the catalogue, so the
    two can drift. A missing entry would print `executive.plain.<id>` on the one
    page a stranger reads, which is why this is checked rather than trusted."""
    for lang in SUPPORTED_LANGS:
        escritas = catalog(lang)["executive"]["plain"]
        assert set(escritas) == set(executive.PLAIN), (
            f"{lang}: sobran {set(escritas) - set(executive.PLAIN)}, "
            f"faltan {set(executive.PLAIN) - set(escritas)}"
        )


def test_the_count_reaches_the_sentence():
    for lang, esperado in (("es", "8 personas"), ("en", "8 people")):
        frase = executive.plain_sentence(
            f("2sv-users", "high", accounts=[f"u{i}@x.com" for i in range(8)]), lang
        )
        assert esperado in frase


def test_an_organization_finding_counts_the_exposure_not_the_payroll():
    for lang in SUPPORTED_LANGS:
        frase = executive.plain_sentence(
            f("policy-drive-sharing", "high", details={"exposed": 17}), lang
        )
        assert "17" not in frase, f"{lang}: un ajuste no es 17 problemas"


def test_a_finding_with_no_written_sentence_still_reads_as_a_sentence():
    for lang in SUPPORTED_LANGS:
        frase = executive.plain_sentence(
            f("algo-nuevo", "high", accounts=["a@x.com"], title="Algo que nadie tradujo"),
            lang,
        )
        # Read from the catalogue: the fallback moved there, and the title is the
        # customer's own text, which is never translated.
        assert frase == text(lang, "executive.frase_generica", titulo="Algo que nadie tradujo", n=1)
        assert "Algo que nadie tradujo" in frase and "1" in frase


# ------------------------------------------------------------- the closing line

def test_the_closing_line_is_specific_when_there_are_criticals():
    findings = [f("composite-superadmin-no-2sv", "critical", accounts=["a@x.com"]),
                f("policy-drive-sharing", "high")]
    for lang, cuenta_atras in (("es", "1 de estos problemas"), ("en", "1 of these problems")):
        linea = executive.closing_line(findings, [{"account": "a@x.com"}], lang)
        # The count of criticals and the settings count both reach the sentence,
        # in the language asked for.
        assert cuenta_atras in linea
        assert linea == text(lang, "executive.cierre_criticos", criticos=1, ajustes=1)


def test_a_clean_tenant_is_told_it_is_clean_rather_than_frightened():
    """A scanner that manufactures urgency for a healthy customer is a scanner
    nobody believes the second time. Both languages, from the catalogue."""
    for lang, marca in (("es", "No hay nada urgente"), ("en", "nothing urgent")):
        linea = executive.closing_line([f("email-spf", "high", status="pass")], [], lang)
        assert linea == text(lang, "executive.cierre_limpio")
        assert marca in linea


def test_the_summary_holds_together():
    findings = [
        f("composite-superadmin-no-2sv-no-recovery", "critical", accounts=["a@x.com"]),
        f("policy-drive-sharing", "high", details={"exposed": 17}),
        f("email-spf", "high"),
    ]
    resumen = executive.summary(
        findings,
        [{"account": "a@x.com"}],
        33,
        [{"title": "Exige 2FA", "minutes": 15, "findings_closed": 8}],
    )
    assert resumen["score"] == 33
    assert resumen["people_at_risk"] == 1
    assert resumen["critical"] == 1
    assert len(resumen["headlines"]) == 3
    assert resumen["actions"][0]["minutes"] == 15
    assert resumen["closing"]


def test_the_page_never_shows_more_than_three_of_anything():
    findings = [f(f"x{i}", "critical", accounts=[f"u{i}@x.com"]) for i in range(10)]
    resumen = executive.summary(findings, [], 10, [{"title": f"a{i}"} for i in range(10)])
    assert len(resumen["headlines"]) == 3
    assert len(resumen["actions"]) == 3


def test_the_cover_never_argues_with_itself_about_the_critical_count():
    """"4 hallazgos críticos" over a closing line saying five, or the body
    saying five: the first number a customer reads has to survive turning the
    page."""
    from vigia.scoring import severity_counts

    findings = [
        f("composite-superadmin-no-2sv", "critical", accounts=["a@x.com"]),
        f("recovery-super-admins", "critical", accounts=["b@x.com"]),
        f("audit-risky-changes", "critical", status="warn"),
        f("email-spf", "high"),
    ]
    resumen = executive.summary(findings, [{"account": "a@x.com"}], 40, [])

    assert resumen["critical"] == severity_counts(findings)["critical"] == 3
    assert resumen["critical_label"] == "3 críticos, 2 en fallo y 1 en aviso"
    assert "3 de estos problemas" in resumen["closing"]

    # And the same figure survives the translation, split the same way.
    ingles = executive.summary(findings, [{"account": "a@x.com"}], 40, [], "en")
    assert ingles["critical"] == 3
    assert ingles["critical_label"] == "3 critical, 2 failing and 1 warning"
    assert "3 of these problems" in ingles["closing"]


def test_when_every_critical_is_a_failure_the_label_stays_short():
    findings = [f("composite-superadmin-no-2sv", "critical", accounts=["a@x.com"])]
    for lang in SUPPORTED_LANGS:
        etiqueta = executive.summary(findings, [], 40, [], lang)["critical_label"]
        assert etiqueta == (
            text(lang, "executive.criticos", n=1) + text(lang, "executive.criticos_en_fallo")
        )
        assert "1" in etiqueta and "{" not in etiqueta
