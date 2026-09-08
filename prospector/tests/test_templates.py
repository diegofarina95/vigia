"""The template engine. Mostly tests that it refuses to render."""
from __future__ import annotations

import pytest

from prospector import db
from prospector.prioritise import select_primary_finding
from prospector.scanner import build_report
from prospector.templates import (
    BODIES,
    PLACEHOLDERS,
    RenderError,
    build_email,
    lang_for_country,
    pick_template,
    render,
    seed_templates,
    validate_template,
    variant_for,
)

SIN_DMARC = {"found": False, "status": "fail", "summary": "No DMARC record."}
REMITE = {
    "sender_name": "Diego Fariña",
    "sender_details": "Diego Fariña · NIF 00000000X · Calle Ejemplo 1, 15001 A Coruña",
    "unsubscribe_url": "https://example.invalid/baja/abc123",
}


@pytest.fixture()
def conn(tmp_path):
    conexion = db.init(tmp_path / "p.db")
    seed_templates(conexion)
    yield conexion
    conexion.close()


def prospecto(conn, dominio="empresa.es", **kwargs):
    pid = db.add_prospect(conn, domain=dominio, **kwargs)
    return conn.execute("SELECT * FROM prospects WHERE id = ?", (pid,)).fetchone()


def hallazgo(dominio="empresa.es", lang="es"):
    return select_primary_finding(build_report(dominio, dmarc=SIN_DMARC), lang=lang)


# --------------------------------------------------------------------------- #
# Strict rendering. This is the whole point of the module.
# --------------------------------------------------------------------------- #


def test_un_marcador_sin_valor_no_renderiza():
    with pytest.raises(RenderError, match="sin rellenar"):
        render("Hola {company_name}", {})


def test_un_valor_vacio_cuenta_como_ausente():
    """`""` is exactly the case that produces "Hola ," in a stranger's inbox."""
    with pytest.raises(RenderError, match="sin rellenar"):
        render("Hola {company_name}", {"company_name": ""})
    with pytest.raises(RenderError, match="sin rellenar"):
        render("Hola {company_name}", {"company_name": "   "})


def test_no_devuelve_nunca_un_texto_a_medias():
    """Not a fallback, not an empty string: an exception."""
    with pytest.raises(RenderError):
        render("{domain} y {company_name}", {"domain": "x.es"})


def test_un_render_completo_no_deja_llaves():
    salida = render("{domain} — {sender_name}", {"domain": "x.es", "sender_name": "D"})
    assert salida == "x.es — D"
    assert "{" not in salida


def test_un_valor_que_contiene_un_marcador_no_se_re_sustituye():
    """A company literally called "{domain}" must not blow a hole in the letter."""
    with pytest.raises(RenderError, match="sin sustituir"):
        render("Hola {company_name}", {"company_name": "{domain}"})


# --------------------------------------------------------------------------- #
# Templates are validated when stored, not when sent.
# --------------------------------------------------------------------------- #


def test_una_plantilla_con_un_marcador_inventado_se_rechaza():
    with pytest.raises(RenderError, match="no existen"):
        validate_template("x", "{sender_details}{unsubscribe_url}{telefono_movil}")


def test_una_plantilla_sin_enlace_de_baja_se_rechaza():
    with pytest.raises(RenderError, match="unsubscribe_url"):
        validate_template("x", "Hola {domain} {sender_details}")


def test_una_plantilla_sin_identificacion_del_remitente_se_rechaza():
    with pytest.raises(RenderError, match="LSSI"):
        validate_template("x", "Hola {domain} {unsubscribe_url}")


def test_todas_las_plantillas_por_defecto_son_validas():
    for (lang, variant), cuerpo in BODIES.items():
        validate_template("x", cuerpo), f"{lang}/{variant}"


def test_las_plantillas_por_defecto_solo_usan_marcadores_conocidos():
    from prospector.templates import placeholders_in

    for cuerpo in BODIES.values():
        assert placeholders_in(cuerpo) <= PLACEHOLDERS


# --------------------------------------------------------------------------- #
# Seeding, versions and A/B.
# --------------------------------------------------------------------------- #


def test_se_siembran_dos_variantes_por_hallazgo_y_por_idioma(conn):
    from prospector.catalog import RULES

    total = conn.execute("SELECT COUNT(*) FROM templates").fetchone()[0]
    assert total == len(RULES) * 2 * 2


def test_sembrar_dos_veces_no_duplica(conn):
    antes = conn.execute("SELECT COUNT(*) FROM templates").fetchone()[0]
    seed_templates(conn)
    assert conn.execute("SELECT COUNT(*) FROM templates").fetchone()[0] == antes


def test_sembrar_no_pisa_una_plantilla_editada(conn):
    """An edited letter survives a restart. Overwriting it would be its own kind of
    silent send: the operator approves wording that is then replaced."""
    with db.transaction(conn):
        conn.execute(
            "UPDATE templates SET body = body || '\nPD: editado a mano' "
            "WHERE finding_code = 'dmarc-missing' AND lang = 'es' AND variant = 'A'"
        )
    seed_templates(conn)
    fila = pick_template(conn, "dmarc-missing", "es", "A")
    assert "editado a mano" in fila["body"]


def test_la_variante_es_estable_para_un_dominio():
    """The preview a person approves has to be the letter that gets sent."""
    assert variant_for("empresa.es") == variant_for("empresa.es")
    assert variant_for("EMPRESA.ES") == variant_for("empresa.es")


def test_las_variantes_se_reparten():
    dominios = [f"empresa{i}.es" for i in range(400)]
    reparto = [variant_for(d) for d in dominios]
    a = reparto.count("A")
    assert 150 < a < 250, f"reparto sesgado: {a}/400 en A"


def test_se_elige_la_version_mas_alta(conn):
    with db.transaction(conn):
        conn.execute(
            "INSERT INTO templates (finding_code, lang, variant, version, subject, body, "
            "created_at) VALUES ('dmarc-missing','es','A',2,'{finding_subject}',"
            "'v2 {sender_details} {unsubscribe_url}', ?)", (db.now(),)
        )
    assert pick_template(conn, "dmarc-missing", "es", "A")["version"] == 2


def test_una_plantilla_desactivada_no_se_elige(conn):
    with db.transaction(conn):
        conn.execute("UPDATE templates SET is_active = 0 WHERE lang='es' AND variant='A'")
    assert pick_template(conn, "dmarc-missing", "es", "A") is None


# --------------------------------------------------------------------------- #
# Language by country.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("pais", ["GB", "UK", "IE", "us"])
def test_los_paises_anglofonos_reciben_ingles(pais):
    assert lang_for_country(pais) == "en"


@pytest.mark.parametrize("pais", ["ES", "PT", "FR", "", None])
def test_el_resto_recibe_castellano(pais):
    assert lang_for_country(pais) == "es"


# --------------------------------------------------------------------------- #
# The whole letter.
# --------------------------------------------------------------------------- #


def test_una_carta_completa_no_lleva_marcadores(conn):
    p = prospecto(conn, "empresa.es", company_name="Empresa SL", country="ES")
    correo = build_email(conn, finding=hallazgo("empresa.es"), prospect=p, **REMITE)
    assert "{" not in correo.body and "{" not in correo.subject
    assert "empresa.es" in correo.subject
    assert correo.lang == "es"


def test_la_carta_lleva_siempre_identificacion_y_baja(conn):
    """The two things that make it lawful, asserted on the rendered output rather
    than on the template — a renderer that dropped them would pass a template test."""
    p = prospecto(conn, "empresa.es", country="ES")
    correo = build_email(conn, finding=hallazgo("empresa.es"), prospect=p, **REMITE)
    assert REMITE["sender_details"] in correo.body
    assert REMITE["unsubscribe_url"] in correo.body
    assert REMITE["sender_name"] in correo.body


def test_el_asunto_es_el_del_hallazgo_sin_duplicarlo(conn):
    """The hook is a property of the finding, not of the letter: one place to change."""
    p = prospecto(conn, "empresa.es", country="ES")
    f = hallazgo("empresa.es")
    correo = build_email(conn, finding=f, prospect=p, **REMITE)
    assert correo.subject == f.subject_line


def test_un_prospecto_britanico_recibe_la_carta_inglesa(conn):
    p = prospecto(conn, "company.co.uk", country="GB")
    f = select_primary_finding(build_report("company.co.uk", dmarc=SIN_DMARC), lang="en")
    correo = build_email(conn, finding=f, prospect=p, **REMITE)
    assert correo.lang == "en"
    assert "Best regards" in correo.body
    assert "Un saludo" not in correo.body


def test_sin_plantilla_para_ese_hallazgo_no_se_renderiza(conn):
    with db.transaction(conn):
        conn.execute("DELETE FROM templates WHERE finding_code = 'dmarc-missing'")
    p = prospecto(conn, "empresa.es", country="ES")
    with pytest.raises(RenderError, match="no hay plantilla"):
        build_email(conn, finding=hallazgo("empresa.es"), prospect=p, **REMITE)


def test_sin_enlace_de_baja_no_se_renderiza(conn):
    """Belt and braces: even if a caller forgets, nothing renders."""
    p = prospecto(conn, "empresa.es", country="ES")
    with pytest.raises(RenderError, match="sin rellenar"):
        build_email(conn, finding=hallazgo("empresa.es"), prospect=p,
                    **{**REMITE, "unsubscribe_url": ""})


def test_sin_identificacion_del_remitente_no_se_renderiza(conn):
    p = prospecto(conn, "empresa.es", country="ES")
    with pytest.raises(RenderError, match="sin rellenar"):
        build_email(conn, finding=hallazgo("empresa.es"), prospect=p,
                    **{**REMITE, "sender_details": ""})


def test_la_carta_no_afirma_haber_accedido_a_nada(conn):
    """The claim that matters legally and commercially: this is public DNS."""
    p = prospecto(conn, "empresa.es", country="ES")
    correo = build_email(conn, finding=hallazgo("empresa.es"), prospect=p, **REMITE)
    assert "no he accedido" in correo.body.lower()


def test_las_dos_variantes_se_pueden_renderizar(conn):
    p = prospecto(conn, "empresa.es", company_name="Empresa SL", country="ES")
    for variante in ("A", "B"):
        correo = build_email(conn, finding=hallazgo("empresa.es"), prospect=p,
                             variant=variante, **REMITE)
        assert correo.variant == variante
        assert "{" not in correo.body


def test_las_dos_variantes_son_cartas_distintas(conn):
    """Comparing two paraphrases of the same structure would measure nothing."""
    p = prospecto(conn, "empresa.es", country="ES")
    a = build_email(conn, finding=hallazgo(), prospect=p, variant="A", **REMITE)
    b = build_email(conn, finding=hallazgo(), prospect=p, variant="B", **REMITE)
    assert a.body != b.body
    assert a.body.splitlines()[2] != b.body.splitlines()[2]


def test_todos_los_hallazgos_tienen_carta_en_los_dos_idiomas(conn):
    """A finding with no letter is a prospect who is silently never contacted."""
    from prospector.catalog import RULES

    for rule in RULES:
        for lang in ("es", "en"):
            for variant in ("A", "B"):
                assert pick_template(conn, rule.code, lang, variant) is not None, (
                    f"{rule.code}/{lang}/{variant}"
                )
