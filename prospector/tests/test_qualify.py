"""Commercial qualification.

The tests are weighted the way the module is: most of them assert that a prospect
is REFUSED. The pool is unlimited and the reputation is not, so the expensive
mistake is qualifying somebody weak, not skipping somebody strong.
"""
from __future__ import annotations

import pytest

from prospector.qualify import (
    DEFAULT_THRESHOLD,
    HIGH_VALUE_SECTORS,
    CommercialScore,
    score_prospect,
)
from prospector.scanner import build_report
from prospector.signals import SiteSignals, is_public_administration


def sitio(**kwargs) -> SiteSignals:
    """A live site with nothing remarkable on it."""
    base = {"domain": "empresa.es", "resolves": True, "html": "<html><body>hola</body></html>",
            "status_code": 200}
    return SiteSignals(**{**base, **kwargs})


def puntos(score: CommercialScore, nombre: str) -> int:
    return sum(s.points for s in score.signals if s.name == nombre)


# --------------------------------------------------------------------------- #
# Each signal on its own, at the weight the brief specifies.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "html",
    ["...cdn.shopify.com/s/files...", "<link href='/wp-content/plugins/woocommerce/x.css'>",
     "<meta name='generator' content='prestashop'>"],
)
def test_una_tienda_suma_tres(html):
    score = score_prospect(build_report(), sitio(html=html))
    assert puntos(score, "ecommerce") == 3


def test_una_ruta_de_compra_suma_tres():
    score = score_prospect(build_report(), sitio(paths_found=("/carrito",)))
    assert puntos(score, "ecommerce") == 3


def test_una_pasarela_de_pago_en_dns_suma_tres():
    score = score_prospect(build_report(), sitio(txt_records=("stripe-verification=abc",)))
    assert puntos(score, "ecommerce") == 3


@pytest.mark.parametrize("sector", ["legal", "asesoria", "clinica", "logistica", "b2b"])
def test_un_sector_de_valor_suma_tres(sector):
    score = score_prospect(build_report(), sitio(), sector=sector)
    assert puntos(score, "sector") == 3


def test_el_sector_se_reconoce_dentro_de_un_texto_libre():
    """Sectors arrive from a CSV somebody else wrote."""
    score = score_prospect(build_report(), sitio(), sector="Servicios juridicos / legal")
    assert puntos(score, "sector") == 3


def test_un_sector_cualquiera_no_suma():
    assert puntos(score_prospect(build_report(), sitio(), sector="hosteleria"), "sector") == 0
    assert puntos(score_prospect(build_report(), sitio(), sector=None), "sector") == 0


@pytest.mark.parametrize(
    "include",
    ["servers.mcsv.net", "sendgrid.net", "spf.brevo.com", "_spf.klaviyo.com"],
)
def test_una_plataforma_de_marketing_en_el_spf_suma_dos(include):
    report = build_report(spf={"record": f"v=spf1 include:{include} -all"})
    assert puntos(score_prospect(report, sitio()), "marketing-platform") == 2


def test_un_spf_normal_no_suma_plataforma():
    report = build_report(spf={"record": "v=spf1 include:_spf.google.com -all"})
    assert puntos(score_prospect(report, sitio()), "marketing-platform") == 0


def test_un_formulario_de_contacto_suma_dos():
    score = score_prospect(build_report(), sitio(html="<form><input type='email'></form>"))
    assert puntos(score, "contact-form") == 2


def test_varios_mx_suman_uno():
    report = build_report(mx=["alt1.aspmx.l.google.com", "aspmx.l.google.com"])
    assert puntos(score_prospect(report, sitio()), "mature-mail") == 1


def test_un_solo_mx_no_suma():
    assert puntos(score_prospect(build_report(mx=["mail.empresa.es"]), sitio()),
                  "mature-mail") == 0


# --------------------------------------------------------------------------- #
# The penalties.
# --------------------------------------------------------------------------- #


def test_un_sitio_que_no_responde_resta_tres():
    score = score_prospect(build_report(), SiteSignals(domain="x.es", resolves=False))
    assert puntos(score, "no-website") == -3


@pytest.mark.parametrize(
    "dominio",
    ["madrid.gob.es", "hacienda.gob.es", "somewhere.gov.uk", "ayuntamientodevigo.es",
     "concellodearteixo.gal", "diputacionalicante.es", "xxx.nhs.uk"],
)
def test_una_administracion_publica_resta_cinco(dominio):
    score = score_prospect(build_report(dominio), sitio(domain=dominio), domain=dominio)
    assert puntos(score, "public-admin") == -5


@pytest.mark.parametrize("dominio", ["lajuntadeaccionistas.com", "govia.co.uk", "milanuncios.es"])
def test_una_empresa_con_un_nombre_parecido_no_se_confunde(dominio):
    """`junta`, `gov` and `mil` inside an ordinary word are not a public body."""
    assert not is_public_administration(dominio)


def test_un_dominio_aparcado_resta_cinco_por_su_nameserver():
    score = score_prospect(build_report(), sitio(nameservers=("ns1.sedoparking.com",)))
    assert puntos(score, "parked") == -5


def test_un_dominio_en_venta_resta_cinco_por_su_pagina():
    score = score_prospect(build_report(), sitio(html="<h1>este dominio está en venta</h1>"))
    assert puntos(score, "parked") == -5


def test_una_pagina_vacia_sin_mx_cuenta_como_aparcada():
    score = score_prospect(build_report(mx=[]), sitio(html="<html></html>"))
    assert puntos(score, "parked") == -5


# --------------------------------------------------------------------------- #
# The rule that protects a whole batch: an unmeasured signal scores zero.
# --------------------------------------------------------------------------- #


def test_un_fallo_de_red_no_penaliza_al_dominio():
    """`resolves=False` with an error means the check failed, not that the site is
    dead. Scoring -3 there would bury a domain permanently because of one bad
    afternoon on the network."""
    caido = SiteSignals(domain="x.es", resolves=False, error="timeout")
    score = score_prospect(build_report(), caido)
    assert puntos(score, "no-website") == 0
    assert score.unmeasured is True


def test_un_prospecto_sin_observar_se_marca_como_no_medido():
    score = score_prospect(build_report("x.es"))
    assert score.unmeasured is True
    assert puntos(score, "no-website") == 0


def test_no_medido_no_es_lo_mismo_que_no_interesante():
    """The queue has to tell them apart: one is a judgement, the other is a gap."""
    sin_medir = score_prospect(build_report("x.es"))
    medido_flojo = score_prospect(build_report("x.es"), sitio())
    assert sin_medir.unmeasured and not medido_flojo.unmeasured
    assert not sin_medir.qualified and not medido_flojo.qualified


# --------------------------------------------------------------------------- #
# The threshold — the actual product decision.
# --------------------------------------------------------------------------- #


def test_una_tienda_de_un_sector_de_valor_se_califica():
    report = build_report(
        mx=["alt1.aspmx.l.google.com", "aspmx.l.google.com"],
        spf={"record": "v=spf1 include:sendgrid.net -all"},
    )
    score = score_prospect(
        report,
        sitio(html="<form><input type='email'></form> cdn.shopify.com"),
        sector="legal",
    )
    assert score.total == 11  # 3 + 3 + 2 + 2 + 1, el máximo
    assert score.qualified is True


def test_una_empresa_cualquiera_con_web_no_llega():
    """A site with a form and a mailbox is not a reason to spend a send."""
    report = build_report(mx=["alt1.aspmx.l.google.com", "aspmx.l.google.com"])
    score = score_prospect(report, sitio(html="<form><input type='email'></form>"))
    assert score.total == 3
    assert score.qualified is False


def test_el_umbral_es_configurable():
    report = build_report(mx=["a.mx", "b.mx"])
    score = score_prospect(report, sitio(html="<form>"), threshold=2)
    assert score.total == 3 and score.qualified is True
    assert score_prospect(report, sitio(html="<form>"), threshold=9).qualified is False


def test_el_umbral_por_defecto_exige_algo_mas_que_existir():
    """5 means a high-value sector or a shop, plus corroboration."""
    assert DEFAULT_THRESHOLD == 5
    solo_sector = score_prospect(build_report(), sitio(), sector="legal")
    assert solo_sector.total == 3 and solo_sector.qualified is False


def test_una_penalizacion_puede_tumbar_a_un_buen_candidato():
    report = build_report(spf={"record": "v=spf1 include:sendgrid.net -all"})
    score = score_prospect(
        report, sitio(nameservers=("ns1.bodis.com",)), sector="legal"
    )
    assert score.total == 0  # 3 + 2 - 5
    assert score.qualified is False


def test_el_desglose_dice_que_regla_disparo_y_con_que_prueba():
    """The threshold gets tuned, and tuning a number blind is guesswork."""
    score = score_prospect(
        build_report(), sitio(html="cdn.shopify.com"), sector="legal"
    )
    nombres = {s.name for s in score.signals}
    assert {"ecommerce", "sector"} <= nombres
    assert all(s.evidence for s in score.signals)
    d = score.as_dict()
    assert d["total"] == score.total and len(d["signals"]) == len(score.signals)


def test_los_sectores_de_valor_no_estan_vacios():
    assert len(HIGH_VALUE_SECTORS) > 20


# --------------------------------------------------------------------------- #
# Known limit of the current weights, asserted so it cannot change silently.
# --------------------------------------------------------------------------- #


def test_una_administracion_normal_queda_fuera():
    """The ordinary case: a public body with a website, a form and real mail.

    3 (sector) + 2 (marketing platform) + 2 (form) + 1 (MX) - 5 = 3. Below the
    threshold, which is the intended outcome.
    """
    dominio = "ayuntamientodevigo.es"
    report = build_report(dominio, mx=["a.mx", "b.mx"],
                          spf={"record": "v=spf1 include:sendgrid.net -all"})
    score = score_prospect(
        report, sitio(domain=dominio, html="<form><input type='email'></form>"),
        sector="legal", domain=dominio,
    )
    assert score.total == 3 and score.qualified is False


def test_una_administracion_con_tienda_si_supera_el_umbral():
    """Documented, not endorsed. The one gap the specified weights leave.

    -5 does not outweigh a *full house* of positives: a public body that also runs
    a shop (municipal ticketing, a museum store) reaches 6 and qualifies. It needs
    every other signal to fire, so it is a narrow case rather than a general leak —
    but it is a real one, and cold-emailing a town hall is a bad look regardless of
    the arithmetic.

    The brief specified the weights, so the weights are what is implemented. This
    test exists so the consequence is visible, and so that changing it has to
    change a test rather than quietly change who gets contacted.
    """
    dominio = "ayuntamientodevigo.es"
    report = build_report(dominio, mx=["a.mx", "b.mx"],
                          spf={"record": "v=spf1 include:sendgrid.net -all"})
    score = score_prospect(
        report,
        sitio(domain=dominio, html="<form><input type='email'></form>",
              paths_found=("/checkout",)),
        sector="legal", domain=dominio,
    )
    assert puntos(score, "public-admin") == -5
    assert score.total == 6 >= DEFAULT_THRESHOLD
    assert score.qualified is True
