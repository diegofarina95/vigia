"""The address classifier.

The asymmetry is the whole design: letting a personal address through is a data
protection complaint, refusing a role address costs one prospect. So the tests
that matter most are the ones asserting that something is REFUSED.
"""
from __future__ import annotations

import pytest

from prospector.addresses import classify_address, is_contactable

# --------------------------------------------------------------------------- #
# Role addresses — the only ones that may be contacted.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "email",
    [
        "info@empresa.com",
        "contacto@empresa.es",
        "hello@company.co.uk",
        "hola@empresa.es",
        "admin@empresa.com",
        "sales@company.com",
        "ventas@empresa.es",
        "soporte@empresa.es",
        "support@company.com",
        "facturacion@empresa.es",
        "rrhh@empresa.es",
        "comercial@empresa.es",
        "reservas@hotel.es",
        "INFO@EMPRESA.COM",          # case is not identity
        "  info@empresa.com  ",      # nor is whitespace
    ],
)
def test_las_direcciones_de_funcion_se_aceptan(email):
    verdict = classify_address(email)
    assert verdict.address_type == "role", verdict.reason
    assert verdict.is_valid is True
    assert is_contactable(email)


def test_una_direccion_de_funcion_con_sufijo_sigue_siendo_de_funcion():
    for email in ("ventas.madrid@empresa.es", "info2@empresa.com", "contacto-es@empresa.es"):
        verdict = classify_address(email)
        assert verdict.address_type == "role", f"{email}: {verdict.reason}"
        assert verdict.is_valid is True


def test_el_subdireccionamiento_no_cambia_la_identidad():
    """`info+web@` is `info@` with a routing tag."""
    verdict = classify_address("info+web@empresa.com")
    assert verdict.address_type == "role" and verdict.is_valid is True
    assert verdict.local == "info"


# --------------------------------------------------------------------------- #
# Personal addresses — refused, and refused as `personal` so that no interface
# can offer a human the option of overriding.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "email, forma",
    [
        ("maria.gonzalez@empresa.es", "nombre.apellido"),
        ("diego.farina@empresa.com", "nombre.apellido"),
        ("maria.gonzalez.lopez@empresa.es", "nombre.apellido1.apellido2"),
        ("gonzalez.maria@empresa.es", "apellido.nombre"),
        ("maria_gonzalez@empresa.es", "nombre_apellido"),
        ("maria-gonzalez@empresa.es", "nombre-apellido"),
        ("maria.de.la.fuente@empresa.es", "nombre con partícula"),
        ("john.smith@company.co.uk", "firstname.lastname"),
        ("j.smith@company.co.uk", "inicial.apellido"),
    ],
)
def test_los_patrones_de_nombre_se_rechazan(email, forma):
    verdict = classify_address(email)
    assert verdict.address_type == "personal", f"{forma}: {verdict.reason}"
    assert verdict.is_valid is False
    assert not is_contactable(email)


@pytest.mark.parametrize(
    "email",
    ["mgonzalez@empresa.es", "dfarina@empresa.com", "jsmith@company.co.uk"],
)
def test_inicial_pegada_al_apellido_se_rechaza(email):
    verdict = classify_address(email)
    assert verdict.address_type == "personal"
    assert verdict.reason == "personal-initial-surname"


@pytest.mark.parametrize(
    "email",
    ["maria@empresa.es", "diego@empresa.com", "javier@empresa.es", "sarah@company.co.uk"],
)
def test_un_nombre_de_pila_a_secas_se_rechaza(email):
    verdict = classify_address(email)
    assert verdict.address_type == "personal"
    assert verdict.reason == "personal-given-name"
    assert not is_contactable(email)


def test_ninguna_direccion_personal_es_contactable():
    """The property, stated once over the whole set."""
    personales = [
        "maria.gonzalez@x.es", "mgonzalez@x.es", "maria@x.es",
        "j.smith@x.co.uk", "maria.de.la.fuente@x.es",
    ]
    assert not any(is_contactable(e) for e in personales)


# --------------------------------------------------------------------------- #
# Role addresses that exist for machines. Real function addresses, still wrong
# to contact: RFC 2142 reserves `abuse@` for reporting mail problems, and a
# marketing message to it is the thing it exists to report.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "email",
    [
        "postmaster@empresa.com",
        "abuse@empresa.com",
        "noreply@empresa.com",
        "no-reply@empresa.com",
        "webmaster@empresa.com",
        "mailer-daemon@empresa.com",
        "baja@empresa.com",
    ],
)
def test_las_direcciones_de_maquina_se_rechazan_aunque_sean_de_funcion(email):
    verdict = classify_address(email)
    assert verdict.address_type == "role"
    assert verdict.is_valid is False
    assert verdict.reason == "role-do-not-contact"


# --------------------------------------------------------------------------- #
# Unknown — refused too, but distinguishable, because Phase 3 may put one of
# these in front of a human and must never do that with a personal address.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("email", ["zxqv@empresa.com", "b2b@empresa.com", "aa@x.es"])
def test_lo_no_reconocido_se_bloquea_pero_no_se_llama_personal(email):
    verdict = classify_address(email)
    assert verdict.address_type == "unknown"
    assert verdict.is_valid is False


def test_lo_desconocido_y_lo_personal_no_se_confunden():
    """The one distinction the review UI is allowed to act on."""
    assert classify_address("zxqv@x.com").address_type == "unknown"
    assert classify_address("maria.gonzalez@x.com").address_type == "personal"


# --------------------------------------------------------------------------- #
# Malformed input. Never raises, always refuses.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "email",
    ["", "   ", "sin-arroba", "dos@@arrobas.com", "info@", "@empresa.com",
     "info@sinpunto", "info..doble@empresa.com", ".info@empresa.com",
     "info@empresa.com extra", "info@empresa,com"],
)
def test_una_direccion_mal_formada_se_rechaza_sin_reventar(email):
    verdict = classify_address(email)
    assert verdict.is_valid is False
    assert not is_contactable(email)


def test_none_no_revienta():
    assert classify_address(None) .is_valid is False  # type: ignore[arg-type]


def test_el_veredicto_siempre_explica_por_que():
    """The blocked view shows the reason, so every path must set one."""
    for email in ("info@x.com", "maria.gonzalez@x.com", "abuse@x.com", "zxqv@x.com", ""):
        assert classify_address(email).reason
