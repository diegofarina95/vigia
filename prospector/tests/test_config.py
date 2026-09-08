"""Startup refusals.

Sender identification and an unsubscribe link are not features with sensible
defaults: an email without them is unlawful under LSSI art. 10 and the GDPR's
transparency duty. So the failure mode has to be "refuses to start", not "starts
and sends something defective".
"""
from __future__ import annotations

import pytest

from prospector.config import ConfigError, SenderIdentity, Settings, load_settings

VARIABLES = {
    "PROSPECTOR_BIND_HOST": "100.71.97.110",
    "PROSPECTOR_SENDER_NAME": "Diego Fariña",
    "PROSPECTOR_SENDER_NIF": "00000000X",
    "PROSPECTOR_SENDER_ADDRESS": "Calle Ejemplo 1, 15001 A Coruña",
    "PROSPECTOR_SENDER_EMAIL": "diego@diegofarina.com",
    "PROSPECTOR_UNSUBSCRIBE_BASE_URL": "https://example.invalid/baja",
}


@pytest.fixture()
def entorno(monkeypatch):
    for clave, valor in VARIABLES.items():
        monkeypatch.setenv(clave, valor)
    return monkeypatch


def test_una_configuracion_completa_arranca(entorno):
    load_settings().validate()


@pytest.mark.parametrize(
    "campo", ["PROSPECTOR_SENDER_NAME", "PROSPECTOR_SENDER_NIF",
              "PROSPECTOR_SENDER_ADDRESS", "PROSPECTOR_SENDER_EMAIL"],
)
def test_sin_identificacion_del_remitente_no_arranca(entorno, campo):
    entorno.setenv(campo, "")
    with pytest.raises(ConfigError, match="identificación del remitente"):
        load_settings().validate()


def test_el_error_dice_que_campos_faltan(entorno):
    entorno.setenv("PROSPECTOR_SENDER_NIF", "")
    entorno.setenv("PROSPECTOR_SENDER_ADDRESS", "")
    with pytest.raises(ConfigError) as exc:
        load_settings().validate()
    assert "company_number" in str(exc.value)
    assert "postal_address" in str(exc.value)


def test_un_campo_en_blanco_cuenta_como_ausente(entorno):
    """A space is not an address."""
    entorno.setenv("PROSPECTOR_SENDER_ADDRESS", "   ")
    with pytest.raises(ConfigError):
        load_settings().validate()


def test_sin_url_de_baja_no_arranca(entorno):
    entorno.setenv("PROSPECTOR_UNSUBSCRIBE_BASE_URL", "")
    with pytest.raises(ConfigError, match="baja"):
        load_settings().validate()


@pytest.mark.parametrize("host", ["0.0.0.0", "::", ""])
def test_no_se_permite_escuchar_en_todas_las_interfaces(entorno, host):
    """This console can email strangers. It is served over Tailscale and nothing
    else, so binding it to every interface is a configuration error, not a choice."""
    entorno.setenv("PROSPECTOR_BIND_HOST", host)
    with pytest.raises(ConfigError, match="Tailscale"):
        load_settings().validate()


def test_el_seguimiento_de_apertura_esta_apagado_por_defecto(entorno):
    """Opt-in, and it stays opt-in."""
    assert load_settings().open_tracking is False


def test_el_seguimiento_de_apertura_solo_se_enciende_a_proposito(entorno):
    entorno.setenv("PROSPECTOR_OPEN_TRACKING", "1")
    assert load_settings().open_tracking is True


def test_un_retardo_minimo_mayor_que_el_maximo_no_arranca(entorno):
    entorno.setenv("PROSPECTOR_MIN_DELAY", "300")
    entorno.setenv("PROSPECTOR_MAX_DELAY", "120")
    with pytest.raises(ConfigError, match="retardo"):
        load_settings().validate()


def test_los_valores_por_defecto_de_envio_son_conservadores(entorno):
    """A cold domain sending 200 messages on day one is a blocked domain."""
    ajustes = load_settings()
    assert ajustes.daily_cap == 40
    assert ajustes.warmup_enabled is True
    assert ajustes.warmup_start == 5
    assert ajustes.min_delay_seconds >= 90


def test_reply_to_cae_al_remitente_cuando_no_se_define(entorno):
    assert load_settings().sender.reply_to == VARIABLES["PROSPECTOR_SENDER_EMAIL"]


def test_missing_enumera_exactamente_lo_que_falta():
    vacio = SenderIdentity(name="", company_number="", postal_address="",
                           email="", reply_to="")
    assert set(vacio.missing()) == set(SenderIdentity.REQUIRED)
    completo = SenderIdentity(name="n", company_number="c", postal_address="p",
                              email="e@x.com", reply_to="e@x.com")
    assert completo.missing() == []


def test_los_ajustes_son_inmutables(entorno):
    """Configuration read once at startup cannot drift under a running queue."""
    ajustes = load_settings()
    with pytest.raises(Exception):
        ajustes.daily_cap = 500  # type: ignore[misc]
    assert isinstance(ajustes, Settings)


# --------------------------------------------------------------------------- #
# Placeholder detection: start the console, refuse to send.
# --------------------------------------------------------------------------- #


def _ident(**kwargs) -> SenderIdentity:
    base = dict(name="Diego Fariña", company_number="12345678Z",
                postal_address="Rúa Real 1, 15003 A Coruña",
                email="d@x.com", reply_to="d@x.com")
    return SenderIdentity(**{**base, **kwargs})


@pytest.mark.parametrize(
    "valor", ["NIF-PENDIENTE", "pendiente", "TODO", "rellenar", "xxx", "TBD"],
)
def test_un_valor_de_relleno_se_detecta(valor):
    assert _ident(company_number=valor).placeholders() == ["company_number"]
    assert _ident(company_number=valor).ready_to_send is False


@pytest.mark.parametrize(
    "direccion",
    [
        "Calle Ejemplo 1, 15001 A Coruña",   # una calle puede llamarse así
        "Rúa do Testón 4",                    # 'test' dentro de una palabra
        "Plaza de los Protestantes 2",
        "Avenida Todohogar 15",               # 'todo' dentro de una palabra
    ],
)
def test_una_direccion_real_no_se_confunde_con_relleno(direccion):
    """A false positive here silently refuses to send with correct details, which
    is worse than the failure being prevented."""
    assert _ident(postal_address=direccion).placeholders() == []
    assert _ident(postal_address=direccion).ready_to_send is True


def test_con_relleno_la_configuracion_sigue_siendo_valida(entorno):
    """The console starts. Only sending is refused, and `sender.py` is what
    refuses it — so exploring the tool never depends on having a NIF."""
    entorno.setenv("PROSPECTOR_SENDER_NIF", "NIF-PENDIENTE")
    ajustes = load_settings()
    ajustes.validate()
    assert ajustes.sender.placeholders() == ["company_number"]
    assert ajustes.sender.ready_to_send is False
