"""The private outreach console: who gets in, and what goes out.

The gate is the part worth being paranoid about. Vigía answers the public
internet and the tailnet from the same process, so a mistake here does not
degrade a feature — it publishes a tool that emails strangers.
"""
import os

import pytest

from vigia import outreach
from vigia.tailnet import classify

TAILNET_IP = "100.71.97.110"


# --------------------------------------------------------------- the gate

@pytest.mark.parametrize("address", ["100.71.97.110", "100.64.0.1", "100.127.255.254"])
def test_a_tailnet_address_is_allowed(address):
    allowed, _ = classify(address, has_funnel_header=False)
    assert allowed


def test_the_funnel_header_is_a_hard_no_even_from_a_tailnet_address():
    """Funnel tags what it proxies. If that tag is present the request came
    from the internet, whatever the peer address looks like."""
    allowed, reason = classify(TAILNET_IP, has_funnel_header=True)
    assert not allowed
    assert "Funnel" in reason


def test_loopback_is_denied_on_purpose():
    """The Funnel proxies from 127.0.0.1. Allowing loopback "for local
    testing" would hand the tool to the whole internet."""
    allowed, reason = classify("127.0.0.1", has_funnel_header=False)
    assert not allowed
    assert "locales" in reason


@pytest.mark.parametrize("address", ["10.10.1.64", "192.168.1.10", "172.16.0.5"])
def test_the_lan_is_not_the_tailnet(address):
    assert not classify(address, has_funnel_header=False)[0]


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.0"])
def test_public_addresses_and_the_edges_of_the_range_are_denied(address):
    assert not classify(address, has_funnel_header=False)[0]


@pytest.mark.parametrize("address", ["", "no-soy-una-ip", "100.71.97.110, 8.8.8.8"])
def test_garbage_is_denied_rather_than_guessed(address):
    assert not classify(address, has_funnel_header=False)[0]


def test_the_ipv6_tailnet_range_is_allowed():
    assert classify("fd7a:115c:a1e0::1", has_funnel_header=False)[0]


# ------------------------------------------------------- problem extraction

def report(domain="ejemplo.com", **statuses):
    base = {"domain": domain, "mx": {"records": [], "provider": "Zoho"}}
    for key in ("spf", "dkim", "dmarc", "mta_sts", "tls_rpt", "dnssec"):
        base[key] = {"status": statuses.get(key, "pass"), "summary": f"resumen de {key}", "issues": []}
    return base


def test_only_open_mechanisms_are_reported():
    found = outreach.problems(report(spf="fail", dkim="pass", dmarc="warn"))
    assert [p["key"] for p in found] == ["spf", "dmarc"]


def test_failures_come_before_warnings():
    found = outreach.problems(report(dnssec="warn", spf="fail"))
    assert [p["status"] for p in found] == ["fail", "warn"]


def test_a_clean_domain_produces_nothing_to_say():
    assert outreach.problems(report()) == []


def test_every_reported_mechanism_carries_a_concrete_fix():
    for key in ("spf", "dkim", "dmarc", "mta_sts", "tls_rpt", "dnssec"):
        found = outreach.problems(report(**{key: "fail"}))
        assert found[0]["fix"], key


# ------------------------------------------------------------- the message

def body(reports=None, **kwargs):
    kwargs.setdefault("sender_name", "Diego")
    kwargs.setdefault("sender_email", "diego@diegofarina.com")
    return outreach.render_email(reports or [report(spf="fail")], **kwargs)


def test_the_message_states_that_only_public_dns_was_read():
    """The first thing a stranger wonders is how you know. Answering it in
    the message is the difference between a heads-up and a threat."""
    text = body()
    assert "registros DNS públicos" in text
    assert "No he accedido a ningún sistema" in text


def test_the_message_identifies_its_sender_and_offers_a_way_out():
    text = body()
    assert "diego@diegofarina.com" in text
    assert "BAJA" in text


def test_the_opt_out_address_can_differ_from_the_sender():
    text = body(opt_out_to="bajas@diegofarina.com")
    assert "bajas@diegofarina.com" in text


def test_the_findings_and_their_fixes_reach_the_body():
    text = body([report(spf="fail", dmarc="warn")])
    assert "resumen de spf" in text and "resumen de dmarc" in text
    assert "Cómo se arregla" in text
    assert "PROBLEMA" in text and "AVISO" in text


def test_a_clean_domain_gets_an_honest_message_rather_than_invented_problems():
    text = body([report()])
    assert "No he encontrado nada que señalar" in text


def test_several_domains_fit_in_one_message():
    text = body([report("uno.com", spf="fail"), report("dos.com", dmarc="fail")])
    assert "uno.com" in text and "dos.com" in text
    assert outreach.subject_for([report("uno.com"), report("dos.com")]).startswith(
        "Autenticación de correo de 2 dominios"
    )


def test_a_personal_note_is_included_verbatim():
    assert "Nos vimos en la conferencia" in body(note="Nos vimos en la conferencia")


def test_the_message_invites_them_to_scan_their_workspace():
    text = body()
    assert "https://diegofarina.com/vigia" in text
    assert "GOOGLE WORKSPACE" in text


def test_the_invitation_states_the_read_only_promise_it_has_to_keep():
    """The product's whole pitch is that it cannot touch anything. If the
    outreach mail overclaimed, the first admin to read the consent screen
    would catch it — so the claim is asserted here."""
    text = body()
    assert "SOLO LECTURA" in text
    assert "no puede modificar" in text
    assert "nunca pide acceso al contenido de Gmail ni de Drive" in text


def test_the_message_offers_a_way_to_verify_the_claims_without_connecting_anything():
    """A stranger will not hand over admin credentials to verify a cold
    email. The public checker needs no access at all, so it is the CTA that
    actually works on first contact."""
    assert "dmarc-checker" in body()


def test_the_sender_name_survives_the_comma_it_contains():
    """"Diego Fariña, Vigía" needs RFC 5322 quoting or the comma turns the
    From header into two addresses."""
    from email.utils import getaddresses

    from vigia.api.tailnet_routes import _sender

    class S:
        smtp_from = '"Diego Fariña, Vigía" <diego@diegofarina.com>'

    assert _sender(S()) == ("Diego Fariña, Vigía", "diego@diegofarina.com")
    assert len(getaddresses([S.smtp_from])) == 1


def test_a_sender_without_a_display_name_still_works():
    from vigia.api.tailnet_routes import _sender

    class S:
        smtp_from = "diego@diegofarina.com"

    assert _sender(S()) == ("diego@diegofarina.com", "diego@diegofarina.com")


def test_the_same_message_can_be_written_in_english():
    """Same claims, same structure, other language.

    Everything this module writes comes from `email.outreach` in the catalogue, so
    the check that matters is that no sentence fell through: a missing entry
    renders as its own dotted path, and a cold e-mail to a stranger with
    "email.outreach.intro" in it is worse than not sending one.
    """
    reports = [report("uno.com", spf="fail"), report("dos.com")]
    text = outreach.render_email(
        reports, sender_name="Diego", sender_email="diego@diegofarina.com", lang="en"
    )
    assert "email.outreach" not in text
    assert "public DNS records" in text and "I have not accessed any system" in text
    # The promises the Spanish version makes, in the same places.
    assert "READ-ONLY" in text and "cannot modify a single setting" in text
    assert "https://diegofarina.com/vigia/dmarc-checker" in text
    assert "UNSUBSCRIBE" in text
    # Nothing Spanish left over in the middle of it.
    for resto in ("Cómo se arregla", "POR QUÉ IMPORTA", "PROBLEMA]", "Hola:"):
        assert resto not in text, resto
    assert outreach.subject_for(reports, "en").startswith("Email authentication for 2 domains")


def test_each_mechanism_carries_its_label_and_fix_in_both_languages():
    for lang in ("es", "en"):
        for key in ("spf", "dkim", "dmarc", "mta_sts", "tls_rpt", "dnssec"):
            found = outreach.problems(report(**{key: "fail"}), lang)[0]
            assert found["label"] and not found["label"].startswith("email."), (lang, key)
            assert found["fix"] and not found["fix"].startswith("email."), (lang, key)
            # The mechanism's own name is never translated.
            assert key.replace("_", "-").upper() in found["label"].upper()


def test_the_summary_counts_by_severity():
    counts = outreach.summarize([report("a.com", spf="fail", dnssec="warn")])
    assert counts == {"domains": ["a.com"], "problems": 2, "fail": 1, "warn": 1}


# --------------------------------------------------------- the live routes

@pytest.fixture(scope="module")
def app(tmp_path_factory):
    os.environ["VIGIA_DB_PATH"] = str(tmp_path_factory.mktemp("db") / "t.db")
    os.environ["VIGIA_SMTP_HOST"] = "smtp.invalido"
    os.environ["VIGIA_SMTP_FROM"] = "Vigía <diego@diegofarina.com>"
    from vigia import create_app

    application = create_app()
    application.config.update(TESTING=True)
    return application


ROUTES = (
    ("get", "/tailnet/"),
    ("get", "/tailnet/api/recipients"),
    ("get", "/tailnet/api/log"),
    ("post", "/tailnet/api/check"),
    ("post", "/tailnet/api/preview"),
    ("post", "/tailnet/api/send"),
)


@pytest.mark.parametrize("method,path", ROUTES)
def test_every_route_refuses_a_request_that_is_not_from_the_tailnet(app, method, path):
    client = app.test_client()
    response = getattr(client, method)(path, json={})
    assert response.status_code == 403
    assert response.get_json()["error"] == "tailnet_only"


@pytest.mark.parametrize("method,path", ROUTES)
def test_every_route_refuses_a_funnel_request_from_a_tailnet_address(app, method, path):
    client = app.test_client()
    response = getattr(client, method)(
        path, json={}, headers={"Tailscale-Funnel-Request": "1"},
        environ_base={"REMOTE_ADDR": TAILNET_IP},
    )
    assert response.status_code == 403


@pytest.mark.parametrize("method,path", ROUTES)
def test_a_forged_forwarded_header_does_not_open_the_gate(app, method, path):
    """A rate limiter in this codebase was already defeated this way."""
    client = app.test_client()
    response = getattr(client, method)(
        path, json={}, headers={"X-Forwarded-For": TAILNET_IP}
    )
    assert response.status_code == 403


@pytest.fixture()
def tailnet(app):
    return app.test_client()


def call(client, method, path, **kwargs):
    kwargs.setdefault("environ_base", {"REMOTE_ADDR": TAILNET_IP})
    return getattr(client, method)(path, **kwargs)


def test_the_console_loads_from_the_tailnet(tailnet):
    response = call(tailnet, "get", "/tailnet/")
    assert response.status_code == 200
    assert b"consola privada" in response.data
    assert b"noindex" in response.data


def test_whoami_explains_the_refusal_without_being_gated(tailnet):
    denied = tailnet.get("/tailnet/api/whoami").get_json()
    assert denied["allowed"] is False and denied["reason"]
    allowed = call(tailnet, "get", "/tailnet/api/whoami").get_json()
    assert allowed["allowed"] is True


@pytest.mark.parametrize("domains", ["", "no válido", "a.com\n" * 11])
def test_bad_domain_input_is_rejected_before_any_dns_lookup(tailnet, domains):
    response = call(tailnet, "post", "/tailnet/api/check", json={"domains": domains})
    assert response.status_code == 400


def test_a_malformed_recipient_is_rejected(tailnet):
    response = call(
        tailnet, "post", "/tailnet/api/send",
        json={"domains": "ejemplo.com", "to": "esto-no-es-un-correo"},
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_email"


def test_sending_with_no_recipient_is_rejected(tailnet):
    response = call(
        tailnet, "post", "/tailnet/api/send", json={"domains": "ejemplo.com", "to": ""}
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "no_recipient"


def test_the_same_person_is_not_written_to_twice_by_accident(app, tailnet, monkeypatch):
    from vigia.api import tailnet_routes

    monkeypatch.setattr(tailnet_routes, "_check", lambda domains, settings: [report(spf="fail")])
    monkeypatch.setattr(tailnet_routes, "send_email", lambda *a, **k: None)

    payload = {"domains": "ejemplo.com", "to": "quien@ejemplo.com"}
    first = call(tailnet, "post", "/tailnet/api/send", json=payload)
    assert first.status_code == 200 and first.get_json()["results"][0]["ok"] is True

    second = call(tailnet, "post", "/tailnet/api/send", json=payload)
    assert second.status_code == 409
    assert second.get_json()["error"] == "cooldown"

    forced = call(tailnet, "post", "/tailnet/api/send", json={**payload, "force": True})
    assert forced.status_code == 200

    history = call(tailnet, "get", "/tailnet/api/log").get_json()["sends"]
    assert len(history) == 2 and all(s["ok"] for s in history)


def test_a_send_failure_is_recorded_instead_of_disappearing(app, tailnet, monkeypatch):
    from vigia.api import tailnet_routes
    from vigia.notify import NotifyError

    monkeypatch.setattr(tailnet_routes, "_check", lambda domains, settings: [report(spf="fail")])

    def explode(*args, **kwargs):
        raise NotifyError("el servidor SMTP dijo no")

    monkeypatch.setattr(tailnet_routes, "send_email", explode)
    response = call(
        tailnet, "post", "/tailnet/api/send",
        json={"domains": "ejemplo.com", "to": "falla@ejemplo.com"},
    )
    assert response.status_code == 200
    assert response.get_json()["results"][0]["ok"] is False

    history = call(tailnet, "get", "/tailnet/api/log").get_json()["sends"]
    failed = [s for s in history if s["recipient"] == "falla@ejemplo.com"]
    assert failed and failed[0]["ok"] is False and "SMTP" in failed[0]["error"]


def test_preview_renders_without_sending_anything(tailnet, monkeypatch):
    from vigia.api import tailnet_routes

    sent = []
    monkeypatch.setattr(tailnet_routes, "_check", lambda domains, settings: [report(spf="fail")])
    monkeypatch.setattr(tailnet_routes, "send_email", lambda *a, **k: sent.append(1))

    data = call(
        tailnet, "post", "/tailnet/api/preview",
        json={"domains": "ejemplo.com", "note": "hola"},
    ).get_json()
    assert "hola" in data["body"] and data["subject"]
    assert sent == [], "la vista previa no puede enviar nada"
