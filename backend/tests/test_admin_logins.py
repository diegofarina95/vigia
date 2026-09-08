"""Where super admins sign in from, and the country lookup behind it.

The signal this check is built on is deliberately narrow: not "a risky
country" — that is a stereotype, and a Spanish company with a developer in
Argentina would light up every week for nothing — but **new**. A country that
appears for the first time on an account with months of history elsewhere.

Everything else here defends the two ways this feature could lie: inventing a
country it does not have, and calling something new when there is no baseline
to be new against.
"""
from datetime import timedelta

import pytest

from vigia import geoip
from vigia.checks import check_admin_logins as mod
from vigia.checks.util import utcnow

NOW = utcnow()


def admin(email, super_admin=True):
    return {"primaryEmail": email, "isAdmin": super_admin, "isDelegatedAdmin": False,
            "suspended": False, "archived": False}


def login(email, ip, days_ago, name="login_success", suspicious=False, login_type=""):
    parameters = []
    if suspicious:
        parameters.append({"name": "is_suspicious", "boolValue": True})
    if login_type:
        parameters.append({"name": "login_type", "value": login_type})
    when = (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return {
        "id": {"time": when, "applicationName": "login"},
        "actor": {"email": email},
        "ipAddress": ip,
        "events": [{"type": "login", "name": name, "parameters": parameters}],
    }


class Ctx:
    def __init__(self, users, events=None, boom=False):
        self._users = users
        self._events = events or []
        self._boom = boom

    def users(self):
        return self._users

    def login_events(self):
        if self._boom:
            raise RuntimeError("la API de informes ha fallado")
        return self._events

    def complete(self, source):
        return getattr(self, "_completo", {}).get(source, True)

    def measured(self, source):
        return True

def by_id(findings):
    return {f.id: f for f in findings}


ES = "81.45.0.1"        # España
US = "8.8.8.8"          # Estados Unidos
NL = "185.230.212.129"  # Países Bajos


@pytest.fixture(autouse=True)
def tiny_database(tmp_path, monkeypatch):
    """A three-country database built in-process.

    The real 8 MB file is a deployment artefact: depending on it would make
    these tests skip on a fresh checkout, and a test that skips because of
    deployment state is not a test. The packing format is the real one, so
    this still exercises `pack` and the binary search.
    """
    import ipaddress

    ranges = [(4, 0, "ZZ")]
    for start, code in [("8.0.0.0", "US"), ("9.0.0.0", "ZZ"),
                        ("81.0.0.0", "ES"), ("82.0.0.0", "ZZ"),
                        ("185.230.212.0", "NL"), ("185.230.213.0", "ZZ")]:
        ranges.append((4, int(ipaddress.IPv4Address(start)), code))
    ranges.append((6, 0, "ZZ"))
    ranges.append((6, int(ipaddress.IPv6Address("2a00::")), "IE"))

    (tmp_path / "geoip-country.bin").write_bytes(geoip.pack(ranges))
    monkeypatch.setenv("VIGIA_DATA_DIR", str(tmp_path))
    geoip._table.cache_clear()
    yield
    geoip._table.cache_clear()


# ------------------------------------------------------ the country lookup

@pytest.mark.parametrize("ip,expected", [(ES, "ES"), (US, "US"), (NL, "NL")])
def test_the_offline_database_resolves_real_addresses(ip, expected):
    assert geoip.country(ip) == expected


@pytest.mark.parametrize("ip", ["192.168.1.10", "10.0.0.1", "127.0.0.1", "::1"])
def test_a_private_address_has_no_country_rather_than_a_wrong_one(ip):
    assert geoip.country(ip) is None


@pytest.mark.parametrize("ip", ["", "no-soy-una-ip", "999.999.999.999", None, 42])
def test_garbage_returns_none_instead_of_guessing(ip):
    assert geoip.country(ip) is None


def test_a_missing_database_degrades_to_unknown_and_does_not_crash(tmp_path):
    # Its own directory: the fixture above populated tmp_path itself.
    empty = tmp_path / "vacio"
    empty.mkdir()
    assert geoip.country(US, data_dir=str(empty)) is None
    assert geoip.available(data_dir=str(empty)) is False


def test_a_corrupt_database_is_ignored_rather_than_misread(tmp_path):
    broken = tmp_path / "roto"
    broken.mkdir()
    (broken / "geoip-country.bin").write_bytes(b"esto no es la base de datos")
    assert geoip.country(US, data_dir=str(broken)) is None


def test_country_names_are_spanish_and_fall_back_to_the_code():
    assert geoip.country_name("ES") == "España"
    assert geoip.country_name("GB") == "Reino Unido"
    assert geoip.country_name(None) == "desconocido"
    # A code with no Spanish name reads as the code rather than as nothing.
    # Picked by asking the table instead of hardcoding one, which is how this
    # assertion broke the moment the table grew.
    missing = next(c for c in ("XK", "TV", "NR", "WS") if c not in geoip.COUNTRY_NAMES)
    assert geoip.country_name(missing) == missing


def test_the_packed_format_round_trips():
    blob = geoip.pack([(4, 0, "ZZ"), (4, 16909060, "ES"), (6, 0, "ZZ")])
    assert blob.startswith(geoip.FORMAT)


# --------------------------------------------------------- the inventory

def test_the_inventory_lists_each_admin_and_where_they_sign_in_from():
    events = [login("ceo@x.com", ES, d) for d in (1, 10, 40)]
    events += [login("cto@x.com", US, d) for d in (2, 30)]
    found = by_id(mod.run(Ctx([admin("ceo@x.com"), admin("cto@x.com")], events)))
    inventory = found["admin-login-countries"]

    assert inventory.status == "pass" and inventory.severity == "info"
    lines = " | ".join(inventory.affected_items)
    assert "ceo@x.com" in lines and "cto@x.com" in lines
    assert "España" in lines and "Estados Unidos" in lines


def test_the_inventory_never_escalates_anybody():
    """It names people without accusing them, so it must not add a bullet to
    anyone's row — the same rule the super-admin count now follows."""
    events = [login("ceo@x.com", ES, d) for d in (1, 40)]
    inventory = by_id(mod.run(Ctx([admin("ceo@x.com")], events)))["admin-login-countries"]
    assert inventory.severity == "info"
    assert not inventory.accounts


def test_with_no_super_admins_the_check_says_nothing():
    assert mod.run(Ctx([admin("ana@x.com", super_admin=False)], [])) == []


def test_an_unreadable_audit_log_is_undetermined_not_empty():
    [found] = mod.run(Ctx([admin("ceo@x.com")], boom=True))
    assert found.status == "undetermined"
    assert "no se puede decir desde dónde" in found.description


def test_only_successful_sign_ins_count():
    events = [login("ceo@x.com", US, 1, name="login_failure")] + [
        login("ceo@x.com", ES, d) for d in (5, 40)
    ]
    inventory = by_id(mod.run(Ctx([admin("ceo@x.com")], events)))["admin-login-countries"]
    assert "Estados Unidos" not in " ".join(inventory.affected_items)


def test_events_from_people_who_are_not_super_admins_are_ignored():
    events = [login("ana@x.com", US, 1)] + [login("ceo@x.com", ES, d) for d in (2, 40)]
    inventory = by_id(mod.run(Ctx(
        [admin("ceo@x.com"), admin("ana@x.com", super_admin=False)], events
    )))["admin-login-countries"]
    assert "ana@x.com" not in " ".join(inventory.affected_items)


# ------------------------------------------------------ the actual signal

def test_a_country_that_only_appears_recently_is_flagged():
    """Months of Spain, then one sign-in from the Netherlands last week."""
    events = [login("ceo@x.com", ES, d) for d in (2, 20, 45, 70)]
    events.append(login("ceo@x.com", NL, 3))
    found = by_id(mod.run(Ctx([admin("ceo@x.com")], events)))["admin-login-new-country"]

    assert found.status == "fail" and found.severity == "high"
    assert found.accounts == ["ceo@x.com"]
    assert "Países Bajos" in " ".join(found.affected_items)


def test_a_country_present_since_the_beginning_is_not_new():
    events = [login("ceo@x.com", ES, d) for d in (1, 30, 60)]
    events += [login("ceo@x.com", US, d) for d in (2, 55)]
    found = by_id(mod.run(Ctx([admin("ceo@x.com")], events)))["admin-login-new-country"]
    assert found.status == "pass"
    assert found.accounts == []


def test_without_enough_history_nothing_can_be_called_new():
    """A log that only covers a few days has no baseline, so every country in
    it looks "new". Saying so is the honest answer; flagging them all is not."""
    events = [login("ceo@x.com", ES, 1), login("ceo@x.com", NL, 2)]
    found = by_id(mod.run(Ctx([admin("ceo@x.com")], events)))["admin-login-new-country"]

    assert found.status == "undetermined"
    assert found.i18n_variant == "no-baseline"
    assert "línea base" in found.description


def test_the_finding_warns_that_a_trip_looks_identical():
    """A scanner that says "compromised" when it means "different country"
    burns the customer's trust the first time someone goes on holiday."""
    events = [login("ceo@x.com", ES, d) for d in (2, 30, 60)]
    events.append(login("ceo@x.com", NL, 1))
    found = by_id(mod.run(Ctx([admin("ceo@x.com")], events)))["admin-login-new-country"]
    assert "viaje" in found.description and "VPN" in found.description


def test_addresses_with_no_country_do_not_become_a_new_country():
    """A private or unresolvable address must not be treated as a country
    appearing for the first time."""
    events = [login("ceo@x.com", ES, d) for d in (2, 30, 60)]
    events.append(login("ceo@x.com", "192.168.1.50", 1))
    found = by_id(mod.run(Ctx([admin("ceo@x.com")], events)))["admin-login-new-country"]
    assert found.status == "pass"


# --------------------------------------------- the data is personal too

def test_the_purge_removes_the_addresses_and_the_ips_it_printed():
    """An IP identifies a person's connection, so it is personal data and the
    24-hour window applies to it as much as to an e-mail address."""
    from vigia.retention import strip_addresses

    data = [{
        "id": "admin-login-countries",
        "accounts": [],
        "affected_items": ["ceo@x.com: España (ES)×12, 81.45.0.1", "cto@x.com: 8.8.8.8"],
    }]
    removed = strip_addresses(data, "2026-08-01T00:00:00Z")
    assert removed == 2, "dos personas"
    assert data[0]["affected_items"] == []
    assert data[0]["details"]["addresses_purged"] == 2


def test_the_same_person_in_several_shapes_counts_once():
    """`accounts` holds the bare address and `affected_items` holds a sentence
    containing it. Counting both would inflate the number the report prints —
    the mistake this counter already made twice."""
    from vigia.retention import strip_addresses

    data = [{
        "id": "recovery-super-admins",
        "accounts": ["a@x.com"],
        "affected_items": ["a@x.com: sin teléfono", "a@x.com: 81.45.0.1 · España"],
    }]
    assert strip_addresses(data, "2026-08-01T00:00:00Z") == 1


@pytest.mark.parametrize("line,expected", [
    ("a@x.com: España", "a@x.com"),
    ("solo la ip 8.8.8.8 aquí", "8.8.8.8"),
    ("2a00:1450:4003:80f::200e", "2a00:1450:4003:80f::200e"),
    ("sin nada personal", "sin nada personal"),
])
def test_identity_picks_who_the_line_is_about(line, expected):
    from vigia.retention import identity

    assert identity(line) == expected


def test_an_organizational_unit_path_is_not_mistaken_for_personal_data():
    """The policy findings print OU paths; those must survive the purge."""
    from vigia.retention import is_address

    assert not is_address("/Ventas/Comercial")
    assert not is_address("toda la organización: desactivado")


def test_one_person_named_by_two_findings_is_still_one_person():
    """A super admin is named by several findings at once. The number the purge
    reports is a headcount, so it must not add up to more people than exist —
    the same inflation this counter produced per field and then per finding."""
    from vigia.retention import addresses_in, strip_addresses

    data = [
        {"id": "admin-login-countries", "accounts": [],
         "affected_items": ["a@x.com: España, 81.45.0.1", "b@x.com: 8.8.8.8"]},
        {"id": "admin-login-new-country", "accounts": ["a@x.com"],
         "affected_items": ["a@x.com: Marruecos"]},
    ]
    assert len(addresses_in(data)) == 2
    assert strip_addresses(data, "2026-08-01T00:00:00Z") == 2, "dos personas, no tres"
    # Each finding still reports its own figure, which is a different question.
    assert data[0]["details"]["addresses_purged"] == 2
    assert data[1]["details"]["addresses_purged"] == 1
