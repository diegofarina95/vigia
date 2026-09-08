"""Country from IP address, resolved offline.

The Admin console shows a location column next to each sign-in, so it is easy
to assume the API does too. It does not: the login audit events carry
`ipAddress`, `is_suspicious`, `login_type` and `login_challenge_method`, and
**no geographic field at all** — Google geolocates the address on their side
purely to draw that column. Verified against the login activity reference.

So the country has to come from somewhere else, and the choice of *where*
matters more than it looks. A lookup service would mean every sign-in IP of
every customer's administrators leaving this server for a company that is not
named in the privacy policy — which enumerates exactly four processors and
says there are no others. An offline database receives nothing, phones
nobody, and needs no new declaration.

Data: DB-IP IP-to-Country Lite, published monthly under CC BY 4.0. It is
downloaded by `scripts/fetch_geoip.py` and packed into a compact binary; this
module only reads it.

**Absence is never a guess.** With no database installed, or an address that
is not in it, `country()` returns None and the caller says "unknown". A
scanner that invents a country is worse than one that admits it does not have
the data, because a wrong country is exactly the kind of detail an admin acts
on.

The packed format exploits a property of the source that is verified at build
time: the ranges tile the whole address space with no gaps, so only the start
of each range needs storing. A lookup is one binary search.
"""
from __future__ import annotations

import bisect
import ipaddress
import logging
import os
import struct
from functools import lru_cache

log = logging.getLogger(__name__)

#: Bumped when the packed layout changes, so a stale file is ignored instead
#: of being misread.
FORMAT = b"VIGIAGEO2"

_DEFAULT_NAME = "geoip-country.bin"


def database_path(data_dir: str = "") -> str:
    return os.path.join(data_dir or os.environ.get("VIGIA_DATA_DIR", "data"), _DEFAULT_NAME)


# --------------------------------------------------------------- packing

def pack(ranges: list[tuple[int, int, str]]) -> bytes:
    """`ranges` is (version, start_as_int, country) already sorted per family.

    Layout: header, then for each family a count, an array of starts and an
    array of two-byte country codes. IPv4 starts are 4 bytes, IPv6 are 16.
    """
    v4 = sorted((start, cc) for version, start, cc in ranges if version == 4)
    v6 = sorted((start, cc) for version, start, cc in ranges if version == 6)

    out = bytearray(FORMAT)
    out += struct.pack("<II", len(v4), len(v6))
    out += b"".join(struct.pack("<I", start) for start, _ in v4)
    out += b"".join(cc[:2].ljust(2).encode("ascii", "replace") for _, cc in v4)
    out += b"".join(start.to_bytes(16, "big") for start, _ in v6)
    out += b"".join(cc[:2].ljust(2).encode("ascii", "replace") for _, cc in v6)
    return bytes(out)


class _Table:
    """Parsed database. Built once and cached."""

    def __init__(self, blob: bytes) -> None:
        if not blob.startswith(FORMAT):
            raise ValueError("cabecera desconocida")
        offset = len(FORMAT)
        n4, n6 = struct.unpack_from("<II", blob, offset)
        offset += 8

        self.v4_starts = list(struct.unpack_from(f"<{n4}I", blob, offset))
        offset += 4 * n4
        self.v4_codes = blob[offset:offset + 2 * n4]
        offset += 2 * n4

        self.v6_starts = [
            int.from_bytes(blob[offset + 16 * i:offset + 16 * (i + 1)], "big")
            for i in range(n6)
        ]
        offset += 16 * n6
        self.v6_codes = blob[offset:offset + 2 * n6]

    def lookup(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        starts, codes = (
            (self.v4_starts, self.v4_codes)
            if address.version == 4
            else (self.v6_starts, self.v6_codes)
        )
        if not starts:
            return None
        index = bisect.bisect_right(starts, int(address)) - 1
        if index < 0:
            return None
        code = codes[2 * index:2 * index + 2].decode("ascii", "replace").strip()
        # ZZ is the source's marker for "unallocated / unknown".
        return code if code and code != "ZZ" else None


@lru_cache(maxsize=4)
def _table(path: str) -> _Table | None:
    try:
        with open(path, "rb") as handle:
            return _Table(handle.read())
    except FileNotFoundError:
        return None
    except (OSError, ValueError, struct.error) as exc:
        log.warning("base de datos de países ilegible (%s): %s", path, exc)
        return None


def available(data_dir: str = "") -> bool:
    return _table(database_path(data_dir)) is not None


def country(ip: str, data_dir: str = "") -> str | None:
    """ISO country code, or None when it genuinely cannot be determined.

    Private, loopback and reserved addresses return None rather than a
    country: they are not on the public internet and no database can place
    them.
    """
    if not ip or not isinstance(ip, str):
        return None
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    if address.is_private or address.is_loopback or address.is_reserved:
        return None
    table = _table(database_path(data_dir))
    return table.lookup(address) if table else None


#: Enough to read a report without a lookup table in your head. Everything
#: else falls back to the ISO code, which is still better than nothing.
COUNTRY_NAMES = {
    "ES": "España", "PT": "Portugal", "FR": "Francia", "IT": "Italia",
    "DE": "Alemania", "GB": "Reino Unido", "IE": "Irlanda", "NL": "Países Bajos",
    "BE": "Bélgica", "CH": "Suiza", "AT": "Austria", "SE": "Suecia",
    "NO": "Noruega", "DK": "Dinamarca", "FI": "Finlandia", "PL": "Polonia",
    "CZ": "Chequia", "RO": "Rumanía", "GR": "Grecia", "TR": "Turquía",
    "RU": "Rusia", "UA": "Ucrania", "BY": "Bielorrusia", "US": "Estados Unidos",
    "CA": "Canadá", "MX": "México", "BR": "Brasil", "AR": "Argentina",
    "CL": "Chile", "CO": "Colombia", "PE": "Perú", "UY": "Uruguay",
    "MA": "Marruecos", "NG": "Nigeria", "ZA": "Sudáfrica", "EG": "Egipto",
    "CN": "China", "HK": "Hong Kong", "TW": "Taiwán", "JP": "Japón",
    "KR": "Corea del Sur", "IN": "India", "PK": "Pakistán", "ID": "Indonesia",
    "SG": "Singapur", "AU": "Australia", "NZ": "Nueva Zelanda", "IL": "Israel",
    "AE": "Emiratos Árabes Unidos", "SA": "Arabia Saudí", "IR": "Irán",
    "VN": "Vietnam", "TH": "Tailandia", "PH": "Filipinas", "MY": "Malasia",
    "HU": "Hungría", "BG": "Bulgaria", "HR": "Croacia", "RS": "Serbia",
    "SK": "Eslovaquia", "SI": "Eslovenia", "LT": "Lituania", "LV": "Letonia",
    "EE": "Estonia", "IS": "Islandia", "LU": "Luxemburgo", "MT": "Malta",
    "CY": "Chipre", "AD": "Andorra", "GI": "Gibraltar", "DZ": "Argelia",
    "TN": "Túnez", "KE": "Kenia", "GH": "Ghana", "SN": "Senegal",
    "EC": "Ecuador", "BO": "Bolivia", "PY": "Paraguay", "VE": "Venezuela",
    "CR": "Costa Rica", "PA": "Panamá", "DO": "República Dominicana",
    "GT": "Guatemala", "CU": "Cuba", "PR": "Puerto Rico", "BD": "Bangladés",
    "LK": "Sri Lanka", "NP": "Nepal", "KZ": "Kazajistán", "GE": "Georgia",
    "AM": "Armenia", "AZ": "Azerbaiyán", "MD": "Moldavia", "AL": "Albania",
    "BA": "Bosnia y Herzegovina", "MK": "Macedonia del Norte", "JO": "Jordania",
    "LB": "Líbano", "IQ": "Irak", "KW": "Kuwait", "QA": "Catar", "BH": "Baréin",
    "OM": "Omán", "YE": "Yemen", "SY": "Siria", "AF": "Afganistán",
    "ET": "Etiopía", "TZ": "Tanzania", "UG": "Uganda", "CM": "Camerún",
    "CI": "Costa de Marfil", "AO": "Angola", "MZ": "Mozambique", "ZM": "Zambia",
    "ZW": "Zimbabue", "BW": "Botsuana", "NA": "Namibia", "MU": "Mauricio",
}


def country_name(code: str | None) -> str:
    if not code:
        return "desconocido"
    return COUNTRY_NAMES.get(code.upper(), code.upper())
