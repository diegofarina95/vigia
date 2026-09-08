"""Download the offline IP-to-country database and pack it for Vigía.

Source: DB-IP IP-to-Country Lite, published monthly under CC BY 4.0. Direct
download, no account and no licence key, which is why it was chosen over the
alternatives that need one — a key is a thing that expires while nobody is
looking.

Chosen deliberately over a lookup API: an offline file receives nothing. A
service would mean every administrator sign-in IP of every customer leaving
this server for a company the privacy policy does not name.

Run it monthly (the file is published on the 1st, so the current month 404s
for a few hours and the previous one is used instead):

    python scripts/fetch_geoip.py

The packed output only stores the START of each range, because the source
tiles the whole address space with no gaps. That is verified here rather than
assumed: if a gap ever appears, the build fails instead of silently
attributing an address to the previous country.
"""
from __future__ import annotations

import csv
import gzip
import io
import ipaddress
import os
import sys
import urllib.request
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vigia.geoip import database_path, pack  # noqa: E402

URL = "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz"
# DB-IP rejects urllib's default User-Agent with a 403, so it is set
# explicitly and honestly rather than disguised as a browser.
USER_AGENT = "Vigia/1.0 (+https://diegofarina.com/vigia) offline-geoip-fetch"
ATTRIBUTION = "IP-to-country data by DB-IP.com, licensed under CC BY 4.0"


def _months_to_try() -> list[str]:
    today = date.today()
    previous = date(today.year - (today.month == 1), today.month - 1 or 12, 1)
    return [today.strftime("%Y-%m"), previous.strftime("%Y-%m")]


def download() -> bytes:
    last_error = None
    for month in _months_to_try():
        url = URL.format(month=month)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                print(f"  descargando {month}…")
                return gzip.decompress(response.read())
        except Exception as exc:  # noqa: BLE001 — any failure just tries the next month
            last_error = exc
            print(f"  {month}: no disponible ({exc})")
    raise SystemExit(f"no se ha podido descargar la base de datos: {last_error}")


def parse(raw: bytes) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    previous_end: dict[int, int] = {}
    gaps = 0

    for start_text, end_text, code in csv.reader(io.StringIO(raw.decode("utf-8"))):
        try:
            start = ipaddress.ip_address(start_text)
            end = ipaddress.ip_address(end_text)
        except ValueError:
            continue
        version = start.version
        # The packed format drops the end of each range, which is only safe
        # while the ranges tile the space. Verified, never assumed.
        if version in previous_end and int(start) != previous_end[version] + 1:
            gaps += 1
        previous_end[version] = int(end)
        ranges.append((version, int(start), code.strip().upper()))

    if gaps:
        raise SystemExit(
            f"la fuente trae {gaps} hueco(s) entre rangos: el formato compacto "
            "asumiría un país equivocado para esas direcciones. Hay que guardar "
            "también el final de cada rango antes de seguir."
        )
    return ranges


def main() -> None:
    raw = download()
    ranges = parse(raw)
    v4 = sum(1 for version, _, _ in ranges if version == 4)
    blob = pack(ranges)

    target = database_path()
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    with open(target, "wb") as handle:
        handle.write(blob)

    print(f"  {v4} rangos IPv4 y {len(ranges) - v4} IPv6")
    print(f"  escrito {target} ({len(blob) / 1_000_000:.1f} MB)")
    print(f"  {ATTRIBUTION}")


if __name__ == "__main__":
    main()
