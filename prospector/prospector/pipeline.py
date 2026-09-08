"""Scan → qualify → record. The batch that turns a domain list into prospects.

Deliberately separate from `queue.py`: this stage touches only public DNS and
public web pages, produces no draft and no recipient, and is safe to run over
anything. Nothing here can result in an email. The stage that can is next door,
and it is the one that refuses things.
"""
from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from typing import Callable, Iterable

from .addresses import classify_address
from .db import add_contact, add_prospect, record_qualification, record_scan
from .prioritise import PrimaryFinding, select_primary_finding
from .qualify import score_prospect
from .scanner import ScannerPort
from .signals import SignalsPort, SiteSignals
from .templates import lang_for_country

log = logging.getLogger("prospector.pipeline")


@dataclass
class ScanOutcome:
    domain: str
    prospect_id: int
    finding: PrimaryFinding | None
    score_total: int
    qualified: bool
    unmeasured: bool
    error: str | None = None

    @property
    def summary(self) -> str:
        if self.error:
            return f"error: {self.error}"
        if self.finding is None:
            return "limpio — excluido"
        estado = "califica" if self.qualified else "no califica"
        return f"{self.finding.code} · {self.score_total} · {estado}"


def import_domains(
    conn: sqlite3.Connection,
    filas: Iterable[dict[str, str]],
    source: str = "import",
) -> tuple[int, int]:
    """Create prospects and contacts from imported rows.

    Returns (prospects, contacts). Contacts are classified on the way in and the
    refused ones are stored too — the blocked view has to be able to say what it
    turned down and why, and a row that was silently dropped at import time can
    never be explained later.
    """
    prospectos = contactos = 0
    for fila in filas:
        dominio = (fila.get("domain") or "").strip().lower()
        if not dominio:
            continue
        pid = add_prospect(
            conn,
            domain=dominio,
            company_name=(fila.get("company_name") or "").strip() or None,
            country=(fila.get("country") or "").strip().upper() or None,
            sector=(fila.get("sector") or "").strip() or None,
            source=source,
        )
        prospectos += 1
        for correo in (fila.get("email") or "").replace(";", ",").split(","):
            correo = correo.strip()
            if correo:
                add_contact(conn, pid, correo)
                contactos += 1
    return prospectos, contactos


def scan_prospect(
    conn: sqlite3.Connection,
    prospect: sqlite3.Row,
    scanner: ScannerPort,
    signals: SignalsPort | None = None,
    *,
    threshold: int = 5,
) -> ScanOutcome:
    """Scan one domain, qualify it, and store both. Never raises."""
    dominio = prospect["domain"]
    try:
        informe = scanner.check(dominio)
    except Exception as exc:  # noqa: BLE001 — one bad domain must not stop a batch
        log.warning("escaneo fallido dominio=%s error=%s", dominio, exc)
        return ScanOutcome(dominio, prospect["id"], None, 0, False, True, str(exc))

    lang = lang_for_country(prospect["country"])
    hallazgo = select_primary_finding(informe, lang=lang)
    record_scan(conn, prospect["id"], informe, hallazgo)

    observacion = SiteSignals(domain=dominio)
    if signals is not None:
        try:
            observacion = signals.observe(dominio)
        except Exception as exc:  # noqa: BLE001
            log.warning("observación fallida dominio=%s error=%s", dominio, exc)
            observacion = SiteSignals(domain=dominio, error=str(exc))

    puntuacion = score_prospect(
        informe, observacion, sector=prospect["sector"], domain=dominio,
        threshold=threshold,
    )
    record_qualification(conn, prospect["id"], puntuacion)

    log.info(
        "escaneado dominio=%s hallazgo=%s puntuacion=%s califica=%s",
        dominio, getattr(hallazgo, "code", None), puntuacion.total, puntuacion.qualified,
    )
    return ScanOutcome(
        dominio, prospect["id"], hallazgo, puntuacion.total,
        puntuacion.qualified, puntuacion.unmeasured,
    )


def scan_batch(
    conn: sqlite3.Connection,
    scanner: ScannerPort,
    signals: SignalsPort | None = None,
    *,
    threshold: int = 5,
    only_new: bool = True,
    progress: Callable[[int, int, ScanOutcome], None] | None = None,
) -> list[ScanOutcome]:
    """Scan every prospect that needs it, reporting progress as it goes."""
    consulta = "SELECT * FROM prospects"
    if only_new:
        consulta += " WHERE status = 'new'"
    consulta += " ORDER BY domain"
    filas = list(conn.execute(consulta))

    resultados: list[ScanOutcome] = []
    for indice, fila in enumerate(filas, start=1):
        resultado = scan_prospect(conn, fila, scanner, signals, threshold=threshold)
        resultados.append(resultado)
        if progress is not None:
            progress(indice, len(filas), resultado)
    return resultados


def contactable_for(conn: sqlite3.Connection, prospect_id: int) -> sqlite3.Row | None:
    """The one address this prospect may be written to, if any.

    Role addresses only, and the first by id so the choice is stable across runs.
    `classify_address` is re-run rather than trusting the stored flag alone: the
    flag is what was believed at import time, and this is the last chance to catch
    a row written by an older classifier or by hand.
    """
    for fila in conn.execute(
        "SELECT * FROM contacts WHERE prospect_id = ? AND is_valid = 1 ORDER BY id",
        (prospect_id,),
    ):
        if classify_address(fila["email"]).is_valid:
            return fila
    return None
