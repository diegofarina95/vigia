"""Rebuilding a finding from a stored scan.

The queue runs long after the scan. It needs the finding back — the subject line,
both descriptions, the evidence — and there are two ways to get it: store the
rendered strings at scan time, or store the evidence and re-derive.

This re-derives, from `scans.raw_findings`, with the same
`select_primary_finding` the scan used. That means one implementation of the
ranking rather than two that drift, and it means a scan taken in March can be
re-read in the other language today without a re-scan.

It also means the *rules* can change under a stored scan. When that happens the
code re-derived today differs from the code stored then, and this module says so
out loud instead of quietly writing a different email than the one the operator's
review table promised.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

from .prioritise import PrimaryFinding, select_primary_finding
from .templates import lang_for_country

log = logging.getLogger("prospector.projection")


def raw_findings(scan: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """The scanner's report as it was stored. `{}` if it cannot be read."""
    try:
        cargado = json.loads(scan["raw_findings"] or "{}")
    except (TypeError, ValueError, KeyError):
        return {}
    return cargado if isinstance(cargado, dict) else {}


def finding_from_scan(
    scan: sqlite3.Row | dict[str, Any],
    prospect: sqlite3.Row | dict[str, Any] | None = None,
    lang: str | None = None,
) -> PrimaryFinding | None:
    """The primary finding for a stored scan, in the reader's language.

    Returns None when the scan stored no usable evidence — which the caller must
    treat as "do not write to them", not as "write something generic".
    """
    informe = raw_findings(scan)
    if not informe:
        return None

    if lang is None:
        pais = prospect["country"] if prospect is not None else None
        lang = lang_for_country(pais)

    hallazgo = select_primary_finding(informe, lang=lang)
    if hallazgo is None:
        return None

    almacenado = scan["primary_finding_code"] if "primary_finding_code" in scan.keys() else None
    if almacenado and almacenado != hallazgo.code:
        # Same evidence, different rules. The current rules win — they are the ones
        # we would have to defend — but it is said out loud, because the review
        # table was populated from the stored code and would otherwise show one
        # hook while the letter argued another.
        log.warning(
            "el hallazgo re-derivado no coincide con el guardado dominio=%s "
            "guardado=%s ahora=%s (las reglas han cambiado desde el escaneo)",
            informe.get("domain"), almacenado, hallazgo.code,
        )
    return hallazgo
