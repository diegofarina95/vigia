"""Metrics. Which hook works, and whether the domain is still healthy.

**Reply rate by finding type is the key number.** It is the only one that changes
what gets built next: if "anyone can send email as you" gets replies and "your
email isn't signed" does not, the ranking in `catalog.py` should change, and this
is the evidence for doing it.

Everything is computed from the rows. There is no counter to drift, no tracking
pixel, and no inbox parsing — replies are classified by hand, which for the volumes
this tool is designed for (tens per day, not thousands) is a minute's work and is
more accurate than anything automatic.
"""
from __future__ import annotations

import csv
import io
import sqlite3
from dataclasses import dataclass, field


@dataclass
class Row:
    """One line of the metrics table."""

    key: str
    sent: int = 0
    replies: int = 0
    interested: int = 0
    not_interested: int = 0
    unsubscribes: int = 0
    bounces: int = 0

    @property
    def reply_rate(self) -> float:
        return self.replies / self.sent if self.sent else 0.0

    @property
    def interest_rate(self) -> float:
        """Replies that were not a brush-off. The number that predicts revenue."""
        return self.interested / self.sent if self.sent else 0.0

    @property
    def unsubscribe_rate(self) -> float:
        return self.unsubscribes / self.sent if self.sent else 0.0

    @property
    def bounce_rate(self) -> float:
        return self.bounces / self.sent if self.sent else 0.0


@dataclass
class Report:
    by_finding: list[Row] = field(default_factory=list)
    by_variant: list[Row] = field(default_factory=list)
    totals: Row = field(default_factory=lambda: Row("total"))


_CLASIFICACIONES = {
    "interested": "interested",
    "not_interested": "not_interested",
    "unsubscribe": "unsubscribes",
    "bounce": "bounces",
}

#: Replies that are not answers from a person. A bounce is a machine and an
#: unsubscribe is a click, so counting either as a "reply" would inflate the one
#: number the whole exercise is steered by.
_NO_SON_RESPUESTA = ("bounce", "unsubscribe")


def _collect(conn: sqlite3.Connection, agrupar_por: str) -> list[Row]:
    filas: dict[str, Row] = {}

    for fila in conn.execute(
        f"SELECT {agrupar_por} AS clave, COUNT(*) AS n FROM sends s "
        "LEFT JOIN scans sc ON sc.id = s.scan_id "
        "LEFT JOIN templates t ON t.id = s.template_id "
        "WHERE s.status = 'sent' GROUP BY clave"
    ):
        clave = fila["clave"] or "—"
        filas.setdefault(clave, Row(clave)).sent = int(fila["n"])

    for fila in conn.execute(
        f"SELECT {agrupar_por} AS clave, r.classification AS c, COUNT(*) AS n "
        "FROM replies r JOIN sends s ON s.id = r.send_id "
        "LEFT JOIN scans sc ON sc.id = s.scan_id "
        "LEFT JOIN templates t ON t.id = s.template_id "
        "GROUP BY clave, c"
    ):
        clave = fila["clave"] or "—"
        registro = filas.setdefault(clave, Row(clave))
        campo = _CLASIFICACIONES.get(fila["c"])
        n = int(fila["n"])
        if campo:
            setattr(registro, campo, getattr(registro, campo) + n)
        if fila["c"] not in _NO_SON_RESPUESTA:
            registro.replies += n

    return sorted(filas.values(), key=lambda r: (-r.sent, r.key))


def build_report(conn: sqlite3.Connection) -> Report:
    por_hallazgo = _collect(conn, "sc.primary_finding_code")
    por_variante = _collect(conn, "t.variant")
    total = Row("total")
    for r in por_hallazgo:
        for campo in ("sent", "replies", "interested", "not_interested",
                      "unsubscribes", "bounces"):
            setattr(total, campo, getattr(total, campo) + getattr(r, campo))
    return Report(by_finding=por_hallazgo, by_variant=por_variante, totals=total)


def record_reply(
    conn: sqlite3.Connection, send_id: int, classification: str, notes: str = ""
) -> int:
    """Log a reply by hand. The CHECK constraint rejects an invented class."""
    from .db import now, transaction

    with transaction(conn):
        cur = conn.execute(
            "INSERT INTO replies (send_id, received_at, classification, notes) "
            "VALUES (?,?,?,?)",
            (send_id, now(), classification, notes or None),
        )
        if classification == "interested":
            conn.execute(
                "UPDATE prospects SET status = 'replied' WHERE id = "
                "(SELECT prospect_id FROM contacts WHERE id = "
                " (SELECT contact_id FROM sends WHERE id = ?))",
                (send_id,),
            )
    return int(cur.lastrowid)


CSV_HEADERS = (
    "grupo", "clave", "enviados", "respuestas", "tasa_respuesta",
    "interesados", "tasa_interes", "no_interesados", "bajas", "tasa_baja",
    "rebotes", "tasa_rebote",
)


def to_csv(report: Report) -> str:
    """The whole report as CSV. Rates as fractions, not pre-formatted percentages —
    a spreadsheet can format a number and cannot un-format a string."""
    salida = io.StringIO()
    escritor = csv.writer(salida)
    escritor.writerow(CSV_HEADERS)
    for grupo, filas in (("hallazgo", report.by_finding), ("variante", report.by_variant)):
        for r in filas:
            escritor.writerow([
                grupo, r.key, r.sent, r.replies, round(r.reply_rate, 4),
                r.interested, round(r.interest_rate, 4), r.not_interested,
                r.unsubscribes, round(r.unsubscribe_rate, 4),
                r.bounces, round(r.bounce_rate, 4),
            ])
    t = report.totals
    escritor.writerow([
        "total", "", t.sent, t.replies, round(t.reply_rate, 4), t.interested,
        round(t.interest_rate, 4), t.not_interested, t.unsubscribes,
        round(t.unsubscribe_rate, 4), t.bounces, round(t.bounce_rate, 4),
    ])
    return salida.getvalue()
