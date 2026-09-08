"""One evaluated result, four projections.

Before this module each channel re-derived what it needed: the dashboard called
`score_breakdown` + `people_at_risk` + `rank_actions` and re-ran the coherence
check; the printable report called the same three minus the coherence check and
plus the executive summary; the CSV called none of them; the alert e-mail called
none of them AND skipped the engine-version gate. Four readers of one row,
disagreeing about it — verified by execution, not suspected.

A projection may **read** the stored result and **shape** it. It may not compute
a verdict, a score, a population or a delta. If a channel needs a number that is
not in here, the number belongs in `scan.evaluated_result`, computed once, at
scan time, next to the coverage that justifies it.

Old rows have no stored result (the column postdates them), so `project` derives
one on the fly for those and marks it. That is a migration path, not a second
code path: the derivation used is the same function.

The sentences live in the locale catalogue, not in here: four channels share one
implementation of each phrase, so a phrase written as an f-string would be a
phrase that can only ever be Spanish in all four. `lang` defaults to Spanish so
a caller that has no language to offer keeps the wording it had.
"""
from __future__ import annotations

from .i18n import status_label, text


def project(scan: dict, ctx=None) -> dict:
    """The evaluated result for a stored scan row, stored or re-derived once."""
    stored = scan.get("result") or {}
    if stored.get("breakdown") is not None:
        return stored

    # Pre-column row. Derive with the same function `run_scan` uses so the two
    # paths cannot drift, and say that we did.
    from .scan import evaluated_result

    derivado = evaluated_result(
        scan.get("findings") or [], scan.get("score"), scan.get("counts") or {}, ctx
    )
    derivado["derived_at_read_time"] = True
    return derivado


#: The sources a coverage entry can describe, in the order the line names them.
#: The words are in the catalogue; what belongs here is which sources exist.
FUENTES = ("users", "domains", "token", "admin", "login", "policies")

#: Google's audit window, the denominator of a partial read. A figure, and it
#: stays in the code: a catalogue that spells out "180 días" is how the CSV ended
#: up printing "(~180 días)" over a label that said 178 measured.
VENTANA_MAXIMA_DIAS = 180


def _dias(lang: str, n: int) -> str:
    """"1 día" / "174 días", agreed with the number, in either language."""
    clave = "un_dia" if n == 1 else "varios_dias"
    return text(lang, f"proyeccion.cobertura.{clave}", n=n)


def coverage_line(result: dict, lang: str = "es") -> str:
    """One sentence a reader can check: what was read, and what was not.

    The brief asked for "17 de 17 usuarios analizados · 174 días de registro".
    This is that line, and it is the same string in every channel because it is
    computed here from the stored coverage rather than phrased per template.
    """
    cobertura = (result or {}).get("coverage") or {}
    if not cobertura:
        return ""

    partes: list[str] = []
    incompletas: list[str] = []
    for clave in FUENTES:
        entrada = cobertura.get(clave)
        if not entrada:
            continue
        nombre = text(lang, f"proyeccion.cobertura.{clave}")
        registros = entrada.get("records")
        dias = entrada.get("window_days")
        texto = f"{registros} {nombre}" if registros is not None else nombre
        if dias:
            texto += text(lang, "proyeccion.cobertura.ventana", dias=_dias(lang, dias))
        partes.append(texto)
        if not entrada.get("complete", True):
            incompletas.append(clave)

    linea = " · ".join(partes)
    if incompletas:
        # Lower case, and with the number. "LEÍDO A MEDIAS" in capitals on the
        # first data line of the report is correct and honest, and a customer
        # reads it as a malfunction. A known limit and a broken tool should not
        # look the same, and the way to tell them apart is the figure.
        detalle = []
        for clave in incompletas:
            nombre = text(lang, f"proyeccion.cobertura.{clave}")
            dias = (cobertura.get(clave) or {}).get("window_days")
            detalle.append(
                text(
                    lang,
                    "proyeccion.cobertura.parcial_detalle",
                    nombre=nombre,
                    dias=dias,
                    maximo=VENTANA_MAXIMA_DIAS,
                )
                if dias
                else nombre
            )
        linea += text(
            lang, "proyeccion.cobertura.parcial", detalle="; ".join(detalle)
        )
    return linea


# ------------------------------------- why the number moved, in one wording

#: The severities this line can name. Their words are in the catalogue and they
#: are NOT the ones in `severity`: these agree with "severidad" ("de media a
#: alta"), which in Spanish is feminine, and the finding labels are masculine.
_SEVERIDADES = ("critical", "high", "medium", "low", "info")

#: The change labels, once. Four channels used to phrase these independently and
#: the CSV shipped the raw English enum to the customer. Kept as the list of
#: labels that exist — an unknown one still produces no sentence at all, rather
#: than a catalogue path shown to a reader.
CAMBIOS = (
    "new",
    "worse",
    "improved",
    "resolved",
    "coverage_gained",
    "coverage_lost",
    "same",
    "baseline",
)


def _severidad(lang: str, clave: str) -> str:
    return text(lang, f"proyeccion.severidad.{clave}") if clave in _SEVERIDADES else clave


def change_label(finding: dict, lang: str = "es") -> str:
    """The change of one finding, in words, with its numbers when it has them."""
    cambio = finding.get("change") or ""
    detalle = finding.get("change_detail") or {}
    if cambio not in CAMBIOS:
        return ""
    etiqueta = text(lang, f"proyeccion.cambio.{cambio}")

    if "from_count" in detalle:
        return text(
            lang,
            "proyeccion.cambio.cuenta",
            etiqueta=etiqueta,
            desde=detalle["from_count"],
            hasta=detalle["to_count"],
        )
    if "from_severity" in detalle:
        return text(
            lang,
            "proyeccion.cambio.severidad",
            etiqueta=etiqueta,
            desde=_severidad(lang, detalle.get("from_severity") or ""),
            hasta=_severidad(lang, detalle.get("to_severity") or ""),
            sufijo=text(lang, "proyeccion.cambio.por_regresion")
            if detalle.get("regression")
            else "",
        )
    if cambio == "coverage_gained":
        return text(
            lang,
            "proyeccion.cambio.ahora_si",
            etiqueta=etiqueta,
            resultado=status_label(lang, detalle.get("to_status") or "").lower(),
        )
    return etiqueta


def score_explanation(
    score_change: dict | None, summary: dict | None = None, lang: str = "es"
) -> dict:
    """The score's movement split by cause, in the wording every channel uses.

    The presentation rule that matters is in here: when the exposure component is
    zero the answer is **not** "sin cambios". It is "sin cambios en tu
    organización", with the coverage movement named separately. The two are
    different statements and the customer is entitled to know which one they are
    being given — the old label collapsed both into "= sin cambios" over a score
    that had moved from 33 to 35.
    """
    if not score_change:
        return {}

    total = score_change.get("total")
    exposicion = score_change.get("exposure")
    cobertura = score_change.get("coverage")
    if total is None:
        return {}

    salida = {
        "total": total,
        "exposure": exposicion,
        "coverage": cobertura,
        "headline": "",
        "lines": [],
        "org_moved": bool(exposicion),
    }
    ahora, antes = score_change.get("score"), score_change.get("previous_score")
    if ahora is not None and antes is not None:
        salida["headline"] = text(
            lang, "proyeccion.puntuacion.titular", ahora=ahora, antes=antes
        )

    if exposicion is None:
        # Said out loud rather than shown as a silent zero.
        salida["lines"].append(score_change.get("reason") or "")
        return salida

    ganados, perdidos = len(score_change.get("gained") or []), len(score_change.get("lost") or [])
    if cobertura:
        if cobertura > 0:
            clave = "cobertura_ganada_una" if ganados == 1 else "cobertura_ganada_varias"
            cuantas = ganados
        else:
            clave = "cobertura_perdida_una" if perdidos == 1 else "cobertura_perdida_varias"
            cuantas = perdidos
        salida["lines"].append(
            text(lang, f"proyeccion.puntuacion.{clave}", delta=f"{cobertura:+d}", n=cuantas)
        )

    if exposicion:
        salida["lines"].append(
            text(lang, "proyeccion.puntuacion.exposicion", delta=f"{exposicion:+d}")
        )
    else:
        # "sin cambios en tu organización" is only true if the organization did
        # not change. The score is rounded to a whole number out of a denominator
        # in the hundreds, so a single medium control going from correct to
        # warning moves it by 0.6 and rounds away — and then this line would deny
        # a change the findings table lists two inches below it. Found by working
        # out what the 2SV grace-period test would print before running it.
        propios = sum(
            len(summary.get(clave) or [])
            for clave in ("new", "worse", "improved", "resolved")
        ) if summary else 0
        if propios:
            # Was: "la puntuación no se mueve, pero hay N cambio(s) en tu
            # organización: son demasiado pequeños para mover un número redondeado".
            # Two problems. It ran to 120 characters in a column the width of a
            # dial, and it was not true: the score holds still because the net
            # exposure is zero, not because each change is small — a new critical
            # and a resolved critical in the same scan cancel out and neither is
            # small. Stating the fact and stopping is both shorter and correct.
            clave = "sin_efecto_uno" if propios == 1 else "sin_efecto_varios"
            salida["lines"].append(text(lang, f"proyeccion.puntuacion.{clave}", n=propios))
            salida["org_moved"] = True
        else:
            salida["lines"].append(text(lang, "proyeccion.puntuacion.sin_cambios"))
    return salida
