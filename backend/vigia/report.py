"""Self-contained printable report (HTML with print CSS → PDF via the
browser's "Save as PDF").

Deliberately not WeasyPrint/wkhtmltopdf: those pull heavy system libraries
(cairo/pango) into a solo-maintained deploy. The browser already has a
production-grade PDF engine.

Reading order is the order a reader actually needs:
  1. how bad is it        → severity counts + people at risk (the headline)
  2. what do I do first   → the leverage-ranked actions
  3. what changed         → delta vs the previous scan
  4. the detail           → findings, people, domains, manual checks
  5. show your work       → the score derivation, line by line

Every sentence the report writes itself — section titles, column headers, the
labels around a number — comes from the bilingual catalogue via `i18n.text`, keyed
under `report.*`. Nothing here is an f-string of Spanish prose: the findings were
already translated on the way out, and Spanish scaffolding around English findings
is the same defect one layer out. Counts and their nouns are agreed with
`wording.con_numero` before they reach a template, because a template cannot see
the number — which is how "1 cuenta(s)" got printed.
"""
from __future__ import annotations

import html
import urllib.parse
from datetime import datetime

from . import executive
from .i18n import DEFAULT_LANG, severity_label, status_label, text
from .projection import coverage_line
from .scoring import SEVERITY_WEIGHTS, is_org_scope

_SEVERITY_COLOR = {
    "critical": "#b93a48",
    "high": "#cf6f33",
    "medium": "#b98a1d",
    "low": "#6f8ba0",
    "info": "#8195a6",
}
_STATUS_COLOR = {
    "pass": "#2f8f63",
    "fail": "#b93a48",
    "warn": "#b98a1d",
    "undetermined": "#5c7183",
}
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_STATUS_ORDER = {"fail": 0, "warn": 1, "undetermined": 2, "pass": 3}

_CSS_EXTRA = '''
.contacto { padding-top: 2mm }
.contacto h2 { border: 0; padding: 0 }
.contacto ul { padding-left: 5mm; line-height: 1.55 }
.contacto li { margin-bottom: 2.5mm }
.cta { margin: 5mm 0 2mm; font-size: 13pt; font-weight: 700 }
.cta a { color: #0d1f2d }
.valor { margin: 2mm 0; padding: 1.5mm 2.5mm; background: #f2f5f4;
         border-radius: 1.5mm; font-size: 9.5pt }
.resumen { padding: 4mm 0 0 }
.resumen h1 { font-size: 20pt; margin: 0 0 1mm }
.resumen h2 { font-size: 11pt; margin: 7mm 0 2mm; border: 0; padding: 0 }
.cifras { display: flex; gap: 10mm; margin: 7mm 0 2mm }
.cifra { display: block; font-size: 30pt; font-weight: 700; line-height: 1 }
.pie { display: block; font-size: 8pt; color: #5c7183; text-transform: uppercase;
       letter-spacing: .04em; margin-top: 1.5mm }
.llano { margin: 0; padding-left: 5mm; font-size: 10.5pt; line-height: 1.55 }
.llano li { margin-bottom: 2.5mm }
.cierre { margin-top: 8mm; padding: 3mm 4mm; border-left: 3px solid #f2b63c;
          background: #fdf7e8; font-size: 10.5pt; line-height: 1.5 }
.saltopagina { page-break-after: always }
'''

_CSS = """
@page { size: A4; margin: 15mm 13mm; }
* { box-sizing: border-box; }
/* Severity colour carries half the meaning of this report, and browsers
   drop backgrounds when printing unless told otherwise. */
html, body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       color: #24333e; margin: 0; font-size: 10.5pt; line-height: 1.45; }
h1 { font-size: 19pt; margin: 0 0 1mm; color: #0d1f2d; }
h2 { font-size: 12.5pt; margin: 7mm 0 3mm; color: #0d1f2d;
     border-bottom: 1.5px solid #0d1f2d; padding-bottom: 1.5mm; }
h3 { font-size: 10.5pt; margin: 0 0 1mm; color: #0d1f2d; }
p { margin: 0 0 2mm; }
.muted { color: #5c7183; font-size: 8.5pt; }
.mono { font-family: ui-monospace, "SFMono-Regular", Menlo, monospace; }
header { border-bottom: 3px solid #0d1f2d; padding-bottom: 4mm; }

/* --- headline: counts first, score second (deliberate) --- */
.headline { display: flex; gap: 6mm; align-items: flex-start; margin-top: 4mm; }
.counts { display: flex; gap: 3mm; flex: 1; }
.count { border: 1.5px solid #dde5e3; border-radius: 2mm; padding: 2mm 3mm;
         min-width: 22mm; text-align: center; }
.count .n { font-size: 20pt; font-weight: 700; line-height: 1.05; }
.count .l { font-size: 7pt; text-transform: uppercase; letter-spacing: .5pt;
            color: #5c7183; }
.riskline { margin-top: 3mm; font-size: 11pt; }
.scoreside { text-align: center; border-left: 1px solid #dde5e3; padding-left: 5mm;
             min-width: 30mm; }
.scoreside .n { font-size: 17pt; font-weight: 600; }

/* --- fix this first --- */
.fix { border: 2px solid #0d1f2d; border-radius: 2mm; padding: 3mm 4mm; margin-bottom: 3mm;
       page-break-inside: avoid; }
.fix .rank { font-size: 8pt; font-weight: 700; color: #5c7183; letter-spacing: .6pt; }
.impact { background: #f2f5f4; border-radius: 1.5mm; padding: 2mm 3mm; margin: 2mm 0;
          font-size: 9.5pt; }
.warnbox { border-left: 3px solid #b98a1d; background: #fdf7e7; padding: 2mm 3mm;
           font-size: 9pt; }

/* --- findings --- */
.finding { border: 1px solid #dde5e3; border-left: 4px solid #8195a6;
           border-radius: 1.5mm; padding: 3mm; margin-bottom: 2.5mm;
           page-break-inside: avoid; }
.finding.unverified { border-style: dashed; background: #fafbfb; }
.badge { display: inline-block; color: #fff; font-size: 7pt; font-weight: 700;
         text-transform: uppercase; letter-spacing: .4pt; padding: .5mm 1.6mm;
         border-radius: 1mm; vertical-align: middle; }
.status { font-size: 8.5pt; font-weight: 700; letter-spacing: .3pt; }
.status.unverified { border: 1px dashed #5c7183; padding: .3mm 1.4mm; border-radius: 1mm; }
.flag { background: #0d1f2d; color: #fff; font-size: 7pt; font-weight: 700;
        padding: .5mm 1.6mm; border-radius: 1mm; margin-left: 1.5mm; }
.items { background: #f2f5f4; border-radius: 1.5mm; padding: 2mm 3mm; margin-top: 2mm;
         font-size: 8.5pt; }
.items div { padding: .3mm 0; }

table { width: 100%; border-collapse: collapse; font-size: 8.5pt; }
th, td { text-align: left; padding: 1.3mm 2mm; border-bottom: 1px solid #dde5e3;
         vertical-align: top; }
th { background: #f2f5f4; font-size: 8pt; text-transform: uppercase;
     letter-spacing: .4pt; color: #5c7183; }
tr { page-break-inside: avoid; }
.dom { border: 1px solid #dde5e3; border-radius: 1.5mm; padding: 3mm; margin-bottom: 2.5mm;
       page-break-inside: avoid; }
.rec { background: #0d1f2d; color: #cfdae2; border-radius: 1mm; padding: 1.5mm 2mm;
       font-size: 8pt; word-break: break-all; margin: 1mm 0; }
.manual { border: 1px dashed #77909f; border-radius: 1.5mm; padding: 3mm;
          margin-bottom: 2.5mm; page-break-inside: avoid; }
footer { margin-top: 7mm; border-top: 1px solid #dde5e3; padding-top: 3mm; }
.noprint { background: #f2b63c; color: #0d1f2d; padding: 3mm; border-radius: 2mm;
           margin-bottom: 4mm; font-size: 9.5pt; }
@media print { .noprint { display: none; } }
"""


def _contacto() -> str:
    from .config import load_settings

    try:
        return load_settings().contact_email
    except Exception:  # noqa: BLE001
        return ""


def _retencion() -> int:
    """The configured retention window, never a number written into a template.

    Two templates said "24 h" while the privacy policy read the setting. A
    report that promises a different window from the policy it links to is the
    same defect as the policy contradicting itself, one document further out.
    """
    from .config import load_settings

    try:
        return load_settings().pii_retention_hours
    except Exception:  # noqa: BLE001 — a report must render even without config
        return 24


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _score_color(score: int | None) -> str:
    """From `scoring.SCORE_BANDS`, not from thresholds written again here.

    These four numbers used to live in this function AND in `ScoreGauge.tsx`, and
    they agreed by luck. The panel and the PDF the customer forwards to their
    manager disagreeing about the same score is the failure that consolidation
    prevents.
    """
    from .scoring import SCORE_BAND_COLORS, score_band

    return SCORE_BAND_COLORS[score_band(score)]


def _status_html(status: str, lang: str = DEFAULT_LANG) -> str:
    label = status_label(lang, status).upper()
    extra = " unverified" if status == "undetermined" else ""
    return (
        f'<span class="status{extra}" style="color:{_STATUS_COLOR.get(status, "#5c7183")}">'
        f"{label}</span>"
    )


def _cuenta(lang: str, n: int) -> str:
    """"1 cuenta" / "3 accounts": the count and its noun, agreed, in `lang`.

    The noun never travels inside the template. A template cannot see the number,
    which is how "1 cuenta(s)" got printed 56 times, and a template written with
    the Spanish noun in it cannot be translated at all.
    """
    return con_numero(n, text(lang, "report.cuenta"), text(lang, "report.cuentas"))


def _hallazgo(lang: str, n: int) -> str:
    return con_numero(n, text(lang, "report.hallazgo"), text(lang, "report.hallazgos"))


# ------------------------------------------------------------- sections


def _headline(scan: dict, previous_score: int | None, people: list[dict], lang: str,
              summary: dict | None = None) -> str:
    counts = scan.get("counts", {})
    score = scan.get("score")

    tiles = "".join(
        f'<div class="count" style="border-color:{_SEVERITY_COLOR[sev]}">'
        f'<div class="n" style="color:{_SEVERITY_COLOR[sev]}">{counts.get(sev, 0)}</div>'
        f'<div class="l">{severity_label(lang, sev)}</div></div>'
        for sev in ("critical", "high", "medium", "low")
    )

    worst = [p for p in people if p["worst"] in ("critical", "high")]
    if people:
        risk = (
            "<strong>"
            + text(lang, "report.cuentas_en_riesgo", cuentas=_cuenta(lang, len(people)))
            + "</strong>"
        )
        if worst:
            risk += f", {text(lang, 'report.de_ellas_graves', n=len(worst))}"
        risk += "."
    else:
        risk = f"<strong>{text(lang, 'report.sin_exposicion_de_cuentas')}</strong>"

    # The movement, and then WHY it moved. "sin cambios" on its own was printed
    # over a score that had gone from 33 to 35, because the two numbers were
    # equal for the pair being compared while the customer's own copy of the
    # report said 33. And when they are equal, the honest sentence is "sin
    # cambios en tu organización" — never a bare "sin cambios", which also
    # claims our coverage held still.
    from .projection import score_explanation

    explicacion = score_explanation((summary or {}).get("score_change"), summary, lang)
    delta = ""
    if score is not None and previous_score is not None:
        change = score - previous_score
        if change:
            arrow = "▲" if change > 0 else "▼"
            colour = "#2f8f63" if change > 0 else "#b93a48"
            movimiento = text(lang, "report.delta_anterior", flecha=arrow, n=abs(change))
            delta = f'<div class="muted" style="color:{colour}">{movimiento}</div>'
        elif not explicacion.get("lines"):
            delta = f'<div class="muted">{text(lang, "report.sin_cambios_anterior")}</div>'
        for linea in explicacion.get("lines") or []:
            if linea:
                delta += f'<div class="muted" style="font-size:9pt">{_esc(linea)}</div>'

    return f"""
    <div class="headline">
      <div style="flex:1">
        <div class="counts">{tiles}</div>
        <div class="riskline">{risk}</div>
      </div>
      <div class="scoreside">
        <div class="n" style="color:{_score_color(score)}">{'—' if score is None else score}/100</div>
        <div class="muted">{text(lang, "report.puntuacion_postura")}</div>
        {delta}
      </div>
    </div>"""


def _fix_first(actions: list[dict], lang: str) -> str:
    if not actions:
        return ""
    blocks = []
    for index, action in enumerate(actions, start=1):
        severity_bits = []
        if action["criticals_closed"]:
            severity_bits.append(
                con_numero(
                    action["criticals_closed"],
                    text(lang, "report.critico"),
                    text(lang, "report.criticos"),
                )
            )
        if action["highs_closed"]:
            severity_bits.append(
                con_numero(
                    action["highs_closed"],
                    text(lang, "report.alto"),
                    text(lang, "report.altos"),
                )
            )
        severity_text = f" ({', '.join(severity_bits)})" if severity_bits else ""
        gain = (
            text(lang, "report.ganancia_puntuacion", n=action["score_gain"])
            if action["score_gain"]
            else ""
        )
        impacto = text(
            lang,
            "report.impacto_frase",
            hallazgos=_hallazgo(lang, action["findings_closed"]),
            severidades=severity_text,
            cuentas=_cuenta(lang, action["accounts_affected"]),
            ganancia=gain,
        )
        esfuerzo = text(lang, "report.minutos", n=action["minutes"])
        warning = (
            f'<div class="warnbox"><strong>{text(lang, "report.aviso_usuarios")}:</strong> '
            f'{_esc(action["user_impact"])}</div>'
            if action.get("user_impact")
            else ""
        )
        blocks.append(
            f"""
        <div class="fix">
          <div class="rank">{text(lang, "report.accion_numero", n=index)}</div>
          <h3>{_esc(action['title'])}</h3>
          <div class="muted mono">{_esc(action['console_path'])}</div>
          <div class="impact">
            <strong>{text(lang, "report.impacto")}:</strong> {impacto}
            <br><strong>{text(lang, "report.esfuerzo")}:</strong> {esfuerzo}.
          </div>
          {warning}
        </div>"""
        )
    return (
        f'<h2>{text(lang, "report.arregla_primero")}</h2>'
        f'<p class="muted">{text(lang, "report.arregla_primero_nota")}</p>'
        + "".join(blocks)
    )


def _changes(summary: dict | None, lang: str) -> str:
    # A changed check set makes the two scans incomparable. Printing a table
    # of zeroes over that would be the report's most confident lie: the reader
    # takes "0 new, 0 worse, 0 resolved" as "nothing moved", when what moved
    # was the yardstick.
    if summary and summary.get("engine_changed"):
        desconocido = text(lang, "report.desconocido")
        antes = _esc(summary.get("previous_engine") or desconocido)
        ahora = _esc(summary.get("engine_version") or desconocido)
        return (
            f'<h2>{text(lang, "report.cambios_titulo")}</h2>'
            f'<p class="muted">{text(lang, "report.cambios_motor", antes=antes, ahora=ahora)}</p>'
        )
    if not summary or not summary.get("has_baseline"):
        return (
            f'<h2>{text(lang, "report.cambios_titulo")}</h2>'
            f'<p class="muted">{text(lang, "report.primer_escaneo")}</p>'
        )
    rows = []
    for clave, key in (("nuevos", "new"), ("empeorados", "worse"), ("resueltos", "resolved")):
        entries = summary.get(key) or []
        rows.append(
            f'<tr><td><strong>{text(lang, "report." + clave)}</strong></td>'
            f"<td>{len(entries)}</td>"
            f"<td>{_esc(', '.join(e['title'] for e in entries[:6])) or '—'}</td></tr>"
        )

    # Two tables, not one, and this is the whole point of the rewrite. Everything
    # above is the tenant; everything below is Vigía's own reach. Merging them is
    # how "we can finally read this" was printed as "resolved" and mailed as good
    # news, and how a revoked scope would have been printed as a new problem.
    cobertura = ""
    ganada, perdida = summary.get("coverage_gained") or [], summary.get("coverage_lost") or []
    if ganada or perdida:
        filas = []
        if ganada:
            abiertos = [e for e in ganada if e.get("open")]
            extra = (
                f" ({text(lang, 'report.con_problema_abierto', n=len(abiertos))})"
                if abiertos
                else ""
            )
            filas.append(
                f'<tr><td><strong>{text(lang, "report.antes_no_comprobables")}</strong></td>'
                f"<td>{len(ganada)}{extra}</td>"
                f"<td>{_esc(', '.join(e['title'] for e in ganada[:6]))}</td></tr>"
            )
        if perdida:
            filas.append(
                f'<tr><td><strong>{text(lang, "report.ya_no_comprobables")}</strong></td>'
                f"<td>{len(perdida)}</td>"
                f"<td>{_esc(', '.join(e['title'] for e in perdida[:6]))}</td></tr>"
            )
        cobertura = (
            f'<h2>{text(lang, "report.cobertura_titulo")}</h2>'
            f'<p class="muted">{text(lang, "report.cobertura_nota")}</p>'
            f'<table><tr><th>{text(lang, "report.col_cambio")}</th><th>#</th>'
            f'<th>{text(lang, "report.col_comprobaciones")}</th></tr>'
            + "".join(filas)
            + "</table>"
        )

    return (
        f'<h2>{text(lang, "report.cambios_organizacion")}</h2><table>'
        f'<tr><th>{text(lang, "report.col_cambio")}</th><th>#</th>'
        f'<th>{text(lang, "report.col_hallazgos")}</th></tr>' + "".join(rows) + "</table>"
        + cobertura
    )


def _finding_html(finding: dict, lang: str) -> str:
    severity = finding.get("severity", "info")
    status = finding.get("status", "undetermined")
    unverified = status == "undetermined"

    flags = ""
    if finding.get("change") in ("new", "worse"):
        flags += f'<span class="flag">{text(lang, "report.flag_nuevo")}</span>'
    # Its own badge, and deliberately not the red one: "we can see this now" is
    # not a change in the tenant, and pinning NUEVO on it is what turned a
    # coverage gain into a security event.
    if finding.get("change") == "coverage_gained":
        flags += (
            '<span class="flag" style="background:#6b7c8c">'
            f'{text(lang, "report.flag_ahora_visible")}</span>'
        )
    if finding.get("change") == "coverage_lost":
        flags += (
            '<span class="flag" style="background:#6b7c8c">'
            f'{text(lang, "report.flag_ya_no_comprobable")}</span>'
        )
    if (finding.get("details") or {}).get("regression"):
        flags += (
            '<span class="flag" style="background:#b93a48">'
            f'{text(lang, "report.flag_regresion")}</span>'
        )

    items = finding.get("affected_items") or []
    # A finding whose addresses were purged must not read as "nobody was
    # affected": it says how many there were and that they were deleted.
    purged = (finding.get("details") or {}).get("addresses_purged") or 0
    items_html = ""
    if items:
        rows = "".join(f"<div class='mono'>{_esc(i)}</div>" for i in items[:30])
        extra = (
            f"<div class='muted'>{text(lang, 'report.y_mas', n=len(items) - 30)}</div>"
            if len(items) > 30
            else ""
        )
        items_html = (
            f"<div class='items'><strong>{text(lang, 'report.afectados', n=len(items))}:"
            f"</strong>{rows}{extra}</div>"
        )
    if purged:
        items_html += (
            f"<div class='items'><strong>{text(lang, 'report.afectados', n=purged)}:</strong>"
            f"<div class='muted'>"
            f"{text(lang, 'report.direcciones_borradas', horas=_retencion())}</div></div>"
        )

    # The measured value, given its own line rather than buried in the prose:
    # it is the one part of a settings finding the reader can act on directly.
    valor = (
        f"<div class='valor'><strong>{text(lang, 'report.valor_actual')}:</strong> "
        f"{_esc(finding.get('observed_value'))}</div>"
        if finding.get("observed_value")
        else ""
    )
    # A passing control still carries advice, but "activate it for the whole
    # organization" under a green tick reads as a contradiction and makes the
    # reader think the check failed. Same text, honest framing: this is what
    # keeps it the way it already is.
    remediation = (
        "<p style='margin:2mm 0 0'><strong>"
        + text(
            lang,
            "report.como_mantenerlo" if status == "pass" else "report.como_se_arregla",
        )
        + f":</strong> {_esc(finding.get('remediation'))}</p>"
        if finding.get("remediation")
        else ""
    )
    cis = (
        f"<div class='muted' style='margin-top:1.5mm'>{_esc(finding.get('cis_control'))}</div>"
        if finding.get("cis_control")
        else ""
    )
    # Stating the population removes the apparent contradiction between two
    # similar findings with opposite states.
    scope = (
        f"<div class='muted' style='margin-top:1mm'><strong>{text(lang, 'report.alcance')}:"
        f"</strong> {_esc(finding.get('scope_label'))}"
        + (f" · {_esc(finding.get('coverage_note'))}" if finding.get("coverage_note") else "")
        + "</div>"
        if finding.get("scope_label")
        else ""
    )
    note = (
        '<div class="muted" style="margin-top:1.5mm">'
        f'{text(lang, "report.no_confirmado")}</div>'
        if unverified
        else ""
    )
    return f"""
    <div class="finding{' unverified' if unverified else ''}"
         style="border-left-color:{_SEVERITY_COLOR.get(severity, '#8195a6')}">
      <div>
        <span class="badge" style="background:{_SEVERITY_COLOR.get(severity, '#8195a6')}">{_esc(severity_label(lang, severity))}</span>
        {_status_html(status, lang)}{flags}
      </div>
      <h3 style="margin-top:1.5mm">{_esc(finding.get('title'))}</h3>
      <p>{_esc(finding.get('description'))}</p>
      {scope}
      {valor}{items_html}{remediation}{cis}{note}
    </div>"""


def _people_section(people: list[dict], lang: str) -> str:
    if not people:
        return ""
    rows = "".join(
        f"<tr><td><span class='badge' style='background:{_SEVERITY_COLOR[p['worst']]}'>"
        f"{_esc(severity_label(lang, p['worst']))}</span></td>"
        f"<td class='mono'>{_esc(p['account'])}</td>"
        f"<td>{len(p['issues'])}</td>"
        f"<td>{_esc(' · '.join(i['title'] for i in p['issues']))}</td></tr>"
        for p in people
    )
    stacked = sum(1 for p in people if len(p["issues"]) > 1)
    note = f" {text(lang, 'report.personas_apiladas', n=stacked)}" if stacked else ""
    # Everyone, always: a printed report that silently truncates the list is
    # worse than no list.
    return (
        f'<h2>{text(lang, "report.personas_riesgo", n=len(people))}</h2>'
        f'<p class="muted">{text(lang, "report.personas_orden")}{note}</p>'
        f'<table><tr><th>{text(lang, "report.col_peor")}</th>'
        f'<th>{text(lang, "report.col_cuenta")}</th>'
        f'<th>{text(lang, "report.col_problemas")}</th>'
        f'<th>{text(lang, "report.col_aparece_en")}</th></tr>'
        + rows
        + "</table>"
    )


def _domain_records(scan: dict, domains: list[dict], lang: str) -> str:
    """Per-domain DNS detail pulled out of the email-auth findings, so the
    reader sees the actual records and what exactly fails in them."""
    by_domain: dict[str, dict] = {}
    for finding in scan.get("findings", []):
        for domain, entry in ((finding.get("details") or {}).get("domains") or {}).items():
            if isinstance(entry, dict):
                key = finding["id"].replace("email-", "").replace("mail-", "").replace("dns-", "")
                by_domain.setdefault(domain, {})[key] = entry

    if not by_domain and not domains:
        return ""

    sources = {d["domain"]: d.get("source") for d in domains}
    blocks = []
    for domain in sorted(by_domain) or [d["domain"] for d in domains]:
        checks = by_domain.get(domain, {})
        source = sources.get(domain)
        label = (
            text(lang, "report.dominio_workspace")
            if source == "google"
            else text(lang, "report.dominio_manual")
            if source
            else ""
        )

        rows = []
        spf = checks.get("spf")
        if spf:
            lookups = spf.get("dns_lookups")
            limit_note = ""
            if isinstance(lookups, int):
                over = lookups > 10
                limit_note = "<br>" + text(
                    lang, "report.spf_consultas", n=f"<strong>{lookups}</strong>"
                ) + (
                    f" — <strong>{text(lang, 'report.spf_sobre_limite')}</strong>"
                    if over
                    else ""
                )
            mecanismo = _esc((spf.get("all_qualifier") or "?") + "all")
            rows.append(
                f"<tr><td>SPF</td><td>{_status_html(spf['status'], lang)}</td><td>"
                f"{_esc(spf.get('summary'))}"
                + (f"<div class='rec mono'>{_esc(spf.get('record'))}</div>" if spf.get("record") else "")
                + text(
                    lang,
                    "report.spf_mecanismo_final",
                    mecanismo=f"<strong>{mecanismo}</strong>",
                )
                + limit_note
                + "</td></tr>"
            )
        dkim = checks.get("dkim")
        if dkim:
            bits = dkim.get("key_bits")
            bits_note = ""
            if bits:
                weak = bits < 2048
                bits_note = (
                    "<br>"
                    + text(
                        lang, "report.dkim_tamano_clave", bits=f"<strong>{bits}</strong>"
                    )
                    + " — "
                    + text(
                        lang,
                        "report.dkim_clave_debil" if weak else "report.dkim_clave_adecuada",
                    )
                )
            elif dkim.get("found") is None:
                tried = dkim.get("checked_selectors") or []
                bits_note = (
                    f"<br><em>{text(lang, 'report.no_verificado')}</em> "
                    + text(
                        lang,
                        "report.dkim_selector_no_encontrado",
                        selectores=_esc(", ".join(tried[:6])),
                    )
                )
            rows.append(
                f"<tr><td>DKIM</td><td>{_status_html(dkim['status'], lang)}</td><td>"
                f"{_esc(dkim.get('summary'))}"
                + (
                    f"<div class='rec mono'>selector {_esc(dkim.get('selector'))}: "
                    f"{_esc((dkim.get('record') or '')[:180])}</div>"
                    if dkim.get("record")
                    else ""
                )
                + bits_note
                + "</td></tr>"
            )
        dmarc = checks.get("dmarc")
        if dmarc:
            destination = {
                "own": text(lang, "report.dmarc_destino_propio"),
                "third_party": text(lang, "report.dmarc_destino_tercero"),
                "none": text(lang, "report.dmarc_destino_ninguno"),
            }.get(dmarc.get("rua_destination") or "", text(lang, "report.desconocido"))

            def _alineacion(estricta: bool) -> str:
                clave = "estricta" if estricta else "relajada"
                return f"<strong>{text(lang, 'report.alineacion_' + clave)}</strong>"

            politica = _esc(dmarc.get("policy") or text(lang, "report.sin_definir"))
            rows.append(
                f"<tr><td>DMARC</td><td>{_status_html(dmarc['status'], lang)}</td><td>"
                f"{_esc(dmarc.get('summary'))}"
                + (f"<div class='rec mono'>{_esc(dmarc.get('record'))}</div>" if dmarc.get("record") else "")
                + text(lang, "report.dmarc_politica", p=f"<strong>{politica}</strong>")
                + " · "
                + text(
                    lang,
                    "report.dmarc_alineacion",
                    dkim=_alineacion(dmarc.get("adkim") == "s"),
                    spf=_alineacion(dmarc.get("aspf") == "s"),
                )
                + "<br>"
                + text(
                    lang,
                    "report.dmarc_informes_van_a",
                    destino=f"<strong>{destination}</strong>",
                )
                + "</td></tr>"
            )
        for key, name in (("mta_sts", "MTA-STS"), ("tls_rpt", "TLS-RPT"), ("dnssec", "DNSSEC")):
            entry = checks.get(key)
            if entry:
                rows.append(
                    f"<tr><td>{name}</td><td>{_status_html(entry['status'], lang)}</td>"
                    f"<td>{_esc(entry.get('summary'))}</td></tr>"
                )

        if rows:
            blocks.append(
                f"<div class='dom'><h3 class='mono'>{_esc(domain)}</h3>"
                f"<div class='muted' style='margin-bottom:2mm'>{_esc(label)}</div>"
                f"<table><tr><th>{text(lang, 'report.col_comprobacion')}</th>"
                f"<th>{text(lang, 'report.col_estado')}</th>"
                f"<th>{text(lang, 'report.col_detalle')}</th></tr>"
                + "".join(rows)
                + "</table></div>"
            )

    if not blocks:
        return ""
    return f'<h2>{text(lang, "report.registros_correo_dns")}</h2>' + "".join(blocks)


def _breakdown_section(breakdown: dict | None, lang: str) -> str:
    if not breakdown:
        return ""
    account_rows = "".join(
        f"<tr><td class='mono'>{_esc(row['account'])}</td>"
        f"<td>{_esc(severity_label(lang, row['severity']))}</td>"
        f"<td>{_esc(status_label(lang, row['status']).lower())}</td>"
        f"<td>{row['weight']}</td><td>{row['earned']:.1f}</td>"
        f"<td class='muted'>{_esc(row['finding_id'])}"
        + (
            f" {text(lang, 'report.tambien_en', n=len(row['also_in']))}"
            if row["also_in"]
            else ""
        )
        + "</td></tr>"
        for row in breakdown["accounts"]
    )
    finding_rows = "".join(
        f"<tr><td>{_esc(row['title'] or row['id'])}</td>"
        f"<td>{_esc(severity_label(lang, row['severity']))}</td>"
        f"<td>{_esc(status_label(lang, row['status']).lower())}</td><td>{row['weight']}</td>"
        f"<td>{row['earned']:.1f}</td><td class='muted'>{_esc(row['id'])}</td></tr>"
        for row in breakdown["findings"]
    )
    excluded = "".join(
        f"<tr><td>{_esc(row['id'])}</td>"
        f"<td>{_esc(severity_label(lang, row['severity']))}</td>"
        f"<td>{_esc(status_label(lang, row['status']).lower())}</td>"
        f"<td colspan='3' class='muted'>{_esc(row['reason'])}</td></tr>"
        for row in breakdown["excluded"]
    )
    weights = ", ".join(f"{sev} {w}" for sev, w in breakdown["weights"].items() if w)
    # Only mentioned when it actually bit: explaining a cap that did nothing
    # is noise in a document the customer is asked to audit.
    escala = ""
    if breakdown.get("people_scale", 1) < 1:
        escala = " " + text(
            lang,
            "report.escala_cuentas",
            porcentaje=f"{breakdown['people_scale']:.0%}",
        )
    puntuacion = breakdown["score"] if breakdown["score"] is not None else "—"
    return f"""
    <h2>{text(lang, "report.puntuacion_calculo")}</h2>
    <p class="muted">{text(lang, "report.pesos_y_credito", pesos=weights)}</p>
    <ul class="muted">
      <li>{text(lang, "report.bloque_ajustes")}</li>
      <li>{text(lang, "report.bloque_cuentas")}{escala}</li>
    </ul>
    <p class="muted">{text(lang, "report.excluidos_de_la_puntuacion")}</p>
    <table>
      <tr><th>{text(lang, "report.col_elemento")}</th>
          <th>{text(lang, "report.col_severidad")}</th>
          <th>{text(lang, "report.col_estado")}</th>
          <th>{text(lang, "report.col_peso")}</th>
          <th>{text(lang, "report.col_obtenido")}</th>
          <th>{text(lang, "report.col_de")}</th></tr>
      {account_rows}{finding_rows}
      <tr><th>{text(lang, "report.total")}</th><th></th><th></th>
          <th>{breakdown['total_weight']}</th>
          <th>{breakdown['earned_weight']:.1f}</th>
          <th>{text(lang, "report.puntuacion_sobre_cien", n=puntuacion)}</th></tr>
      {excluded}
    </table>"""


def _incoherencia_html(scan: dict) -> str:
    """The coherence diagnostic, in the printed report too.

    The comment at the dashboard route says "a contradiction must never reach a
    reader, not even from the archive". It reached the dashboard and stopped
    there: the PDF and the CSV were silent about the same stored row.
    """
    for finding in scan.get("findings") or []:
        if finding.get("id") == "internal-consistency":
            return (
                "<div style='border-left:3px solid #b93a48;background:#fdf0f1;"
                "padding:3mm 4mm;margin:4mm 0'><strong>"
                f"{_esc(finding.get('title'))}</strong><p class='muted'>"
                f"{_esc(finding.get('description'))}</p></div>"
            )
    return ""



# The read-only claim and the link back to the site live in one module so the
# report, the two privacy pages and the React landing cannot drift apart. They
# already had four different wordings of the same promise.
from .wording import (  # noqa: E402  — placed next to its only users
    READ_ONLY_CLAIM,
    READ_ONLY_LEAD,
    SCAN_DID_NOT_MODIFY,
    con_numero,
    site_link,
)


def _contacto_html(org: dict, scan: dict, contacto: str, lang: str) -> str:
    """The one place in the report where the reader can answer it.

    The business is free report → paid remediation, and until now the document
    ended with a score and no way to reply to it. No prices: the number depends
    on what the report found and that conversation belongs in an e-mail, not in
    a PDF the reader may be forwarding to somebody else.
    """
    # The follow-up sentence is worded as MY commitment, not the tool's. It used to
    # read "seguimiento mensual: el escaneo se repite solo y os aviso cuando algo
    # cambia", which described the recurring-scan feature — and that feature came
    # off the panel, so the sentence was selling something the product no longer
    # does. It was not only the word "mensual": "el escaneo se repite solo" is the
    # same promise in other words, which is why the sweep looked for the promise
    # rather than the word.
    #
    # This explanation lives in Python and not in an HTML comment: the first
    # attempt put it inside the returned markup, where it shipped to the customer
    # in a document they may forward. `test_the_report_ends_with_a_way_to_reply`
    # caught it, by asserting the word is absent from the rendered HTML.
    if not contacto:
        return ""
    dominio = str(org.get("primary_domain") or "")
    score = scan.get("score")
    asunto = text(lang, "report.correo_asunto", dominio=dominio)
    cuerpo = text(
        lang,
        "report.correo_cuerpo",
        dominio=dominio,
        puntuacion=(
            text(lang, "report.correo_puntuacion", n=score) if score is not None else ""
        ),
    )
    enlace = (
        f"mailto:{contacto}"
        f"?subject={urllib.parse.quote(asunto)}&body={urllib.parse.quote(cuerpo)}"
    )
    return f"""
<div class="saltopagina"></div>
<section class="contacto">
  <h2>{text(lang, "report.arreglamos_titulo")}</h2>
  <p>{text(lang, "report.arreglamos_intro")}</p>
  <ul>
    <li>{text(lang, "report.arreglamos_auditoria")}</li>
    <li>{text(lang, "report.arreglamos_criticos")}</li>
    <li>{text(lang, "report.arreglamos_sesion")}</li>
    <li>{text(lang, "report.arreglamos_documentacion")}</li>
  </ul>
  <p>{text(lang, "report.arreglamos_repeticion")}</p>
  <p class="cta"><a href="{enlace}">{_esc(contacto)}</a></p>
  <p class="muted">{text(lang, "report.arreglamos_precio")}</p>
</section>
"""


def _cobertura_html(scan: dict, lang: str) -> str:
    """What was read, and what was not — in the report, not just in the logs.

    A verdict without its provenance is the thing this whole exercise exists to
    stop. If a source came back short the line says so here, next to the score,
    instead of the reader having to notice that some cards say "no verificado".
    """
    resultado = scan.get("result") or {}
    linea = coverage_line(resultado, lang)
    if not linea:
        return ""
    # Read off the coverage data, not off the sentence. This used to grep the line
    # for "LEÍDO A MEDIAS", so the amber highlight was tied to one language's
    # wording of it — and the moment the phrase was translated (or reworded, which
    # already happened once) the report would stop flagging a short read at all.
    corta = any(
        isinstance(entrada, dict) and not entrada.get("complete", True)
        for entrada in (resultado.get("coverage") or {}).values()
    )
    estilo = (
        "border-left:3px solid #f2b63c;background:#fdf7e8"
        if corta
        else "border-left:3px solid #dde5e3;background:#f2f5f4"
    )
    return (
        f"<div class='muted' style='{estilo};padding:2mm 3mm;margin-top:3mm'>"
        f"<strong>{text(lang, 'report.datos_analizados')}:</strong> {_esc(linea)}</div>"
    )


def _executive_page(
    scan: dict, people: list[dict], actions: list[dict], org: dict, lang: str
) -> str:
    """The one page a stranger reads. Deliberately nothing else on it."""
    resumen = executive.summary(
        scan.get("findings", []), people, scan.get("score"), actions, lang
    )
    score = resumen["score"]

    titulares = "".join(
        f'<li><span class="sev sev-{_esc(h["severity"])}">'
        f'{_esc(severity_label(lang, h["severity"]))}</span> {_esc(h["sentence"])}</li>'
        for h in resumen["headlines"]
    ) or f'<li>{text(lang, "report.sin_problemas_abiertos")}</li>'

    acciones = "".join(
        f"<li><strong>{_esc(a['title'])}</strong>"
        + (
            f" — {text(lang, 'report.minutos', n=a['minutes'])}"
            if a.get("minutes")
            else ""
        )
        + (
            f", {text(lang, 'report.cierra_hallazgos', hallazgos=_hallazgo(lang, a['findings_closed']))}"
            if a.get("findings_closed")
            else ""
        )
        + "</li>"
        for a in resumen["actions"]
    ) or f'<li>{text(lang, "report.nada_pendiente")}</li>'

    return f"""
<section class="resumen">
  <h1>{text(lang, "report.resumen_direccion")}</h1>
  <p class="muted">{_esc(org.get('primary_domain'))} · {text(lang, "report.resumen_lead")}</p>

  <div class="cifras">
    <div><span class="cifra" style="color:{_score_color(score)}">{score if score is not None
      else '—'}</span><span class="pie">{text(lang, "report.puntuacion_sobre_100")}</span></div>
    <div><span class="cifra">{resumen['people_at_risk']}</span>
      <span class="pie">{text(lang, "report.cuentas_realmente_en_riesgo")}</span></div>
    <div><span class="cifra">{resumen['critical']}</span>
      <span class="pie">{_esc(resumen['critical_label'])}</span></div>
  </div>

  <h2>{text(lang, "report.lo_mas_grave")}</h2>
  <ul class="llano">{titulares}</ul>

  <h2>{text(lang, "report.por_donde_empezar")}</h2>
  <ol class="llano">{acciones}</ol>

  <p class="cierre">{_esc(resumen['closing'])}</p>
</section>
<div class="saltopagina"></div>
"""


def build_html_report(
    org: dict,
    scan: dict,
    previous_score: int | None,
    summary: dict | None,
    domains: list[dict],
    actions: list[dict] | None = None,
    breakdown: dict | None = None,
    people: list[dict] | None = None,
    lang: str = DEFAULT_LANG,
) -> str:
    def _orden(f):
        return (
            _STATUS_ORDER.get(f.get("status"), 9),
            _SEVERITY_ORDER.index(f["severity"]) if f.get("severity") in _SEVERITY_ORDER else 9,
        )

    findings = sorted(scan.get("findings", []), key=_orden)
    # Two questions, two sections. "What has this organization configured
    # badly" and "who in it is exposed" call for different people and
    # different fixes, and mixing them is what made a console toggle look
    # like seventeen personal failures.
    ajustes = [f for f in findings if is_org_scope(f)]
    cuentas = [f for f in findings if not is_org_scope(f)]
    scanned_at = scan.get("created_at", "")
    # The engine fingerprint travels with the report: it is how a reader tells
    # "the posture got worse" from "the set of checks changed".
    engine = scan.get("engine_version") or ""
    motor = f" · {text(lang, 'report.motor', version=_esc(engine))}" if engine else ""
    # Carries the language: this PDF gets forwarded from the technician to the
    # manager, so the link back is what turns a forward into a visit — and
    # somebody sent a Spanish report should not land on an English page.
    enlace_web = site_link(lang)
    try:
        scanned_at = datetime.fromisoformat(scanned_at).strftime("%d %b %Y, %H:%M UTC")
    except (TypeError, ValueError):
        pass

    manual_html = "".join(
        f"""<div class="manual">
              <div class="muted">{text(lang, "report.comprobacion_manual")} · {_esc(m.get('area'))}</div>
              <h3>{_esc(m.get('title'))}</h3>
              <p>{_esc(m.get('why_manual'))}</p>
              <ol style="margin:0; padding-left:5mm">
                {''.join(f'<li>{_esc(step)}</li>' for step in m.get('instructions', []))}
              </ol>
            </div>"""
        for m in scan.get("manual_checks", [])
    )
    manual_section = (
        "<h2>"
        + text(
            lang, "report.comprobaciones_manuales", n=len(scan.get("manual_checks", []))
        )
        + "</h2>"
        f'<p class="muted">{text(lang, "report.comprobaciones_manuales_nota")}</p>'
        + manual_html
        if scan.get("manual_checks")
        else ""
    )

    dominio = _esc(org.get("primary_domain"))
    return f"""<!doctype html>
<html lang="{_esc(lang)}"><head><meta charset="utf-8">
<title>{text(lang, "report.titulo_documento", dominio=dominio)}</title>
<style>{_CSS}{_CSS_EXTRA}</style></head>
<body>
<div class="noprint">
  {text(lang, "report.guardar_pdf")}
</div>

{_executive_page(scan, people or [], actions or [], org, lang)}

<header>
  <h1>{text(lang, "report.informe_postura")}</h1>
  <div class="mono">{dominio}</div>
  <div class="muted">{text(lang, "report.escaneado_el", fecha=_esc(scanned_at))}</div>
  {_headline(scan, previous_score, people or [], lang, summary)}
  {_cobertura_html(scan, lang)}
</header>

{_fix_first(actions or [], lang)}
{_changes(summary, lang)}

{_incoherencia_html(scan)}
<h2>{text(lang, "report.ajustes_organizacion", n=len(ajustes))}</h2>
<p class="muted">{text(lang, "report.ajustes_organizacion_nota")}</p>
{''.join(_finding_html(f, lang) for f in ajustes)}

<h2>{text(lang, "report.hallazgos_por_cuenta", n=len(cuentas))}</h2>
<p class="muted">{text(lang, "report.hallazgos_por_cuenta_nota")}</p>
{''.join(_finding_html(f, lang) for f in cuentas)}

{_people_section(people or [], lang)}
{_domain_records(scan, domains, lang)}
{manual_section}
{_breakdown_section(breakdown, lang)}
{_contacto_html(org, scan, _contacto(), lang)}

<footer class="muted">
  <p><strong>{READ_ONLY_LEAD}</strong> {READ_ONLY_CLAIM} {SCAN_DID_NOT_MODIFY}</p>
  <p>{text(lang, "report.generado_por")}{motor} ·
    <a href="{enlace_web}">diegofarina.com</a></p>
</footer>
</body></html>"""


def findings_csv_rows(scan: dict, lang: str = DEFAULT_LANG) -> list[list[str]]:
    """Flat CSV: one row per finding, affected items joined.

    The column names come from the catalogue too. A spreadsheet's heading row is
    read by the same customer who reads the PDF, so an English report that exports
    "severidad" is the same defect as an English report with a Spanish heading.
    """
    from .projection import change_label

    rows = [
        [
            text(lang, f"report.csv.{columna}")
            for columna in (
                "id",
                "titulo",
                "severidad",
                "estado",
                "alcance",
                "ventana_leida",
                "cambio",
                "regresion",
                "num_afectados",
                "afectados",
                "cuentas",
                "control_cis",
                "remediacion",
            )
        ]
    ]
    for finding in scan.get("findings", []):
        items = finding.get("affected_items") or []
        # Same rule as the PDF: a purged finding reports the real count and
        # says why the names are missing, instead of exporting a silent zero.
        purged = (finding.get("details") or {}).get("addresses_purged") or 0
        marker = (
            text(lang, "report.csv_direcciones_borradas", horas=_retencion())
            if purged
            else ""
        )
        rows.append(
            [
                finding.get("id", ""),
                finding.get("title", ""),
                finding.get("severity", ""),
                finding.get("status", ""),
                finding.get("scope_label", ""),
                # The measured window as its own column: it is data, and the
                # translation catalogue would have eaten it inside `alcance`.
                finding.get("coverage_note", ""),
                # Was exporting the raw English enum ("same", "coverage_gained")
                # into a client deliverable. One wording, shared with the PDF,
                # the panel and the e-mail.
                change_label(finding, lang),
                "yes" if (finding.get("details") or {}).get("regression") else "",
                str(len(items) + purged),
                " | ".join(items) or marker,
                " | ".join(finding.get("accounts") or []) or marker,
                finding.get("cis_control", ""),
                finding.get("remediation", ""),
            ]
        )
    return rows
