"""The review console. Tailnet only.

Server-rendered HTML, no SPA, no build step. Rows expand with `<details>` rather
than JavaScript, so the table works with scripting off; the only script in the
whole console is the keyboard handler, which is a convenience and not a
dependency.

**Nothing here sends anything on its own.** `/enviar` starts a run of *approved*
messages, and approval is a separate act by a person. There is no route, no flag
and no background job that turns a scan into an email without somebody pressing
approve first.

The long jobs (scanning, sending) run in a background thread with their progress
in memory, and the progress page refreshes itself with `<meta http-equiv>`. A
single operator on a tailnet does not need websockets, and in-memory state that
dies with the process is the right trade: a scan can always be re-run, and a
resumable job would be a second source of truth about what has been scanned.
"""
from __future__ import annotations

import csv
import io
import logging
import threading
from dataclasses import dataclass, field
from typing import Any

from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from .config import Settings, load_settings
from .db import connect, init, is_suppressed
from .metrics import build_report, record_reply, to_csv
from .pipeline import import_domains, scan_batch
from .projection import finding_from_scan, raw_findings
from .queue import (
    BLOCK_REASONS,
    approve,
    edit_send,
    queue_batch,
    skip,
    suppress_prospect,
)
from .scanner import VigiaScanner, scanner_disponible
from .sender import SmtpTransport, daily_allowance, remaining_today, run_queue, sent_today
from .signals import HttpSignals
from .templates import RenderError, build_email, lang_for_country, seed_templates

log = logging.getLogger("prospector.app")


@dataclass
class Job:
    """A long job's progress, held in memory for the one operator watching it."""

    name: str = ""
    done: int = 0
    total: int = 0
    running: bool = False
    lines: list[str] = field(default_factory=list)

    @property
    def percent(self) -> int:
        return int(100 * self.done / self.total) if self.total else 0


JOB = Job()
_LOCK = threading.Lock()


def _sender_details(settings: Settings) -> str:
    s = settings.sender
    return f"{s.name} · NIF/CIF {s.company_number} · {s.postal_address}"


def create_app(settings: Settings | None = None) -> Flask:
    settings = settings or load_settings()
    settings.validate()

    app = Flask(__name__)
    app.secret_key = "prospector-tailnet-only"  # noqa: S105 — no auth, no sessions of value
    app.config["SETTINGS"] = settings
    init(settings.db_path).close()

    conexion = connect(settings.db_path)
    seed_templates(conexion)
    conexion.close()

    def db():
        return connect(settings.db_path)

    # ---------------------------------------------------------------- panel

    @app.get("/")
    def panel() -> str:
        conn = db()
        try:
            def n(sql: str, *args) -> int:
                return int(conn.execute(sql, args).fetchone()[0])

            datos = {
                "prospectos": n("SELECT COUNT(*) FROM prospects"),
                "sin_escanear": n("SELECT COUNT(*) FROM prospects WHERE status='new'"),
                "calificados": n("SELECT COUNT(*) FROM prospects WHERE qualified=1"),
                "en_cola": n("SELECT COUNT(*) FROM sends WHERE status='queued'"),
                "aprobados": n("SELECT COUNT(*) FROM sends WHERE status='approved'"),
                "enviados": n("SELECT COUNT(*) FROM sends WHERE status='sent'"),
                "bloqueados": n("SELECT COUNT(*) FROM sends WHERE status='blocked'"),
                "supresiones": n("SELECT COUNT(*) FROM suppressions"),
                "hoy": sent_today(conn),
                "cupo": daily_allowance(settings, conn),
                "restantes": remaining_today(settings, conn),
            }
            disponible, motivo = scanner_disponible()
            return render_template("panel.html", d=datos, job=JOB, s=settings,
                                   escaner_ok=disponible, escaner_motivo=motivo)
        finally:
            conn.close()

    # ---------------------------------------------------------------- import

    @app.get("/importar")
    def importar_form() -> str:
        return render_template("importar.html")

    @app.post("/importar")
    def importar() -> Response:
        filas: list[dict[str, str]] = []
        fichero = request.files.get("csv")
        if fichero and fichero.filename:
            texto = fichero.read().decode("utf-8", "replace")
            filas.extend(csv.DictReader(io.StringIO(texto)))
        pegado = (request.form.get("pegado") or "").strip()
        for linea in pegado.splitlines():
            # "dominio, correo, empresa, país, sector" — everything but the first
            # optional, because the common case is a bare list of domains.
            partes = [p.strip() for p in linea.replace("\t", ",").split(",")]
            if partes and partes[0]:
                filas.append(dict(zip(
                    ("domain", "email", "company_name", "country", "sector"), partes
                )))
        conn = db()
        try:
            prospectos, contactos = import_domains(conn, filas, source="consola")
        finally:
            conn.close()
        flash(f"Importados {prospectos} dominios y {contactos} direcciones.", "ok")
        return redirect(url_for("panel"))

    # ---------------------------------------------------------------- one domain

    @app.get("/analizar")
    def analizar_form() -> str:
        disponible, motivo = scanner_disponible()
        return render_template("analizar.html", r=None, disponible=disponible,
                               motivo=motivo, datos={})

    @app.post("/analizar")
    def analizar() -> str:
        """Scan one domain live and show everything, without saving anything.

        Read-only by default: analysing costs a DNS query and a page fetch, both of
        public data, so it should not require a decision. Saving the prospect is a
        separate tick-box, because adding to the list is the decision.
        """
        from .prioritise import select_primary_finding
        from .qualify import score_prospect

        datos = {
            "domain": (request.form.get("domain") or "").strip().lower().rstrip("/"),
            "company_name": (request.form.get("company_name") or "").strip(),
            "country": (request.form.get("country") or "ES").strip().upper(),
            "sector": (request.form.get("sector") or "").strip(),
            "email": (request.form.get("email") or "").strip(),
        }
        # Tolerate a pasted URL or an address: what is wanted is the domain.
        dominio = datos["domain"].split("//")[-1].split("/")[0].split("@")[-1]
        datos["domain"] = dominio

        disponible, motivo = scanner_disponible()
        if not dominio:
            flash("Escribe un dominio.", "error")
            return render_template("analizar.html", r=None, disponible=disponible,
                                   motivo=motivo, datos=datos)
        if not disponible:
            return render_template("analizar.html", r=None, disponible=False,
                                   motivo=motivo, datos=datos)

        informe = VigiaScanner().check(dominio)
        observacion = HttpSignals().observe(dominio)
        lang = lang_for_country(datos["country"])
        hallazgo = select_primary_finding(informe, lang=lang)
        puntuacion = score_prospect(informe, observacion, sector=datos["sector"] or None,
                                    domain=dominio, threshold=settings.min_commercial_score)

        # The preview the brief asks for: the actual letter, rendered, without
        # queueing it. The token is a visible stand-in — a preview must not be
        # confusable with something that could be sent.
        carta = None
        error_carta = None
        if hallazgo is not None:
            conn = db()
            try:
                carta = build_email(
                    conn, finding=hallazgo,
                    prospect={"domain": dominio, "company_name": datos["company_name"],
                              "country": datos["country"]},
                    sender_name=settings.sender.name,
                    sender_details=_sender_details(settings),
                    unsubscribe_url=f"{settings.unsubscribe_base_url.rstrip('/')}/VISTA-PREVIA",
                )
            except RenderError as exc:
                error_carta = str(exc)
            finally:
                conn.close()

        guardado = None
        if request.form.get("guardar") == "1":
            conn = db()
            try:
                if is_suppressed(conn, domain=dominio):
                    guardado = "suprimido"
                else:
                    import_domains(conn, [datos], source="analisis puntual")
                    fila = conn.execute(
                        "SELECT * FROM prospects WHERE domain = ?", (dominio,)).fetchone()
                    from .db import record_qualification, record_scan

                    record_scan(conn, fila["id"], informe, hallazgo)
                    record_qualification(conn, fila["id"], puntuacion)
                    guardado = "ok"
            finally:
                conn.close()

        return render_template(
            "analizar.html", r={
                "dominio": dominio, "informe": informe, "hallazgo": hallazgo,
                "puntuacion": puntuacion, "sitio": observacion, "carta": carta,
                "error_carta": error_carta, "guardado": guardado,
                "mecanismos": ("spf", "dkim", "dmarc", "mta_sts", "tls_rpt", "dnssec"),
            }, disponible=True, motivo="", datos=datos)

    # ---------------------------------------------------------------- scan

    @app.post("/escanear")
    def escanear() -> Response:
        with _LOCK:
            if JOB.running:
                flash("Ya hay un trabajo en marcha.", "aviso")
                return redirect(url_for("progreso"))
            JOB.name, JOB.done, JOB.total = "Escaneo", 0, 0
            JOB.running, JOB.lines = True, []

        solo_nuevos = request.form.get("todos") != "1"

        def trabajo() -> None:
            conn = connect(settings.db_path)
            try:
                escaner = VigiaScanner()
                señales = HttpSignals()

                def progreso(hecho: int, total: int, resultado) -> None:
                    JOB.done, JOB.total = hecho, total
                    JOB.lines.append(f"{resultado.domain} — {resultado.summary}")
                    del JOB.lines[:-200]

                scan_batch(conn, escaner, señales, threshold=settings.min_commercial_score,
                           only_new=solo_nuevos, progress=progreso)
            except Exception as exc:  # noqa: BLE001
                log.exception("escaneo fallido")
                JOB.lines.append(f"ERROR: {exc}")
            finally:
                conn.close()
                JOB.running = False

        threading.Thread(target=trabajo, daemon=True).start()
        return redirect(url_for("progreso"))

    @app.get("/progreso")
    def progreso() -> str:
        return render_template("progreso.html", job=JOB)

    # ---------------------------------------------------------------- queue

    @app.post("/cola")
    def construir_cola() -> Response:
        conn = db()
        try:
            filas = list(conn.execute(
                "SELECT * FROM prospects WHERE status = 'scanned' ORDER BY "
                "commercial_score DESC, domain"
            ))
            resultados = queue_batch(
                conn, filas,
                sender_name=settings.sender.name,
                sender_details=_sender_details(settings),
                unsubscribe_base_url=settings.unsubscribe_base_url,
            )
        finally:
            conn.close()
        encolados = sum(1 for r in resultados if r.queued)
        flash(
            f"{encolados} en cola para revisar · {len(resultados) - encolados} bloqueados, "
            f"con su motivo.", "ok",
        )
        return redirect(url_for("revisar"))

    @app.get("/revisar")
    def revisar() -> str:
        orden = request.args.get("orden", "severidad")
        filtro = (request.args.get("q") or "").strip().lower()
        hallazgo = request.args.get("hallazgo") or ""

        columnas = {
            "severidad": "sc.severity ASC, p.commercial_score DESC",
            "puntuacion": "p.commercial_score DESC",
            "dominio": "p.domain ASC",
            "hallazgo": "sc.primary_finding_code ASC",
        }
        sql = (
            "SELECT s.id, s.subject, s.body, s.queued_at, c.email, p.domain, "
            "p.company_name, p.country, p.commercial_score, p.score_breakdown, "
            "sc.primary_finding_code, sc.severity, sc.raw_findings, sc.id AS scan_id, "
            "t.variant "
            "FROM sends s JOIN contacts c ON c.id = s.contact_id "
            "JOIN prospects p ON p.id = c.prospect_id "
            "JOIN scans sc ON sc.id = s.scan_id "
            "LEFT JOIN templates t ON t.id = s.template_id "
            "WHERE s.status = 'queued' "
        )
        args: list[Any] = []
        if filtro:
            sql += "AND (p.domain LIKE ? OR p.company_name LIKE ?) "
            args += [f"%{filtro}%", f"%{filtro}%"]
        if hallazgo:
            sql += "AND sc.primary_finding_code = ? "
            args.append(hallazgo)
        sql += "ORDER BY " + columnas.get(orden, columnas["severidad"])

        conn = db()
        try:
            filas = list(conn.execute(sql, args))
            hallazgos = [
                r["primary_finding_code"] for r in conn.execute(
                    "SELECT DISTINCT sc.primary_finding_code FROM sends s "
                    "JOIN scans sc ON sc.id = s.scan_id WHERE s.status='queued' "
                    "AND sc.primary_finding_code IS NOT NULL ORDER BY 1"
                )
            ]
            return render_template(
                "revisar.html", filas=filas, hallazgos=hallazgos, orden=orden,
                q=filtro, hallazgo=hallazgo, raw=raw_findings,
            )
        finally:
            conn.close()

    @app.post("/envio/<int:send_id>/<accion>")
    def accion_envio(send_id: int, accion: str) -> Response:
        conn = db()
        try:
            if accion == "aprobar":
                approve(conn, [send_id])
                flash("Aprobado. Todavía no se ha enviado.", "ok")
            elif accion == "saltar":
                skip(conn, send_id, request.form.get("motivo", ""))
                flash("Saltado.", "ok")
            elif accion == "editar":
                try:
                    edit_send(conn, send_id, request.form.get("asunto", ""),
                              request.form.get("cuerpo", ""))
                    flash("Guardado.", "ok")
                except RenderError as exc:
                    flash(str(exc), "error")
            elif accion == "suprimir":
                fila = conn.execute(
                    "SELECT p.id FROM sends s JOIN contacts c ON c.id=s.contact_id "
                    "JOIN prospects p ON p.id=c.prospect_id WHERE s.id=?", (send_id,)
                ).fetchone()
                if fila:
                    suppress_prospect(conn, int(fila["id"]), "suprimido desde la consola")
                    flash("Suprimido para siempre. No se le volverá a escribir.", "ok")
        finally:
            conn.close()
        return redirect(request.referrer or url_for("revisar"))

    @app.post("/revisar/aprobar")
    def aprobar_lote() -> Response:
        ids = [int(i) for i in request.form.getlist("envio")]
        conn = db()
        try:
            movidos = approve(conn, ids)
        finally:
            conn.close()
        flash(f"{movidos} aprobados. Siguen sin enviarse hasta que lances la tanda.", "ok")
        return redirect(url_for("revisar"))

    # ---------------------------------------------------------------- blocked

    @app.get("/bloqueados")
    def bloqueados() -> str:
        conn = db()
        try:
            envios = list(conn.execute(
                "SELECT s.id, s.blocked_reason, s.subject, c.email, p.domain "
                "FROM sends s JOIN contacts c ON c.id=s.contact_id "
                "JOIN prospects p ON p.id=c.prospect_id "
                "WHERE s.status IN ('blocked','skipped','failed') ORDER BY s.id DESC"
            ))
            # Prospects that never produced a draft at all: the reason has to be
            # re-derived, because there is no row to hang it on.
            sin_borrador = list(conn.execute(
                "SELECT p.*, sc.primary_finding_code, "
                "(SELECT COUNT(*) FROM contacts c2 WHERE c2.prospect_id=p.id "
                " AND c2.is_valid=1) AS validos, "
                "(SELECT COUNT(*) FROM contacts c3 WHERE c3.prospect_id=p.id) AS totales "
                "FROM prospects p LEFT JOIN scans sc ON sc.id = "
                "(SELECT MAX(id) FROM scans WHERE prospect_id=p.id) "
                "WHERE p.id NOT IN (SELECT c.prospect_id FROM sends s "
                "JOIN contacts c ON c.id=s.contact_id) ORDER BY p.domain"
            ))
            motivos = {}
            for p in sin_borrador:
                if p["status"] == "new":
                    motivos[p["id"]] = "not-scanned"
                elif not p["primary_finding_code"]:
                    motivos[p["id"]] = "clean"
                elif is_suppressed(conn, domain=p["domain"]):
                    motivos[p["id"]] = "suppressed"
                elif not p["validos"]:
                    motivos[p["id"]] = "no-contact"
                elif not p["qualified"]:
                    motivos[p["id"]] = "unqualified"
                else:
                    motivos[p["id"]] = "no-finding-record"
            return render_template(
                "bloqueados.html", envios=envios, prospectos=sin_borrador,
                motivos=motivos, textos=BLOCK_REASONS,
            )
        finally:
            conn.close()

    # ---------------------------------------------------------------- send

    @app.post("/enviar")
    def enviar() -> Response:
        with _LOCK:
            if JOB.running:
                flash("Ya hay un trabajo en marcha.", "aviso")
                return redirect(url_for("progreso"))
            JOB.name, JOB.done, JOB.total = "Envío", 0, 0
            JOB.running, JOB.lines = True, []

        def trabajo() -> None:
            conn = connect(settings.db_path)
            try:
                pendientes = remaining_today(settings, conn)
                JOB.total = pendientes

                def progreso(resultado) -> None:
                    JOB.done += 1
                    estado = ("enviado" if resultado.sent
                              else f"BLOQUEADO: {resultado.blocked}" if resultado.blocked
                              else f"fallo: {resultado.error}")
                    JOB.lines.append(f"#{resultado.send_id} — {estado}")

                run_queue(conn, settings, SmtpTransport(settings), progress=progreso)
            except Exception as exc:  # noqa: BLE001
                log.exception("tanda de envío fallida")
                JOB.lines.append(f"ERROR: {exc}")
            finally:
                conn.close()
                JOB.running = False

        threading.Thread(target=trabajo, daemon=True).start()
        return redirect(url_for("progreso"))

    # ---------------------------------------------------------------- metrics

    @app.get("/metricas")
    def metricas() -> str:
        conn = db()
        try:
            informe = build_report(conn)
            enviados = list(conn.execute(
                "SELECT s.id, s.subject, s.sent_at, c.email, p.domain, "
                "sc.primary_finding_code, "
                "(SELECT classification FROM replies WHERE send_id=s.id ORDER BY id DESC "
                " LIMIT 1) AS respuesta "
                "FROM sends s JOIN contacts c ON c.id=s.contact_id "
                "JOIN prospects p ON p.id=c.prospect_id "
                "JOIN scans sc ON sc.id=s.scan_id "
                "WHERE s.status='sent' ORDER BY s.sent_at DESC LIMIT 300"
            ))
            return render_template("metricas.html", r=informe, enviados=enviados)
        finally:
            conn.close()

    @app.get("/metricas.csv")
    def metricas_csv() -> Response:
        conn = db()
        try:
            cuerpo = to_csv(build_report(conn))
        finally:
            conn.close()
        return Response(cuerpo, mimetype="text/csv; charset=utf-8", headers={
            "Content-Disposition": 'attachment; filename="prospector-metricas.csv"'})

    @app.post("/respuesta/<int:send_id>")
    def respuesta(send_id: int) -> Response:
        conn = db()
        try:
            record_reply(conn, send_id, request.form.get("clase", "other"),
                         request.form.get("notas", ""))
        finally:
            conn.close()
        flash("Respuesta anotada.", "ok")
        return redirect(url_for("metricas"))

    return app


def main() -> None:  # pragma: no cover - entry point
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = load_settings()
    app = create_app(settings)
    log.info("consola en http://%s:%s (solo tailnet)", settings.bind_host, settings.bind_port)
    app.run(host=settings.bind_host, port=settings.bind_port, threaded=True)


if __name__ == "__main__":  # pragma: no cover
    main()
