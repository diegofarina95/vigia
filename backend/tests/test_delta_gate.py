"""One door, and nothing walks past it.

The worst bug in this whole area was not a wrong label. It was that `jobs.py`
called `annotate_changes` directly, skipping the comparability check, and mailed
a paying customer "1 hallazgo crítico nuevo · −30" about the very same stored row
the dashboard was describing as *not comparable*. A monitoring product sending
false alarms is worse than one that stays quiet: the customer stops reading it.

`gated_summary` is now the only way to produce a delta. This file is what keeps
it that way, because a door you can walk around is not a door and this one was
already walked around once.

It works on the AST rather than on `grep`, so a comment or docstring that names
the function — several of them do, including the one explaining this bug — is not
mistaken for a call.
"""
from __future__ import annotations

import ast
import pathlib

PAQUETE = pathlib.Path(__file__).resolve().parents[1] / "vigia"

#: `annotate_changes` may only be reached through the gate. Called anywhere else,
#: the comparability check and the score decomposition are both skipped.
SOLO_DENTRO_DE_DELTA = "annotate_changes"

#: `detect_regressions` is different: it runs at SCAN time, before scoring, so
#: the stored severities and the stored score always match. Its callers are the
#: two things that produce a scan, and they are named here so a third one has to
#: be a decision instead of an accident.
ESCANEADORES = {"scan.py", "demo.py"}

#: Every module allowed to produce a delta. Not a blocklist — an inventory. If a
#: new module calls the gate, this test fails until somebody adds it here, which
#: is the moment to ask whether that module should be producing deltas at all.
PRODUCTORES = {
    "api/routes.py",   # panel, informe PDF, CSV — todos vía _scan_with_delta
    "jobs.py",         # escaneo programado y su correo de aviso
    "demo.py",         # el escaparate, con el mismo motor que el producto
}


def _modulos():
    for archivo in sorted(PAQUETE.rglob("*.py")):
        yield archivo, ast.parse(archivo.read_text())


def _invocaciones(arbol: ast.AST, nombre: str) -> int:
    """Llamadas e importaciones reales de `nombre`, no menciones en texto."""
    total = 0
    for nodo in ast.walk(arbol):
        if isinstance(nodo, ast.Call):
            objetivo = nodo.func
            if isinstance(objetivo, ast.Name) and objetivo.id == nombre:
                total += 1
            elif isinstance(objetivo, ast.Attribute) and objetivo.attr == nombre:
                total += 1
        elif isinstance(nodo, ast.ImportFrom):
            if any(alias.name == nombre for alias in nodo.names):
                total += 1
    return total


def test_annotate_changes_is_only_reachable_from_delta():
    """El fallo original, fijado: `jobs.py` la llamaba directa."""
    culpables = []
    for archivo, arbol in _modulos():
        relativo = archivo.relative_to(PAQUETE).as_posix()
        if relativo == "delta.py":
            continue
        if _invocaciones(arbol, SOLO_DENTRO_DE_DELTA):
            culpables.append(relativo)
    assert culpables == [], (
        "estos módulos se saltan gated_summary y con ella la comprobación de "
        "comparabilidad y la descomposición de la puntuación:\n  "
        + "\n  ".join(culpables)
    )


def test_detect_regressions_is_only_called_by_the_scanners():
    """Muta severidades antes de puntuar. Llamarla desde una ruta de lectura
    cambiaría el informe sin cambiar el escaneo guardado."""
    fuera = []
    for archivo, arbol in _modulos():
        relativo = archivo.relative_to(PAQUETE).as_posix()
        if relativo == "delta.py" or archivo.name in ESCANEADORES:
            continue
        if _invocaciones(arbol, "detect_regressions"):
            fuera.append(relativo)
    assert fuera == [], "detect_regressions llamada fuera del escaneo:\n  " + "\n  ".join(fuera)


def test_the_inventory_of_delta_producers_is_complete():
    """Enumera quién produce un delta y falla si aparece alguien nuevo.

    Es la mitad que faltaba: prohibir la puerta trasera no sirve si alguien abre
    una puerta principal nueva sin que nadie se entere.
    """
    encontrados = set()
    for archivo, arbol in _modulos():
        if archivo.relative_to(PAQUETE).as_posix() == "delta.py":
            continue
        if _invocaciones(arbol, "gated_summary"):
            encontrados.add(archivo.relative_to(PAQUETE).as_posix())

    nuevos = encontrados - PRODUCTORES
    desaparecidos = PRODUCTORES - encontrados
    assert not nuevos, (
        "productores de delta nuevos y sin declarar: " + ", ".join(sorted(nuevos))
    )
    assert not desaparecidos, (
        "estos ya no producen delta; revisa si el camino sigue cubierto: "
        + ", ".join(sorted(desaparecidos))
    )


def test_both_paths_reach_the_same_verdict_on_the_same_rows():
    """La comprobación de comportamiento, no solo de estructura.

    El panel y el correo programado leen las mismas filas por código distinto.
    Aquí se les pasa un par en el que la cobertura cambió y nada más, y los dos
    tienen que decidir que no hay nada que avisar.
    """
    from vigia.delta import alert_worthy, coverage_worthy, gated_summary

    def hallazgo(estado):
        return {
            "id": "suspended-with-tokens",
            "title": "Aplicaciones conectadas por cuentas suspendidas",
            "severity": "critical",
            "status": estado,
            "accounts": [],
            "affected_items": [],
            "details": {},
        }

    def desglose(score, items):
        return {
            "score": score,
            "accounts": [],
            "findings": [{"id": i, "weight": w, "earned": e} for i, w, e in items],
        }

    anterior = {
        "id": 59, "score": 33, "engine_version": "v1-a60b3d20",
        "findings": [hallazgo("undetermined")],
        "result": {"breakdown": desglose(33, [("otro", 100, 33.0)])},
    }
    actual = {
        "id": 60, "score": 35, "engine_version": "v1-a60b3d20",
        "findings": [hallazgo("pass")],
        "result": {"breakdown": desglose(35, [("otro", 100, 33.0),
                                              ("suspended-with-tokens", 19, 19.0)])},
    }

    previo, resumen = gated_summary(actual, anterior)

    # La puntuación subió, y entera por cobertura.
    assert previo == 33 and resumen["score_change"]["total"] == 2
    assert resumen["score_change"]["exposure"] == 0
    assert resumen["score_change"]["coverage"] == 2

    # Ninguno de los dos caminos manda un correo de seguridad por esto…
    assert alert_worthy(resumen, actual["score"], previo) is False
    # …y los dos pueden decir que la visibilidad se movió, por separado.
    assert coverage_worthy(resumen) is True
    assert resumen["resolved"] == [], "esto es justo lo que el correo llamó resuelto"
