from vigia.delta import alert_worthy, annotate_changes


def f(fid, status, severity="high", title=None):
    return {"id": fid, "status": status, "severity": severity, "title": title or fid}


def test_no_previous_scan_is_baseline():
    current = [f("a", "fail")]
    summary = annotate_changes(current, None)
    assert summary["has_baseline"] is False
    assert current[0]["change"] == "baseline"
    assert summary["new"] == []


def test_pass_to_fail_is_new_issue():
    current = [f("a", "fail")]
    summary = annotate_changes(current, [f("a", "pass")])
    assert current[0]["change"] == "new"
    assert [e["id"] for e in summary["new"]] == ["a"]


def test_warn_to_fail_is_worse_not_new():
    current = [f("a", "fail")]
    summary = annotate_changes(current, [f("a", "warn")])
    assert current[0]["change"] == "worse"
    assert [e["id"] for e in summary["worse"]] == ["a"]
    assert summary["new"] == []


def test_fail_to_pass_is_resolved():
    current = [f("a", "pass")]
    summary = annotate_changes(current, [f("a", "fail")])
    assert current[0]["change"] == "resolved"
    assert [e["id"] for e in summary["resolved"]] == ["a"]


def test_fail_to_warn_is_improved_not_resolved():
    current = [f("a", "warn")]
    summary = annotate_changes(current, [f("a", "fail")])
    assert current[0]["change"] == "improved"
    assert summary["resolved"] == []


def test_unchanged_is_same():
    current = [f("a", "fail")]
    annotate_changes(current, [f("a", "fail")])
    assert current[0]["change"] == "same"


def test_brand_new_check_only_counts_when_open():
    current = [f("new-open", "fail"), f("new-clean", "pass")]
    summary = annotate_changes(current, [])
    assert current[0]["change"] == "new"
    assert current[1]["change"] == "same"
    assert [e["id"] for e in summary["new"]] == ["new-open"]


def test_undetermined_is_not_on_the_severity_scale():
    """The replacement for `test_undetermined_sits_between_pass_and_warn`, which
    asserted the bug: it fixed `pass → undetermined` as `new` and
    `fail → undetermined` as `improved`.

    Both statements are about Vigía, not about the tenant. The first mailed a
    customer about a problem that did not exist; the second told one that
    something had got better when all that happened was that we stopped being
    able to look.
    """
    current = [f("a", "undetermined")]
    annotate_changes(current, [f("a", "pass")])
    assert current[0]["change"] == "coverage_lost"

    current = [f("b", "undetermined")]
    annotate_changes(current, [f("b", "fail")])
    assert current[0]["change"] == "coverage_lost"

    # And asking for its badness is now a loud failure rather than a 1.
    import pytest

    from vigia.delta import _badness

    with pytest.raises(ValueError, match="no está en la escala"):
        _badness("undetermined")


def test_alert_worthy_rules():
    empty = {"new": [], "worse": []}
    assert alert_worthy({"new": [{"id": "x"}], "worse": []}, 50, 50) is True
    assert alert_worthy({"new": [], "worse": [{"id": "x"}]}, 50, 50) is True
    assert alert_worthy(empty, 40, 60) is True  # score dropped
    assert alert_worthy(empty, 60, 40) is False  # improved
    assert alert_worthy(empty, 50, 50) is False
    assert alert_worthy(empty, None, None) is False


# --------------------------------------------------------------------------
# La tabla de transiciones. Nada de esto se puede validar comparando dos
# escaneos idénticos: siempre saldría "sin cambios", tanto si el comparador
# funciona como si devuelve `same` a ciegas. Hacen falta cambios reales, uno
# por fila.
# --------------------------------------------------------------------------

import pytest

from vigia.delta import coverage_worthy, explain_score, gated_summary


def g(fid, status, severity="high", accounts=None, details=None):
    """Un hallazgo con los campos que ahora entran en la comparación."""
    return {
        "id": fid,
        "status": status,
        "severity": severity,
        "title": fid,
        "accounts": list(accounts or []),
        "affected_items": [],
        "details": details or {},
    }


CASOS = [
    # (etiqueta esperada, antes, ahora, ¿dispara aviso de seguridad?)
    ("new", g("x", "pass"), g("x", "fail"), True),
    ("worse", g("x", "warn"), g("x", "fail"), True),
    ("resolved", g("x", "fail"), g("x", "pass"), False),
    ("worse", g("x", "fail", "high"), g("x", "fail", "critical"), True),
    ("improved", g("x", "fail", "critical"), g("x", "fail", "high"), False),
    (
        "worse",
        g("x", "fail", accounts=["a@x", "b@x", "c@x"]),
        g("x", "fail", accounts=["a@x", "b@x", "c@x", "d@x", "e@x", "f@x", "g@x", "h@x"]),
        True,
    ),
    (
        "improved",
        g("x", "fail", accounts=["a@x"] * 0 + [f"u{i}@x" for i in range(8)]),
        g("x", "fail", accounts=[f"u{i}@x" for i in range(3)]),
        False,
    ),
    ("coverage_gained", g("x", "undetermined"), g("x", "pass"), False),
    ("coverage_gained", g("x", "undetermined"), g("x", "fail"), False),
    ("coverage_lost", g("x", "pass"), g("x", "undetermined"), False),
    ("coverage_lost", g("x", "fail"), g("x", "undetermined"), False),
    ("same", g("x", "fail"), g("x", "fail"), False),
]


@pytest.mark.parametrize("esperada,antes,ahora,avisa", CASOS)
def test_transition_table(esperada, antes, ahora, avisa):
    actual = [dict(ahora)]
    resumen = annotate_changes(actual, [antes])
    assert actual[0]["change"] == esperada, (
        f"{antes['status']}/{antes['severity']}/{len(antes['accounts'])} -> "
        f"{ahora['status']}/{ahora['severity']}/{len(ahora['accounts'])}"
    )
    assert alert_worthy(resumen, 50, 50) is avisa


def test_coverage_gained_is_never_resolved():
    """La felicitación falsa. Esto es lo que le llegó al cliente el 3 de agosto
    por `suspended-with-tokens`: 'RESUELTOS DESDE EL ÚLTIMO ESCANEO'."""
    actual = [g("suspended-with-tokens", "pass", "critical")]
    resumen = annotate_changes(actual, [g("suspended-with-tokens", "undetermined", "critical")])
    assert actual[0]["change"] == "coverage_gained"
    assert resumen["resolved"] == []
    assert [e["id"] for e in resumen["coverage_gained"]] == ["suspended-with-tokens"]
    assert resumen["coverage_gained"][0]["to_status"] == "pass"
    assert resumen["coverage_gained"][0]["open"] is False


def test_coverage_gained_on_an_open_issue_keeps_its_own_text():
    """`undetermined → fail`: hay un problema abierto y hay que decirlo, pero no
    es nuevo en el tenant. Era invisible, no inexistente."""
    actual = [g("oauth-high-risk", "fail", "high")]
    resumen = annotate_changes(actual, [g("oauth-high-risk", "undetermined", "high")])
    assert actual[0]["change"] == "coverage_gained"
    assert resumen["new"] == [] and resumen["worse"] == []
    assert resumen["coverage_gained"][0]["open"] is True
    assert resumen["coverage_gained"][0]["to_status"] == "fail"


def test_coverage_lost_never_raises_a_security_alert():
    """Un 429 de Google, o un scope revocado, no es un problema de seguridad
    nuevo. Antes lo era: `pass → undetermined` salía como `new`."""
    actual = [g("x", "undetermined")]
    resumen = annotate_changes(actual, [g("x", "pass")])
    assert alert_worthy(resumen, 50, 50) is False
    assert coverage_worthy(resumen) is True


def test_the_summary_carries_the_drift_numbers():
    """'Usuarios sin 2FA: de 3 a 8' tiene que poder escribirse desde el resumen,
    así que los números viajan como datos y no como texto — un texto aquí lo
    borraría el catálogo de traducción en la salida, ya ha pasado tres veces."""
    actual = [g("2sv-users", "fail", accounts=[f"u{i}@x" for i in range(8)])]
    resumen = annotate_changes(actual, [g("2sv-users", "fail", accounts=["a@x", "b@x", "c@x"])])
    assert actual[0]["change"] == "worse"
    assert actual[0]["change_detail"] == {"from_count": 3, "to_count": 8}
    assert resumen["worse"][0]["from_count"] == 3
    assert resumen["worse"][0]["to_count"] == 8


def test_a_regression_is_attributed_to_the_tenant_not_to_coverage():
    """Punto 4: `detect_regressions` sube la severidad en tiempo de escaneo, lo
    que mueve el denominador sin tocar la huella del motor. Es un cambio real
    del tenant y la etiqueta debe decirlo."""
    actual = [g("2sv-users", "fail", "critical", details={"regression": True})]
    annotate_changes(actual, [g("2sv-users", "fail", "high")])
    assert actual[0]["change"] == "worse"
    assert actual[0]["change_detail"]["regression"] is True


# ------------------------------------------------- descomposición por causa

def _breakdown(score, findings):
    """Un desglose mínimo con la forma que guarda `score_breakdown`."""
    return {
        "score": score,
        "accounts": [],
        "findings": [
            {"id": fid, "weight": w, "earned": e} for fid, w, e in findings
        ],
    }


def test_score_split_between_coverage_and_exposure():
    """El caso real del 3 de agosto: 33 -> 35 con el denominador 238 -> 257,
    entero por cobertura. La organización no cambió nada."""
    antes = _breakdown(33, [("a", 100, 33.0)])
    ahora = _breakdown(35, [("a", 100, 33.0), ("nuevo", 19, 19.0)])
    explicado = explain_score(ahora, antes)
    assert explicado["total"] == 2
    assert explicado["exposure"] == 0, "la organización no se movió"
    assert explicado["coverage"] == 2
    assert explicado["gained"] == ["finding:nuevo"]


def test_a_real_drop_is_attributed_to_exposure():
    antes = _breakdown(100, [("a", 100, 100.0)])
    ahora = _breakdown(50, [("a", 100, 50.0)])
    explicado = explain_score(ahora, antes)
    assert explicado["total"] == -50
    assert explicado["exposure"] == -50
    assert explicado["coverage"] == 0


def test_the_two_causes_can_appear_at_once():
    antes = _breakdown(100, [("a", 100, 100.0)])
    ahora = _breakdown(50, [("a", 100, 50.0), ("nuevo", 100, 50.0)])
    explicado = explain_score(ahora, antes)
    assert explicado["exposure"] == -50   # 'a' cayó de verdad
    assert explicado["coverage"] == 0     # y el item nuevo entró con el mismo crédito
    assert explicado["gained"] == ["finding:nuevo"]


def test_no_decomposition_is_said_out_loud():
    """Un escaneo guardado sin desglose no produce un cero silencioso."""
    explicado = explain_score(_breakdown(35, [("a", 10, 5.0)]), {})
    assert explicado["exposure"] is None
    assert explicado["reason"], "tiene que explicar por qué no hay descomposición"


def test_only_an_exposure_drop_alerts():
    """Con descomposición disponible, una bajada causada por cobertura no avisa.
    Ese era el segundo camino por el que un 429 llegaba al cliente como alarma:
    `alert_worthy` mira la puntuación cruda."""
    resumen = {"new": [], "worse": [], "score_change": {"exposure": 0, "coverage": -7}}
    assert alert_worthy(resumen, 33, 40) is False
    resumen["score_change"] = {"exposure": -7, "coverage": 0}
    assert alert_worthy(resumen, 33, 40) is True


# ------------------------------------------------------- la puerta, los dos caminos

def _scan(sid, score, engine, findings, breakdown=None):
    return {
        "id": sid,
        "score": score,
        "engine_version": engine,
        "findings": findings,
        "result": {"breakdown": breakdown} if breakdown else {},
    }


def test_a_different_engine_is_not_comparable_on_either_path():
    actual = _scan(2, 35, "v1-bbbb", [g("x", "fail")])
    anterior = _scan(1, 33, "v1-aaaa", [g("x", "pass")])
    previo, resumen = gated_summary(actual, anterior)
    assert previo is None, "no se resta nada entre motores distintos"
    assert resumen["engine_changed"] is True
    assert resumen["score_change"] is None
    assert resumen["new"] == [], "y no se inventa un hallazgo nuevo"
    assert actual["findings"][0]["change"] == "baseline"
    assert alert_worthy(resumen, 35, None) is False


def test_no_previous_scan_gives_a_baseline_and_no_delta():
    actual = _scan(1, 35, "v1-aaaa", [g("x", "fail")])
    previo, resumen = gated_summary(actual, None)
    assert previo is None
    assert resumen["has_baseline"] is False
    assert resumen["score_change"] is None
    assert actual["findings"][0]["change"] == "baseline"


def test_the_gate_attaches_the_decomposition_when_it_can():
    actual = _scan(2, 35, "v1-aaaa", [g("x", "pass")], _breakdown(35, [("x", 100, 35.0)]))
    anterior = _scan(1, 33, "v1-aaaa", [g("x", "pass")], _breakdown(33, [("x", 100, 33.0)]))
    previo, resumen = gated_summary(actual, anterior)
    assert previo == 33
    assert resumen["score_change"]["total"] == 2
    assert resumen["score_change"]["exposure"] == 2


def test_a_rounded_zero_does_not_deny_a_real_change():
    """Encontrado calculando la prueba del periodo de gracia de 2FA antes de
    ejecutarla: un control medio que pasa de correcto a aviso mueve la puntuación
    0,6 sobre un denominador de 257 y se redondea a nada. La línea de exposición
    decía entonces 'sin cambios en tu organización' justo encima de una tabla que
    listaba el cambio."""
    from vigia.projection import score_explanation

    cambio = {"score": 35, "previous_score": 35, "total": 0, "exposure": 0,
              "coverage": 0, "gained": [], "lost": [], "common": 30, "reason": ""}
    resumen = {"new": [{"id": "policy-2sv-grace"}], "worse": [], "improved": [], "resolved": []}

    sin_contexto = score_explanation(cambio)
    assert sin_contexto["lines"] == ["sin cambios en tu organización"]

    con_contexto = score_explanation(cambio, resumen)
    assert "sin cambios en tu organización" not in con_contexto["lines"]
    assert "1 cambio en tu organización" in con_contexto["lines"][0]
    assert con_contexto["org_moved"] is True


def test_the_wording_is_the_same_in_every_channel():
    """Una sola implementación de la frase, y los tres consumidores la usan: el
    panel la recibe ya renderizada en el payload, el correo y el PDF llaman a la
    misma función. Es el invariante que faltaba cuando cuatro canales describían
    la misma comparación de cuatro formas."""
    import ast
    import pathlib

    raiz = pathlib.Path(__file__).resolve().parents[1] / "vigia"
    llamantes = set()
    for archivo in raiz.rglob("*.py"):
        arbol = ast.parse(archivo.read_text())
        for nodo in ast.walk(arbol):
            if isinstance(nodo, ast.Call) and getattr(nodo.func, "id", "") == "score_explanation":
                llamantes.add(archivo.relative_to(raiz).as_posix())
    assert llamantes == {"notify.py", "report.py", "api/routes.py"}, llamantes
