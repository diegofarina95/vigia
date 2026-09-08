"""What a score means, said once.

The thresholds lived twice: as colours in `report.py::_score_color` and as labels in
`frontend/src/components/ScoreGauge.tsx`. They agreed by luck. The failure that
matters is not the duplication itself but what it produces — a panel and the PDF the
customer forwards to their manager disagreeing about the same number.

There is also a product decision encoded here. The old set had one 65–84 band
labelled "requiere atención", so a domain scoring 79 was told to pay attention and
given no hint it was nearly there, in the same box as a mediocre 65. Five bands fix
that, and this file is where the boundaries stop being an opinion.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from vigia.scoring import SCORE_BAND_COLORS, SCORE_BANDS, score_band

RAIZ = pathlib.Path(__file__).resolve().parents[2]
MEDIDOR = RAIZ / "frontend" / "src" / "components" / "ScoreGauge.tsx"


def test_las_bandas_van_de_mayor_a_menor_y_llegan_a_cero():
    limites = [minimo for minimo, _ in SCORE_BANDS]
    assert limites == sorted(limites, reverse=True), "las bandas no están ordenadas"
    assert limites[-1] == 0, "la última banda debe ser el suelo, o un 0 no cae en ninguna"
    assert len(set(limites)) == len(limites), "hay dos bandas con el mismo límite"


def test_cada_banda_tiene_color():
    for _, clave in SCORE_BANDS:
        assert clave in SCORE_BAND_COLORS, f"la banda {clave} no tiene color"
    assert "undetermined" in SCORE_BAND_COLORS, "sin color para «no se sabe»"


@pytest.mark.parametrize(
    "puntuacion,esperada",
    [
        (100, "solid"), (85, "solid"),
        (84, "good"), (79, "good"), (72, "good"),
        (71, "attention"), (58, "attention"),
        (57, "risk"), (40, "risk"),
        (39, "exposed"), (0, "exposed"),
        (None, "undetermined"),
    ],
)
def test_donde_cae_cada_puntuacion(puntuacion, esperada):
    assert score_band(puntuacion) == esperada


def test_un_79_no_se_lee_como_un_65():
    """The case that prompted this: 79 is a good score and was being told off.

    A 20-point band is not a verdict, it is a shrug.
    """
    assert score_band(79) != score_band(65)


def test_el_frontend_usa_los_mismos_numeros():
    """The invariant. `ScoreGauge.tsx` mirrors the definition; it does not own it.

    Read as text because no Python import reaches a React component — the same
    constraint three other tests in this suite work around.
    """
    fuente = MEDIDOR.read_text(encoding="utf-8")
    # `minimo: N`, the shape the component uses now that its colour and its label
    # read ONE table. They were two functions with two threshold lists, and the
    # first run of this test caught them out of step.
    en_ts = [int(n) for n in re.findall(r"minimo:\s*(\d+)", fuente)]
    en_python = [minimo for minimo, _ in SCORE_BANDS]

    assert en_ts == en_python, (
        f"ScoreGauge.tsx comprueba {en_ts} y scoring.py define {en_python}: "
        "el panel y el PDF dirían cosas distintas del mismo número"
    )


def test_el_informe_no_reescribe_los_umbrales():
    """`_score_color` must read the definition, not carry its own copy."""
    fuente = (RAIZ / "backend" / "vigia" / "report.py").read_text(encoding="utf-8")
    cuerpo = fuente[fuente.index("def _score_color") : fuente.index("def _status_html")]
    assert "score_band" in cuerpo, "el informe volvió a escribir sus propios umbrales"
    for numero in ("85", "72", "58", "40"):
        assert f">= {numero}" not in cuerpo, f"umbral {numero} escrito a mano en el informe"
