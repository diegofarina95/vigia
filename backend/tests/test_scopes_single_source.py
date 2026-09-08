"""One definition of the scopes, and no way back to three.

There were three lists inside the repository — the authorization request, the
privacy policy's table, the homepage's no-JavaScript block — and a fourth outside
it, Google Cloud Console. They disagreed: the homepage announced "Cuatro permisos
de Google" while the request asked for six and the privacy page listed six. Nothing
failed. A human reviewer at Google compares exactly these lists, and a mismatch is
grounds for rejection.

`vigia.scopes` is now the only definition. These tests exist so that the next
person who needs a scope on a page cannot solve it by typing the identifier into
the template, which is how the drift happened in the first place.

The invariant test is the important one. The others check that today's output is
right; the invariant checks that tomorrow's cannot be wrong in this particular way.
"""
from __future__ import annotations

import os
import pathlib
import re

import pytest

from vigia import scopes

#: Only the tenant-reading scopes are scanned for. `openid` and `email` are bare
#: words that legitimately appear all over the codebase — every e-mail address, and
#: the fake third-party grants in demo.py and mock_data.py, which are the scopes
#: *imaginary* apps requested and have nothing to do with what Vigía asks for.
IDS_WORKSPACE = {s.id for s in scopes.SCOPES if s.familia == "workspace"}
CORTOS_WORKSPACE = {s.corto for s in scopes.SCOPES if s.familia == "workspace"}

RAIZ = pathlib.Path(__file__).resolve().parents[2]

#: Files a reader or a reviewer sees. A scope identifier written by hand in any of
#: these is the defect this module exists to prevent.
SUPERFICIES = [
    "backend/vigia/legal.py",
    "frontend/index.html",
]

#: Directories of user-facing source that must not name a scope either.
ARBOLES_SUPERFICIE = ["frontend/src"]

#: Generated from the definition, so naming a scope there is the point. It is not an
#: exception to the rule — `test_el_modulo_ts_generado_esta_al_dia` checks it matches.
GENERADOS = {"frontend/src/generated/scopes.ts"}


@pytest.fixture(scope="module")
def cliente(tmp_path_factory):
    directorio = tmp_path_factory.mktemp("scopes")
    os.environ["VIGIA_DB_PATH"] = str(directorio / "scopes.db")
    os.environ["VIGIA_CONTACT_EMAIL"] = "diego@diegofarina.com"
    from vigia import create_app

    return create_app().test_client()


def _texto(ruta: pathlib.Path) -> str:
    return ruta.read_text(encoding="utf-8", errors="replace")


# ─────────────────────────────────────────────── the request is the source of truth


def test_la_peticion_de_autorizacion_usa_la_definicion():
    from vigia.auth.oauth import ALL_SCOPES

    assert ALL_SCOPES == list(scopes.ALL_IDS), (
        "the authorization request no longer matches vigia.scopes"
    )


def test_openid_y_email_se_piden_de_verdad():
    """If they are requested they belong on every surface; if not, on none.

    They are requested, so every surface that enumerates scopes has to say so. This
    test is what makes that statement checkable rather than a convention.
    """
    from vigia.auth.oauth import ALL_SCOPES

    assert "openid" in ALL_SCOPES and "email" in ALL_SCOPES
    assert set(scopes.IDENTITY_IDS) == {"openid", "email"}


def test_no_se_pide_ningun_permiso_de_escritura():
    for s in scopes.SCOPES:
        if s.familia != "workspace":
            continue
        assert s.id.endswith(".readonly"), f"{s.id} is not a read-only scope"


def test_ningun_permiso_restringido():
    """Restricted scopes would trigger a CASA assessment; none of ours is one."""
    restringidos = ("gmail", "/drive", "fitness", "chat", "dataportability", "photoslibrary")
    for s in scopes.SCOPES:
        assert not any(r in s.id.lower() for r in restringidos), f"{s.id} looks restricted"


# ───────────────────────────────────────────────────────── every surface agrees


def test_la_privacidad_lista_exactamente_la_definicion(cliente):
    html = cliente.get("/privacy").get_data(as_text=True)
    listados = re.findall(r"<tr><td><code>([^<]+)</code></td>", html)
    assert listados == [s.corto for s in scopes.SCOPES], (
        f"the privacy table lists {listados}, the definition says "
        f"{[s.corto for s in scopes.SCOPES]}"
    )


def test_la_portada_lista_los_permisos_de_organizacion(cliente):
    html = cliente.get("/").get_data(as_text=True)
    listados = re.findall(r"<code>([a-z0-9.\-]+\.readonly)</code>", html)
    esperados = [s.corto for s in scopes.SCOPES if s.familia == "workspace"]
    assert listados == esperados, (
        f"the homepage lists {listados}, the definition says {esperados}"
    )


def test_la_portada_no_miente_sobre_cuantos_son(cliente):
    """It said "Cuatro permisos" while asking for six."""
    html = cliente.get("/").get_data(as_text=True)
    assert scopes.cuantos("es") in html, (
        f"the homepage does not state the real count ({scopes.cuantos('es')})"
    )
    for falso in ("Cuatro permisos", "Cinco permisos", "Tres permisos"):
        assert falso not in html, f"the homepage still claims {falso!r}"


def test_no_queda_ningun_marcador_sin_sustituir(cliente):
    for ruta in ("/", "/privacy"):
        html = cliente.get(ruta).get_data(as_text=True)
        assert "__VIGIA_" not in html, f"{ruta} ships an unsubstituted placeholder"
        assert "{filas_permisos}" not in html


# ─────────────────────────────────────────────────────────────── the invariant


def test_ninguna_superficie_escribe_un_permiso_a_mano():
    """The one that matters: a scope identifier may only exist in `scopes.py`.

    Templates and legal pages must render from the definition. If this fails, the
    fix is to read from `vigia.scopes`, not to add the file to the exception list.
    """
    culpables: list[str] = []
    rutas = [RAIZ / r for r in SUPERFICIES]
    for arbol in ARBOLES_SUPERFICIE:
        base = RAIZ / arbol
        if base.is_dir():
            rutas += [
                p
                for p in base.rglob("*")
                if p.suffix in {".ts", ".tsx", ".html", ".css"} and p.is_file()
            ]

    for ruta in rutas:
        if not ruta.is_file():
            continue
        if str(ruta.relative_to(RAIZ)) in GENERADOS:
            continue
        contenido = _texto(ruta)
        for identificador in sorted(IDS_WORKSPACE | CORTOS_WORKSPACE):
            if identificador in contenido:
                for numero, linea in enumerate(contenido.splitlines(), 1):
                    if identificador in linea:
                        culpables.append(
                            f"{ruta.relative_to(RAIZ)}:{numero} writes {identificador!r}"
                        )
    assert not culpables, "scope identifiers written by hand:\n  " + "\n  ".join(culpables)


def test_los_chequeos_que_declara_cada_permiso_existen():
    """The `checks` field has to point at real files.

    It is what a justification to Google leans on: "this scope feeds these checks".
    A name that no longer exists turns that into a claim nobody can verify.
    """
    directorio = RAIZ / "backend" / "vigia" / "checks"
    presentes = {p.stem.removeprefix("check_") for p in directorio.glob("check_*.py")}
    for s in scopes.SCOPES:
        faltan = [c for c in s.checks if c not in presentes]
        assert not faltan, f"{s.corto} claims checks that do not exist: {faltan}"


def test_todo_permiso_de_organizacion_alimenta_algun_chequeo():
    """An unused scope is the thing that got removed on 2026-07-31. Keep it removed."""
    for s in scopes.SCOPES:
        if s.familia == "workspace":
            assert s.checks, f"{s.corto} feeds no check — it should not be requested"


def test_los_docstrings_de_los_clientes_no_nombran_permisos_muertos():
    """`google_client/*.py` documents its scope at the point of use.

    That is worth keeping, but it is prose, so it can go stale — the usage scope
    lived in one of these docstrings after it stopped being requested. Any scope
    named there must still be one we ask for.
    """
    directorio = RAIZ / "backend" / "vigia" / "google_client"
    patron = re.compile(r"\b((?:admin|cloud-identity)[a-z.\-]*\.readonly)\b")
    for ruta in directorio.glob("*.py"):
        for encontrado in patron.findall(_texto(ruta)):
            assert encontrado in CORTOS_WORKSPACE, (
                f"{ruta.name} documents {encontrado!r}, which is not requested any more"
            )


def test_el_modulo_ts_generado_esta_al_dia():
    """`generated/scopes.ts` must be what the generator produces right now.

    Regenerating in memory and comparing is what makes the generated file safe to
    trust: editing either side without running the script is a failing test instead
    of a React component that disagrees with the privacy policy.
    """
    import importlib.util

    ruta_script = RAIZ / "backend" / "scripts" / "build_scopes_ts.py"
    spec = importlib.util.spec_from_file_location("build_scopes_ts", ruta_script)
    assert spec and spec.loader
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)

    en_disco = pathlib.Path(modulo.DESTINO)
    assert en_disco.is_file(), "generated/scopes.ts does not exist — run the generator"
    assert _texto(en_disco) == modulo.generar(), (
        "generated/scopes.ts is stale — run: python backend/scripts/build_scopes_ts.py"
    )
