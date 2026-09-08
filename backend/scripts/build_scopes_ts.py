"""Writes frontend/src/generated/scopes.ts from vigia/scopes.py.

The React app needs the scope list too — `components/ScopeList.tsx` renders it on
the landing page and in the connect flow — and TypeScript cannot import a Python
dataclass. Before this, the component held its own hand-typed copy: the sixth list
of the same six scopes, agreeing about which scopes but not about the wording.

So the list is generated. `ScopeList.tsx` imports the generated module and does not
know the identifiers; `tests/test_scopes_single_source.py` regenerates the file in
memory and fails if what is on disk differs, so a stale copy is a red test rather
than a page that quietly contradicts the privacy policy.

Run it after changing `vigia/scopes.py`:

    python backend/scripts/build_scopes_ts.py
"""
from __future__ import annotations

import json
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(RAIZ, "backend"))

from vigia import scopes  # noqa: E402

DESTINO = os.path.join(RAIZ, "frontend", "src", "generated", "scopes.ts")

CABECERA = """// GENERATED FILE — do not edit.
// Source: backend/vigia/scopes.py · Regenerate: python backend/scripts/build_scopes_ts.py
//
// The scopes are defined once, in Python, because the authorization request is
// built there and that request is the only source of truth. This file exists so the
// React app can render the same list without a second copy to keep in sync;
// tests/test_scopes_single_source.py fails if it drifts.

export type ScopeFamily = "workspace" | "identidad";

export type ScopeInfo = {
  /** Full identifier, exactly as sent to Google and as configured in Cloud Console. */
  id: string;
  /** Abbreviated form, as the consent screen shows it. */
  corto: string;
  familia: ScopeFamily;
  nombre: { es: string; en: string };
  /** What data it reads, and what for. */
  lee: { es: string; en: string };
  /** Checks that stop working without it. */
  checks: readonly string[];
};

"""


def generar() -> str:
    filas = [
        {
            "id": s.id,
            "corto": s.corto,
            "familia": s.familia,
            "nombre": s.nombre,
            "lee": s.lee,
            "checks": list(s.checks),
        }
        for s in scopes.SCOPES
    ]
    cuerpo = json.dumps(filas, ensure_ascii=False, indent=2)
    # `as const` so a typo in a consumer is a compile error rather than a runtime one.
    return (
        CABECERA
        + f"export const SCOPES: readonly ScopeInfo[] = {cuerpo} as const;\n\n"
        + "export const WORKSPACE_SCOPES = SCOPES.filter((s) => s.familia === "
        + '"workspace");\n'
        + "export const IDENTITY_SCOPES = SCOPES.filter((s) => s.familia === "
        + '"identidad");\n'
    )


def main() -> None:
    os.makedirs(os.path.dirname(DESTINO), exist_ok=True)
    contenido = generar()
    with open(DESTINO, "w", encoding="utf-8") as handle:
        handle.write(contenido)
    print(f"generated/scopes.ts: {len(scopes.SCOPES)} permisos")


if __name__ == "__main__":
    main()
