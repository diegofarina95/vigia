"""Entry point for the public unsubscribe app.

Separate process from the console, on a separate port, with a separate WSGI app.
That separation is the security boundary: what gets exposed through the Funnel is
this file's routes and nothing else, so no future console route can inherit public
reach by accident.

Binds to 127.0.0.1 — Tailscale's Funnel connects to it locally, and nothing else
should be able to.
"""
from __future__ import annotations

import logging
import os

from .config import load_settings
from .unsubscribe import create_public_app


def main() -> None:  # pragma: no cover - entry point
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = load_settings()
    puerto = int(os.environ.get("PROSPECTOR_PUBLIC_PORT", "8123"))
    app = create_public_app(settings.db_path)
    logging.getLogger("prospector.public").info(
        "app de baja en http://127.0.0.1:%s (se publica por Funnel)", puerto)
    app.run(host="127.0.0.1", port=puerto, threaded=True)


if __name__ == "__main__":  # pragma: no cover
    main()
