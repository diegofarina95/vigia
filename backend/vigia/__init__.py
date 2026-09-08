"""Vigía — Google Workspace security posture scanner (read-only)."""
from __future__ import annotations

import logging
import os

from flask import Flask, jsonify, send_from_directory, request

from .config import Settings, load_settings
from .crypto import TokenCipher, load_or_create_key
from .db import Database


class PrefixStripMiddleware:
    """Serve the app both at / (direct Tailscale access) and under a public
    mount path like /vigia (Cloudflare Worker → Tailscale Funnel preserves
    the original path). When the prefix is present it is stripped and
    recorded in the WSGI environ so redirects can re-apply it."""

    def __init__(self, wsgi_app, prefix: str) -> None:
        self.wsgi_app = wsgi_app
        self.prefix = prefix.rstrip("/")

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if self.prefix:
            if path == self.prefix:
                # /vigia → /vigia/ so the SPA's relative asset URLs resolve
                start_response("308 Permanent Redirect", [("Location", self.prefix + "/")])
                return [b""]
            if path.startswith(self.prefix + "/"):
                environ["PATH_INFO"] = path[len(self.prefix):]
                environ["SCRIPT_NAME"] = self.prefix
                environ["vigia.prefix"] = self.prefix
        return self.wsgi_app(environ, start_response)


def create_app(settings: Settings | None = None) -> Flask:
    settings = settings or load_settings()
    logging.basicConfig(level=logging.INFO)

    os.makedirs(settings.data_dir, exist_ok=True)

    app = Flask(__name__, static_folder=None)
    app.secret_key = settings.secret_key
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Not derived from the redirect URI: the app is reachable both over
        # plain HTTP (direct Tailscale IP) and HTTPS (public proxy).
        SESSION_COOKIE_SECURE=settings.cookie_secure,
    )
    app.wsgi_app = PrefixStripMiddleware(app.wsgi_app, settings.prefix)  # type: ignore[method-assign]

    app.extensions["vigia"] = {
        "settings": settings,
        "db": Database(settings.db_path),
        "cipher": TokenCipher(load_or_create_key(settings)),
    }

    from .api.routes import api_bp
    from .api.tailnet_routes import tailnet_bp
    from .auth.routes import auth_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    from .api.routes import _remember_lang

    # An explicit ?lang= choice is remembered, so the reader picks once.
    app.after_request(_remember_lang)
    # Private outreach console: guarded per request, since this same process
    # also answers the public Funnel path.
    app.register_blueprint(tailnet_bp)

    from .jobs import start_scheduler

    app.extensions["vigia"]["scheduler"] = start_scheduler(app, settings)

    dist = os.path.abspath(settings.frontend_dist)

    # The legal pages are server-rendered, not SPA routes: Google's OAuth brand
    # verifier fetches them without running JavaScript, and the SPA answers
    # every route with an empty <div id="root">. Registered before the
    # catch-all so Flask, not React, owns these URLs.
    @app.after_request
    def no_store_for_private(response):
        """Never let an intermediary keep a copy of somebody's report.

        Cloudflare caches by file extension, and `.csv` is on its default
        list. `/api/report.csv` was being stored at the edge for four hours
        and served to ANYONE who asked for that URL — no cookie, no session,
        HTTP 200 — with the customer's employee addresses inside. A stale
        export was the symptom; the defect was a per-tenant document sitting
        in a shared cache.

        The rule is deliberately blunt: everything under /api/ is either
        somebody's data or an action, and none of it may be stored by a proxy
        or a browser. The public marketing pages and the static bundle are
        untouched and still cache normally.
        """
        if request.path.startswith(f"{settings.prefix}/api/") or request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, private, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers.pop("Expires", None)
            # Cloudflare honours this and drops the object from the edge.
            response.headers["CDN-Cache-Control"] = "no-store"
        return response

    from . import legal

    # Every legal page is rendered in the reader's language, and the language is
    # `?lang=` then the `vigia_lang` cookie — the same precedence the API uses, so
    # a visitor who picked EN in the dashboard and then clicked "Privacidad" does
    # not land on a Spanish document. Deliberately not `Accept-Language`: a legal
    # page that disagrees with the app about the language is worse than either
    # choice, and that header was removed from the API for the same reason.
    # `Vary: Cookie` because the language is decided by `?lang=` or by the
    # `vigia_lang` cookie: without it a browser or a shared cache can hand a reader
    # the other language's copy of the document they came to read.
    CABECERAS_LEGAL = {"Content-Type": "text/html; charset=utf-8", "Vary": "Cookie"}

    def _legal(render):
        html = render(
            settings.prefix, settings.contact_email, lang=legal.idioma_pedido()
        )
        return html, 200, CABECERAS_LEGAL

    # One source of truth for the retention promise. /privacy used to hardcode
    # "24 horas" in five places while /help/data read the setting, so changing
    # the variable left two pages of the same product contradicting each other
    # about a data-protection commitment — in the document a reviewer at Google
    # reads during verification, and the one a customer reads before handing
    # over their tenant.
    @app.get("/privacy")
    def privacy_page():
        html = legal.privacy_html(
            settings.prefix,
            settings.contact_email,
            settings.pii_retention_hours,
            lang=legal.idioma_pedido(),
        )
        return html, 200, CABECERAS_LEGAL

    @app.get("/connect")
    def connect_page():
        """The interstitial before Google's consent screen. Named `/connect`
        because that is what the landing page's button now points at: nobody
        should meet "unverified application" without having been told."""
        html = legal.connect_html(
            settings.prefix,
            settings.contact_email,
            settings.pii_retention_hours,
            lang=legal.idioma_pedido(),
        )
        return html, 200, CABECERAS_LEGAL

    @app.get("/terms")
    def terms_page():
        return _legal(legal.terms_html)

    @app.get("/help/data")
    def data_help_page():
        html = legal.data_help_html(
            settings.prefix,
            settings.contact_email,
            settings.pii_retention_hours,
            lang=legal.idioma_pedido(),
        )
        return html, 200, CABECERAS_LEGAL

    # Routes the React app owns. Anything else is a real 404 instead of a
    # blank 200, which reads as a broken page to a crawler and to a person.
    SPA_ROUTES = frozenset({"", "dashboard", "dmarc-checker", "demo"})

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def spa(path: str):
        if path.startswith("api/"):
            return jsonify({"error": "not_found"}), 404
        candidate = os.path.join(dist, path)
        if path and os.path.isfile(candidate):
            return send_from_directory(dist, path)
        if path.strip("/") not in SPA_ROUTES:
            return (
                legal.not_found_html(settings.prefix, lang=legal.idioma_pedido()),
                404,
                CABECERAS_LEGAL,
            )
        index = os.path.join(dist, "index.html")
        if os.path.isfile(index):
            # Served as text rather than as a file so the prefix placeholder can be
            # substituted, and the substitution exists because of Google's OAuth
            # verification.
            #
            # `index.html` carries the homepage itself inside `#root` — the version
            # a reader WITHOUT JavaScript sees, which React replaces the moment it
            # mounts. Verification was rejected twice on findings that were both the
            # empty div this replaces: "en la página principal, no se explica el
            # propósito de la app", and the app name not matching the consent
            # screen. `legal.py`'s docstring had said from the start that the brand
            # verifier fetches "the privacy-policy and homepage URLs without
            # executing JavaScript"; the fix reached /privacy and /terms and never
            # the homepage, which answered every request with an empty root.
            #
            # The block's prose now lives in `legal.portada_sin_js`, with the rest of
            # the server-rendered prose, because it has to exist in two languages and
            # text written into a static file can only ever have one. The constraints
            # it has to respect — inline styles, absolute links, the `<h1>` matching
            # the consent screen byte for byte — are documented next to it.
            #
            # `no-cache` because this document names hash-versioned assets: an edge
            # or browser copy that outlives a deploy points at files that are gone.
            # It revalidates, it does not refetch blindly. `Vary: Cookie` for the
            # same reason as the legal pages: the language is decided by `?lang=` or
            # by the `vigia_lang` cookie, and without it a shared cache can hand a
            # reader the other language's homepage.
            lang = legal.idioma_pedido()

            with open(index, encoding="utf-8") as fh:
                html = fh.read()
            html = html.replace("__VIGIA_PREFIX__", settings.prefix)
            # `<html lang>` was hardcoded `es` and is the first thing a screen reader
            # and a translator consult; an English document declaring Spanish gets
            # read aloud with Spanish phonetics.
            html = html.replace("__VIGIA_LANG__", lang)
            html = html.replace(
                "__VIGIA_PORTADA__",
                legal.portada_sin_js(settings.prefix, settings.contact_email, lang),
            )
            return (
                html,
                200,
                {
                    "Content-Type": "text/html; charset=utf-8",
                    "Cache-Control": "no-cache",
                    "Vary": "Cookie",
                },
            )
        return (
            jsonify(
                {
                    "service": "vigia",
                    "hint": "Frontend build not found. Run `npm run build` in /frontend "
                    "or use the Vite dev server on :5173.",
                }
            ),
            200,
        )

    return app
