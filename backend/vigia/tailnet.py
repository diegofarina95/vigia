"""Restrict a route to the private Tailscale network.

Vigía is a single process that answers on two paths at once:

    internet → Cloudflare Worker → Tailscale Funnel → 127.0.0.1:8110
    tailnet  → 100.71.97.110:8110  (gunicorn binds 0.0.0.0)

So "tailnet only" cannot be done by binding an address — it has to be
decided per request, and the two rules below are what make it safe:

1. **127.0.0.1 is NOT trusted.** It is tempting to allow localhost for
   convenience, but the Funnel proxies *from* localhost: allowing it would
   publish the tool to the whole internet the moment the header below is
   absent. Loopback is denied on purpose.
2. **`X-Forwarded-For` is ignored.** It is client-supplied and trivially
   forged — this codebase already had a rate limiter defeated by rotating
   it. Only `REMOTE_ADDR`, the peer of the actual TCP connection, decides.

`Tailscale-Funnel-Request` is checked as a second, independent signal:
Funnel tags every request it proxies, so its presence is a hard no even if
the peer address somehow looked private.

The LAN (10.x, 192.168.x) is denied too: the requirement is the tailnet,
not "the local network".
"""
from __future__ import annotations

import ipaddress
import logging
from functools import wraps

from flask import jsonify, request

log = logging.getLogger(__name__)

# Tailscale hands out addresses from this CGNAT range (RFC 6598).
TAILNET = ipaddress.ip_network("100.64.0.0/10")
TAILNET_V6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")

FUNNEL_HEADER = "Tailscale-Funnel-Request"


def peer_address() -> str:
    """The address of the TCP peer. Never derived from a header."""
    return request.remote_addr or ""


def classify(address: str, has_funnel_header: bool) -> tuple[bool, str]:
    """(allowed, reason). Split out from the request so it is testable."""
    if has_funnel_header:
        return False, "la petición llega por el Funnel público"
    if not address:
        return False, "no se ha podido determinar la dirección de origen"
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False, f"dirección de origen no válida: {address}"
    if ip.is_loopback:
        # This is the Funnel's own source address, not a person.
        return False, "las peticiones locales no cuentan como tailnet"
    if ip in TAILNET or ip in TAILNET_V6:
        return True, "tailnet"
    return False, f"{address} no pertenece a la red Tailscale"


def is_tailnet_request() -> tuple[bool, str]:
    return classify(peer_address(), FUNNEL_HEADER in request.headers)


def tailnet_only(view):
    """403 for anything that is not a direct tailnet connection."""

    @wraps(view)
    def guard(*args, **kwargs):
        allowed, reason = is_tailnet_request()
        if not allowed:
            log.warning("acceso denegado a %s: %s", request.path, reason)
            return (
                jsonify(
                    {
                        "error": "tailnet_only",
                        "message": (
                            "Esta herramienta solo funciona desde la red Tailscale. "
                            f"Motivo: {reason}."
                        ),
                    }
                ),
                403,
            )
        return view(*args, **kwargs)

    return guard
