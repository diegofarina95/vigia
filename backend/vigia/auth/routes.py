"""OAuth connect flow: /api/auth/google/start → Google consent →
/api/auth/google/callback, plus disconnect (GDPR delete)."""
from __future__ import annotations

import secrets

from flask import Blueprint, jsonify, redirect, request, session

from ..google_client import DirectoryClient, GoogleApiError, GoogleSession
from ..services import get_cipher, get_db, get_settings
from . import oauth
from ..mock_data import MOCK_ADMIN_EMAIL, MOCK_DOMAIN

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _app_redirect(path: str):
    settings = get_settings()
    if settings.app_url:
        return redirect(f"{settings.app_url}{path}")
    # Same-origin redirect. The public path is diegofarina.com/vigia/…, but
    # the Tailscale Funnel strips the /vigia prefix before the request
    # reaches us — so we must re-add it, otherwise the browser lands on a
    # bare /dashboard that the Cloudflare Worker doesn't route here. The
    # Funnel tags proxied requests with this header; direct Tailscale-IP
    # access (no prefix) does not carry it.
    behind_proxy = "Tailscale-Funnel-Request" in request.headers
    if behind_proxy:
        prefix = settings.prefix
    else:
        prefix = request.environ.get("vigia.prefix", "")
    return redirect(f"{prefix}{path}")


@auth_bp.get("/google/start")
def google_start():
    settings = get_settings()

    if settings.mock_mode:
        org = get_db().upsert_org(MOCK_DOMAIN, MOCK_ADMIN_EMAIL, get_cipher().encrypt("mock"))
        session["org_id"] = org["id"]
        return _app_redirect("/dashboard?connected=1")

    if not settings.google_client_id:
        return _app_redirect("/?error=not_configured")

    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    return redirect(oauth.build_auth_url(settings, state))


@auth_bp.get("/google/callback")
def google_callback():
    settings = get_settings()

    if request.args.get("error"):
        return _app_redirect("/?error=consent_denied")
    if request.args.get("state") != session.pop("oauth_state", None):
        return _app_redirect("/?error=state_mismatch")
    code = request.args.get("code")
    if not code:
        return _app_redirect("/?error=missing_code")

    try:
        tokens = oauth.exchange_code(settings, code)
    except oauth.AuthError:
        return _app_redirect("/?error=token_exchange")

    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        # Happens when a previous grant exists; user must remove it first.
        return _app_redirect("/?error=no_refresh_token")

    try:
        identity = oauth.decode_id_token(tokens.get("id_token", ""))
    except oauth.AuthError:
        return _app_redirect("/?error=identity")
    admin_email = identity.get("email", "")
    if not identity.get("hd"):
        return _app_redirect("/?error=not_workspace")

    # Verify the connecting user can actually read domain-wide data.
    google_session = GoogleSession(oauth.StaticTokenProvider(tokens["access_token"]))
    directory = DirectoryClient(google_session)
    try:
        domains, _ = directory.list_domains()
    except GoogleApiError as exc:
        if exc.status_code == 403:
            return _app_redirect("/?error=not_admin")
        return _app_redirect("/?error=google_api")

    primary_domain = next(
        (d["domainName"] for d in domains if d.get("isPrimary")),
        identity.get("hd"),
    )

    org = get_db().upsert_org(
        primary_domain=primary_domain,
        admin_email=admin_email,
        refresh_token_enc=get_cipher().encrypt(refresh_token),
    )
    session.clear()
    session["org_id"] = org["id"]
    return _app_redirect("/dashboard?connected=1")


@auth_bp.post("/disconnect")
def disconnect():
    """Deletes the org, its encrypted token and every scan; revokes the
    Google grant best-effort. This is the GDPR 'delete my data' path."""
    db = get_db()
    org_id = session.get("org_id")
    if org_id is not None:
        org = db.get_org(org_id)
        if org and not get_settings().mock_mode:
            try:
                oauth.revoke_token(get_cipher().decrypt(org["refresh_token_enc"]))
            except Exception:  # noqa: BLE001 — revocation is best-effort
                pass
        db.delete_org(org_id)
    session.clear()
    return jsonify({"ok": True})
