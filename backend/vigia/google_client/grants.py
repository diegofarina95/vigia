"""OAuth grants, folded down as they are read instead of piled up.

`cluster365.ai` produces more than 8 000 `token` audit events over Google's
180-day window and the eighth page still had a `nextPageToken`. The old code
took the first five pages and stopped — silently — so every OAuth finding was
answering a question about the last few weeks while claiming to answer one
about six months. Because the events arrive newest-first, what fell off the end
was the past: an application authorised in January and never revoked simply did
not exist as far as the report was concerned, and the card said so.

Raising the page cap would have moved the lie rather than removed it. The fix
is that **the raw events are not what the checks need**. They need the distinct
set of (application, person, scopes) plus, per pair, when it was granted and
whether it was later revoked. Eight thousand events collapse to a handful of
applications, so the whole window fits in a few kilobytes and the cap stops
being the thing that decides what the customer is told.

A defensive cap still exists, because an unbounded loop against somebody else's
API is not a thing to ship. When it is reached the result says so, and every
finding built on it reports **partial** — never a pass and never a failure.
"I saw nothing" and "I could not look" are different statements and this module
exists so the report stops confusing them.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Grant:
    """One application, as far as this tenant is concerned."""

    client_id: str
    name: str = ""
    scopes: set[str] = field(default_factory=set)
    #: {account: {"authorized": datetime|None, "revoked": datetime|None}}
    users: dict[str, dict] = field(default_factory=dict)

    @property
    def accounts(self) -> set[str]:
        return set(self.users)

    def still_granted_for(self, account: str) -> bool:
        """Authorised and not revoked afterwards.

        A revocation only undoes a grant that came before it: revoked in March
        and reconnected in June is connected.
        """
        entry = self.users.get(account.lower())
        if not entry or entry.get("authorized") is None:
            return False
        revoked = entry.get("revoked")
        return revoked is None or revoked < entry["authorized"]


@dataclass
class Coverage:
    """How much of a data source was actually read.

    `complete` is the only field the checks are allowed to treat as a verdict;
    the rest is there so the report can say *how* short it fell instead of
    just that it did.
    """

    source: str
    pages: int = 0
    records: int = 0
    complete: bool = True
    oldest: str = ""
    newest: str = ""
    reason: str = ""

    @property
    def window_days(self) -> int | None:
        if not self.oldest or not self.newest:
            return None
        from datetime import datetime

        try:
            desde = datetime.fromisoformat(self.oldest.replace("Z", "+00:00"))
            hasta = datetime.fromisoformat(self.newest.replace("Z", "+00:00"))
        except ValueError:
            return None
        return max(0, (hasta - desde).days)

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "pages": self.pages,
            "records": self.records,
            "complete": self.complete,
            "oldest": self.oldest,
            "newest": self.newest,
            "window_days": self.window_days,
            "reason": self.reason,
        }


def fold(items, grants: dict[str, Grant] | None = None) -> dict[str, Grant]:
    """Fold a page of `token` events into the running set of grants.

    Called once per page so nothing accumulates: the caller keeps the folded
    dictionary and throws the page away.
    """
    from .reports import event_parameters
    from ..checks.util import parse_google_time

    grants = grants if grants is not None else {}
    for item in items or []:
        actor = ((item.get("actor") or {}).get("email") or "").lower()
        when = parse_google_time((item.get("id") or {}).get("time"))
        for event in item.get("events") or []:
            nombre = (event.get("name") or "").lower()
            if nombre not in ("authorize", "revoke"):
                continue
            params = event_parameters(event)
            client_id = str(params.get("client_id") or "")
            if not client_id:
                continue

            grant = grants.setdefault(client_id, Grant(client_id=client_id))
            app_name = str(params.get("app_name") or "")
            # Prefer a real name over the numeric id if any event carries one.
            if app_name and (not grant.name or grant.name == client_id):
                grant.name = app_name
            elif not grant.name:
                grant.name = client_id

            scopes = params.get("scope") or []
            if isinstance(scopes, str):
                scopes = [scopes]
            grant.scopes.update(str(s) for s in scopes)

            if not actor or when is None:
                continue
            entry = grant.users.setdefault(actor, {"authorized": None, "revoked": None})
            clave = "authorized" if nombre == "authorize" else "revoked"
            # Newest wins: the events arrive newest-first, but the pages are
            # not guaranteed to be, so compare rather than assume.
            if entry[clave] is None or when > entry[clave]:
                entry[clave] = when
    return grants


# ------------------------------------------- persisting the accumulated fold

def dehydrate(grants: dict) -> dict:
    """Grants as plain JSON-safe data, for storage between scans."""
    return {
        client_id: {
            "name": grant.name,
            "scopes": sorted(grant.scopes),
            "users": {
                cuenta: {
                    "authorized": (
                        entrada["authorized"].isoformat() if entrada.get("authorized") else None
                    ),
                    "revoked": (
                        entrada["revoked"].isoformat() if entrada.get("revoked") else None
                    ),
                }
                for cuenta, entrada in grant.users.items()
            },
        }
        for client_id, grant in grants.items()
    }


def rehydrate(data: dict) -> dict[str, Grant]:
    """The inverse. Anything unparseable is dropped rather than guessed: a
    corrupt row must not silently become a verdict."""
    from datetime import datetime

    def cuando(valor):
        if not valor:
            return None
        try:
            return datetime.fromisoformat(str(valor))
        except ValueError:
            return None

    salida: dict[str, Grant] = {}
    for client_id, bruto in (data or {}).items():
        if not isinstance(bruto, dict):
            continue
        salida[client_id] = Grant(
            client_id=client_id,
            name=str(bruto.get("name") or client_id),
            scopes=set(bruto.get("scopes") or []),
            users={
                cuenta: {
                    "authorized": cuando((entrada or {}).get("authorized")),
                    "revoked": cuando((entrada or {}).get("revoked")),
                }
                for cuenta, entrada in (bruto.get("users") or {}).items()
            },
        )
    return salida


def merge(acumulado: dict[str, Grant], nuevos: dict[str, Grant]) -> dict[str, Grant]:
    """Fold a fresh incremental read into the accumulated picture, in place.

    Newest wins per (app, person, action). A revoke read today must not be
    overwritten by an authorize stored last week, and vice versa — which is
    exactly what `still_granted_for` compares.
    """
    for client_id, nuevo in nuevos.items():
        actual = acumulado.get(client_id)
        if actual is None:
            acumulado[client_id] = nuevo
            continue
        if nuevo.name and (not actual.name or actual.name == client_id):
            actual.name = nuevo.name
        actual.scopes.update(nuevo.scopes)
        for cuenta, entrada in nuevo.users.items():
            destino = actual.users.setdefault(
                cuenta, {"authorized": None, "revoked": None}
            )
            for clave in ("authorized", "revoked"):
                venido = entrada.get(clave)
                if venido is not None and (
                    destino.get(clave) is None or venido > destino[clave]
                ):
                    destino[clave] = venido
    return acumulado
