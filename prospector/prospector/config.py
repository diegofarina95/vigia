"""Configuration, and the checks that refuse to start without it.

Two of these are legal requirements rather than preferences. Spanish LSSI article
10 and the GDPR's transparency duty both require a commercial email to identify
who is sending it — name, company number, postal address — and an email that
omits them is not a badly-formatted email, it is an unlawful one. So the identity
fields are not defaults with a fallback: absent, the process refuses to start.

`open_tracking` is off, and the comment explaining why is part of the contract.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(RuntimeError):
    """Raised at startup when the configuration cannot lawfully be used."""


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name) or default)
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on", "si", "sí")


@dataclass(frozen=True)
class SenderIdentity:
    """Who is writing. Every field appears in every email, by law."""

    name: str
    company_number: str      # NIF/CIF in Spain, company number in the UK
    postal_address: str
    email: str
    reply_to: str

    #: The fields without which an email may not be sent. Named here rather than
    #: implied by `dataclass` field order so the error message can list them.
    REQUIRED = ("name", "company_number", "postal_address", "email")

    #: Values that are obviously unfilled configuration. Present so the console can
    #: be started and explored before the real details exist, without that
    #: convenience ever turning into a letter that identifies the sender falsely —
    #: which is worse than one that does not identify them at all, because it looks
    #: deliberate.
    #:
    #: Deliberately narrow, and matched as whole words. The first version included
    #: "ejemplo", "prueba" and "test", and blocked `Calle Ejemplo 1` — a plausible
    #: real street name, and `test` is a substring of `Testón` and `Protestantes`.
    #: A false positive here silently refuses to send with correct details, which
    #: is a worse failure than the one being prevented: these are the words somebody
    #: types when told to fill a field in later, not words that appear in addresses.
    PLACEHOLDER_MARKERS = (
        "pendiente", "pending", "rellenar", "rellena", "cambiar", "cambiame",
        "todo", "tbd", "xxx", "placeholder", "fixme", "sinrellenar",
    )

    def missing(self) -> list[str]:
        return [f for f in self.REQUIRED if not (getattr(self, f) or "").strip()]

    def placeholders(self) -> list[str]:
        """Required fields whose value is clearly a stand-in, not a real detail.

        Whole words only: `-`, `_` and spaces are boundaries, so `NIF-PENDIENTE`
        matches and `Testón` does not.
        """
        encontrados = []
        for campo in self.REQUIRED:
            valor = (getattr(self, campo) or "").strip().lower()
            if not valor:
                continue
            palabras = set(re.split(r"[^a-z0-9á-úñ]+", valor))
            if palabras & set(self.PLACEHOLDER_MARKERS):
                encontrados.append(campo)
        return encontrados

    @property
    def ready_to_send(self) -> bool:
        return not self.missing() and not self.placeholders()


@dataclass(frozen=True)
class Settings:
    """Everything the module reads from the environment."""

    # Tailscale-only. Never 0.0.0.0: this console can send email to strangers, and
    # binding it to every interface would put that behind nothing but a port.
    bind_host: str
    bind_port: int
    db_path: Path

    sender: SenderIdentity

    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_starttls: bool

    daily_cap: int
    warmup_enabled: bool
    warmup_start: int
    warmup_step: int
    warmup_step_days: int
    min_delay_seconds: int
    max_delay_seconds: int

    unsubscribe_base_url: str

    #: Below this, a prospect is scanned and kept but never contacted. The pool is
    #: unlimited and reputation is not, so this number is the main lever on how
    #: much damage a bad batch can do.
    min_commercial_score: int = 5

    #: Off by default and it should stay off. An open-tracking pixel processes
    #: personal data (an IP address, a timestamp, a mail client) about somebody who
    #: never consented, for a purpose — measuring their attention — that is far
    #: harder to defend as legitimate interest than the message itself. The message
    #: has a case; watching whether they read it does not. Turn it on only with a
    #: documented reason and an updated privacy notice.
    open_tracking: bool = False

    feature_flags: dict[str, bool] = field(default_factory=dict)

    def validate(self) -> None:
        """Refuse to run on a configuration that cannot lawfully send."""
        faltan = self.sender.missing()
        if faltan:
            raise ConfigError(
                "faltan datos de identificación del remitente, que son obligatorios "
                f"en todo correo comercial (LSSI art. 10, RGPD): {', '.join(faltan)}. "
                "Defínelos en PROSPECTOR_SENDER_NAME, PROSPECTOR_SENDER_NIF, "
                "PROSPECTOR_SENDER_ADDRESS y PROSPECTOR_SENDER_EMAIL."
            )
        if not self.unsubscribe_base_url:
            raise ConfigError(
                "PROSPECTOR_UNSUBSCRIBE_BASE_URL no está definida: sin ella los correos "
                "no pueden llevar enlace de baja, que es obligatorio."
            )
        if self.bind_host in ("0.0.0.0", "::", ""):
            raise ConfigError(
                f"bind host {self.bind_host!r}: este módulo se sirve solo por Tailscale. "
                "Define PROSPECTOR_BIND_HOST con la IP de la interfaz tailscale0."
            )
        if self.min_delay_seconds > self.max_delay_seconds:
            raise ConfigError("el retardo mínimo entre envíos es mayor que el máximo")


def load_settings() -> Settings:
    """Read the environment. Does not validate — call `validate()` at startup."""
    return Settings(
        bind_host=_env("PROSPECTOR_BIND_HOST"),
        bind_port=_env_int("PROSPECTOR_BIND_PORT", 8116),
        db_path=Path(_env("PROSPECTOR_DB_PATH", "data/prospector.db")),
        sender=SenderIdentity(
            name=_env("PROSPECTOR_SENDER_NAME"),
            company_number=_env("PROSPECTOR_SENDER_NIF"),
            postal_address=_env("PROSPECTOR_SENDER_ADDRESS"),
            email=_env("PROSPECTOR_SENDER_EMAIL"),
            reply_to=_env("PROSPECTOR_REPLY_TO") or _env("PROSPECTOR_SENDER_EMAIL"),
        ),
        smtp_host=_env("PROSPECTOR_SMTP_HOST"),
        smtp_port=_env_int("PROSPECTOR_SMTP_PORT", 587),
        smtp_user=_env("PROSPECTOR_SMTP_USER"),
        smtp_password=_env("PROSPECTOR_SMTP_PASSWORD"),
        smtp_starttls=_env_bool("PROSPECTOR_SMTP_STARTTLS", True),
        daily_cap=_env_int("PROSPECTOR_DAILY_CAP", 40),
        warmup_enabled=_env_bool("PROSPECTOR_WARMUP", True),
        warmup_start=_env_int("PROSPECTOR_WARMUP_START", 5),
        warmup_step=_env_int("PROSPECTOR_WARMUP_STEP", 5),
        warmup_step_days=_env_int("PROSPECTOR_WARMUP_STEP_DAYS", 2),
        min_delay_seconds=_env_int("PROSPECTOR_MIN_DELAY", 90),
        max_delay_seconds=_env_int("PROSPECTOR_MAX_DELAY", 180),
        unsubscribe_base_url=_env("PROSPECTOR_UNSUBSCRIBE_BASE_URL"),
        min_commercial_score=_env_int("PROSPECTOR_MIN_COMMERCIAL_SCORE", 5),
        open_tracking=_env_bool("PROSPECTOR_OPEN_TRACKING", False),
    )
