"""The Finding model — the single result type every check returns.

Keeping this a plain dataclass (no ORM) means checks are pure functions
from API data to Findings, which keeps them trivially testable.
"""
from __future__ import annotations

from ..wording import con_numero

from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("pass", "fail", "warn", "undetermined")


ORG_SCOPE = "organization"
ACCOUNT_SCOPE = "accounts"
SCOPE_TYPES = (ORG_SCOPE, ACCOUNT_SCOPE)


@dataclass
class Finding:
    id: str
    title: str
    severity: str  # critical | high | medium | low | info
    status: str  # pass | fail | warn | undetermined
    description: str = ""
    affected_items: list[str] = field(default_factory=list)
    remediation: str = ""
    admin_console_url: str = ""
    cis_control: str = ""
    # Which population this finding measured ("superadministradores",
    # "toda la organización"…). Two findings can look contradictory when one
    # passes and the other fails; stating the population makes the difference
    # explicit instead of implicit in the wording.
    scope_label: str = ""
    #: WHAT this finding is about, stated rather than inferred:
    #:
    #:   "organization" — a tenant-wide setting. That the company allows SMS
    #:                    as a second factor is not david@'s weakness; it is
    #:                    the organization's. These name no accounts.
    #:   "accounts"     — something true of specific people: no 2SV, never
    #:                    signed in, super admin, bad recovery, new country.
    #:
    #: The distinction drives three things at once: who appears under "people
    #: at risk", which block of the report a finding lands in, and whether it
    #: scores once or once per account. Deriving it from "does it have
    #: accounts?" is what let the policy checks quietly list all 17 employees
    #: as if each of them had a problem.
    scope_type: str = ACCOUNT_SCOPE
    #: The measured value of the setting, as one short phrase — "Periodo de
    #: gracia: {con_numero(14, 'día')}". A FIELD and not part of the description on purpose:
    #: the description is keyed by finding id in the translation catalogue and
    #: gets replaced wholesale at read time, which silently deleted this text
    #: the first time it lived there. A measurement is data, not prose, and it
    #: must survive being rendered in another language.
    observed_value: str = ""
    #: Which data sources THIS finding rests on. Empty means "whatever the
    #: module declares", which is the right answer for almost everything.
    #: It exists for the case where one module produces findings with
    #: different footings: `check_oauth_apps` reads the token feed for two of
    #: its findings and the admin audit log for the third, and marking that
    #: third one partial because the token window was short is over-reporting
    #: — which erodes trust in the partial flag exactly as fast as
    #: under-reporting does.
    depends_on: tuple = ()
    #: The window this finding was actually able to read — "{con_numero(178, 'día')} leídos,
    #: 483 eventos". A FIELD, for the third time the same lesson: the
    #: translation catalogue replaces `scope_label` wholesale, so a measurement
    #: written into it is deleted on the way out. `observed_value` moved here
    #: for exactly this reason and the audit labels had to follow.
    #:
    #: A measurement is data. Data does not go in a translatable string.
    coverage_note: str = ""
    manual: bool = False
    details: dict = field(default_factory=dict)
    # Clean account identifiers this finding is about (no formatting), so the
    # score can count each person once at their worst severity instead of
    # once per finding they appear in. Empty for org-level findings (DNS,
    # policies, audit log), which keep scoring per finding.
    accounts: list[str] = field(default_factory=list)
    # Remediation actions that would close this finding, by id — this is the
    # finding→action graph the "Fix this first" block is derived from.
    remediation_actions: list[str] = field(default_factory=list)
    # Localisation. The finding `id` is the catalogue key; these carry the
    # values a template needs so the text can be re-rendered in any language
    # at read time instead of being frozen when the scan was stored.
    i18n_params: dict = field(default_factory=dict)
    i18n_variant: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity!r}")
        if self.status not in STATUSES:
            raise ValueError(f"invalid status: {self.status!r}")
        if self.scope_type not in SCOPE_TYPES:
            raise ValueError(f"invalid scope_type: {self.scope_type!r}")
        if self.scope_type == ORG_SCOPE and self.accounts:
            raise ValueError(
                f"{self.id}: un hallazgo de organización no puede enumerar cuentas "
                f"({len(self.accounts)} listadas). Un ajuste del tenant no es una "
                "debilidad de cada persona."
            )

    def to_dict(self) -> dict:
        return asdict(self)
