"""Check registry. Each check module exposes:

* ``CHECK_ID``  — stable string id prefix for its findings
* ``run(ctx)``  — pure function from ScanContext to list[Finding]

Adding a check = adding a file here and one import below.
"""
from . import (
    check_2sv,
    check_admin_logins,
    check_alert_rules,
    check_backup_codes,
    check_audit_log,
    composite,
    check_dormant,
    check_email_auth,
    check_login_security,
    check_mail_transport,
    check_oauth_apps,
    check_policies,
    check_stale,
    check_suspended_tokens,
    check_super_admins,
    check_recovery,
)

ALL_CHECKS = [
    # Composites first: they are the conclusions a reader should see before
    # the one-signal-at-a-time findings.
    composite,
    check_2sv,
    check_login_security,
    check_admin_logins,
    check_super_admins,
    check_recovery,
    check_backup_codes,
    check_dormant,
    check_stale,
    check_oauth_apps,
    check_suspended_tokens,
    check_policies,
    check_alert_rules,
    check_audit_log,
    check_email_auth,
    check_mail_transport,
]
