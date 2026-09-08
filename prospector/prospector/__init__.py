"""Vigía outreach: prioritise DNS findings, draft, review, and send by hand.

Phase 1 is the data model and the two engines that decide what gets said and to
whom. No Flask app, no SMTP, no network: everything here is importable and
testable on the standard library alone.
"""
from __future__ import annotations

__all__ = ["addresses", "catalog", "config", "db", "prioritise", "scanner"]
