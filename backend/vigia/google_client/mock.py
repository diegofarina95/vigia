"""Mock Directory/Reports clients backed by seeded data (MOCK_MODE=1)."""
from __future__ import annotations

from .. import mock_data


class MockDirectoryClient:
    def list_users(self) -> tuple[list[dict], bool]:
        return mock_data.mock_users(), False

    def list_domains(self) -> list[dict]:
        return mock_data.mock_domains()


class MockReportsClient:
    def token_activities(self, max_pages: int = 5) -> list[dict]:
        return mock_data.mock_token_events()

    def admin_activities(self, max_results: int = 1000, max_pages: int = 3) -> list[dict]:
        return mock_data.mock_admin_events()

    def login_activities(self, max_pages: int = 5) -> list[dict]:
        return mock_data.mock_login_events()


class MockPolicyClient:
    def list_policies(self) -> list[dict]:
        return mock_data.mock_policies()
