from unittest.mock import MagicMock

from core.models import InstalledApp, OrgWebhooksData
from scripts.org_security_posture import (
    GITHUB_APPS_TABLE,
    WEBHOOKS_TABLE,
    _persist_webhook_integrations,
)


def test_persist_webhook_integrations_writes_webhooks_and_detailed_apps():
    storage = MagicMock()
    data = OrgWebhooksData(
        webhooks_count=2,
        installed_apps_detail=[
            InstalledApp(
                app_slug="renovate",
                installation_id=12345678,
                repository_selection="selected",
                permissions={"checks": "write", "contents": "write"},
            )
        ],
    )

    _persist_webhook_integrations(
        org="dummyorg",
        audited_at="2026-08-12T00:00:00Z",
        webhooks_data=data,
        storage=storage,
    )

    storage.create_table.assert_any_call(
        WEBHOOKS_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "webhooks_count": "INTEGER NOT NULL",
        },
    )
    storage.create_table.assert_any_call(
        GITHUB_APPS_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "app_slug": "TEXT NOT NULL",
            "installation_id": "INTEGER",
            "repository_selection": "TEXT",
            "permissions": "TEXT",
        },
    )
    storage.write_rows.assert_any_call(
        WEBHOOKS_TABLE,
        [
            {
                "org": "dummyorg",
                "audited_at": "2026-08-12T00:00:00Z",
                "webhooks_count": 2,
            }
        ],
    )
    storage.write_rows.assert_any_call(
        GITHUB_APPS_TABLE,
        [
            {
                "org": "dummyorg",
                "audited_at": "2026-08-12T00:00:00Z",
                "app_slug": "renovate",
                "installation_id": 12345678,
                "repository_selection": "selected",
                "permissions": "checks:write, contents:write",
            }
        ],
    )


def test_persist_webhook_integrations_falls_back_to_slug_only_apps():
    storage = MagicMock()
    data = OrgWebhooksData(
        webhooks_count=0,
        installed_apps=["dependabot", "renovate"],
        installed_apps_detail=[],
    )

    _persist_webhook_integrations(
        org="dummyorg",
        audited_at="2026-08-12T00:00:00Z",
        webhooks_data=data,
        storage=storage,
    )

    storage.write_rows.assert_any_call(
        GITHUB_APPS_TABLE,
        [
            {
                "org": "dummyorg",
                "audited_at": "2026-08-12T00:00:00Z",
                "app_slug": "dependabot",
                "installation_id": None,
                "repository_selection": None,
                "permissions": "",
            },
            {
                "org": "dummyorg",
                "audited_at": "2026-08-12T00:00:00Z",
                "app_slug": "renovate",
                "installation_id": None,
                "repository_selection": None,
                "permissions": "",
            },
        ],
    )
