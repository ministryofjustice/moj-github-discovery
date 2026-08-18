from unittest.mock import MagicMock

from core.models import (
    InstalledApp,
    OrgActionsData,
    OrgCodeScanningAlertsData,
    OrgSecretScanningAlertsData,
    OrgWebhooksData,
)
from scripts.org_security_posture import (
    GITHUB_APPS_TABLE,
    ORG_ACTIONS_RUNNERS_TABLE,
    ORG_ACTIONS_SECRETS_TABLE,
    ORG_CODE_SCANNING_ALERTS_TABLE,
    ORG_RULESETS_TABLE,
    ORG_SECRET_SCANNING_ALERTS_TABLE,
    ORG_SETTINGS_TABLE,
    OUTSIDE_COLLABORATORS_TABLE,
    TEAMS_TABLE,
    TWOFA_DISABLED_TABLE,
    WEBHOOKS_TABLE,
    _persist_actions_posture,
    _persist_ghas_alerts,
    _persist_org_settings_entities,
    _persist_rulesets,
    _persist_webhook_integrations,
)


def test_persist_webhook_integrations_writes_webhooks_and_detailed_apps():
    storage = MagicMock()
    data = OrgWebhooksData(
        webhooks_count=2,
        hooks=[
            {
                "id": 101,
                "name": "web",
                "active": True,
                "events": "push",
                "url": "https://api.github.com/hooks/101",
                "config_url": "https://example.org/hook",
                "created_at": "2026-08-12T00:00:00Z",
                "updated_at": "2026-08-12T00:00:00Z",
            }
        ],
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
            "hook_id": "INTEGER",
            "name": "TEXT",
            "active": "TEXT",
            "events": "TEXT",
            "url": "TEXT",
            "config_url": "TEXT",
            "created_at": "TEXT",
            "updated_at": "TEXT",
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
                "hook_id": 101,
                "name": "web",
                "active": "True",
                "events": "push",
                "url": "https://api.github.com/hooks/101",
                "config_url": "https://example.org/hook",
                "created_at": "2026-08-12T00:00:00Z",
                "updated_at": "2026-08-12T00:00:00Z",
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


def test_persist_org_settings_entities_writes_expected_tables():
    storage = MagicMock()

    org_overview = {
        "name": "ministryofjustice",
        "description": "MOJ org",
        "public_repos": 123,
        "total_private_repos": 456,
        "created_at": "2020-01-01T00:00:00Z",
        "updated_at": "2026-08-14T00:00:00Z",
        "two_factor_requirement_enabled": True,
        "default_repository_permission": "read",
        "default_repository_branch": "main",
        "web_commit_signoff_required": False,
    }
    org_settings = {
        "teams": [
            {
                "name": "Platform",
                "slug": "platform",
                "description": "Platform team",
                "privacy": "closed",
                "notification_setting": "notifications_enabled",
                "permission": "admin",
                "parent": None,
            }
        ],
        "outside_collaborators": {
            "collaborators": [
                {"login": "outside-user", "id": 12345},
            ]
        },
        "members_without_2fa": {
            "members": [
                {"login": "no-2fa-user"},
            ]
        },
    }

    _persist_org_settings_entities(
        org="dummyorg",
        audited_at="2026-08-14T00:00:00Z",
        org_overview=org_overview,
        org_settings=org_settings,
        storage=storage,
    )

    storage.create_table.assert_any_call(
        ORG_SETTINGS_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "setting_name": "TEXT NOT NULL",
            "setting_value": "TEXT",
        },
    )
    storage.create_table.assert_any_call(
        TEAMS_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "team_name": "TEXT",
            "slug": "TEXT",
            "description": "TEXT",
            "privacy": "TEXT",
            "notification_setting": "TEXT",
            "permission": "TEXT",
            "parent": "TEXT",
        },
    )
    storage.create_table.assert_any_call(
        OUTSIDE_COLLABORATORS_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "login": "TEXT",
            "id": "INTEGER",
        },
    )
    storage.create_table.assert_any_call(
        TWOFA_DISABLED_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "login": "TEXT",
        },
    )

    storage.write_rows.assert_any_call(
        ORG_SETTINGS_TABLE,
        [
            {
                "org": "dummyorg",
                "audited_at": "2026-08-14T00:00:00Z",
                "setting_name": "name",
                "setting_value": "ministryofjustice",
            },
            {
                "org": "dummyorg",
                "audited_at": "2026-08-14T00:00:00Z",
                "setting_name": "description",
                "setting_value": "MOJ org",
            },
            {
                "org": "dummyorg",
                "audited_at": "2026-08-14T00:00:00Z",
                "setting_name": "public_repo_count",
                "setting_value": "123",
            },
            {
                "org": "dummyorg",
                "audited_at": "2026-08-14T00:00:00Z",
                "setting_name": "private_repo_count",
                "setting_value": "456",
            },
            {
                "org": "dummyorg",
                "audited_at": "2026-08-14T00:00:00Z",
                "setting_name": "created_at",
                "setting_value": "2020-01-01T00:00:00Z",
            },
            {
                "org": "dummyorg",
                "audited_at": "2026-08-14T00:00:00Z",
                "setting_name": "updated_at",
                "setting_value": "2026-08-14T00:00:00Z",
            },
            {
                "org": "dummyorg",
                "audited_at": "2026-08-14T00:00:00Z",
                "setting_name": "two_factor_requirement_enabled",
                "setting_value": "True",
            },
            {
                "org": "dummyorg",
                "audited_at": "2026-08-14T00:00:00Z",
                "setting_name": "default_repository_permission",
                "setting_value": "read",
            },
            {
                "org": "dummyorg",
                "audited_at": "2026-08-14T00:00:00Z",
                "setting_name": "default_branch",
                "setting_value": "main",
            },
            {
                "org": "dummyorg",
                "audited_at": "2026-08-14T00:00:00Z",
                "setting_name": "web_commit_signoff_required",
                "setting_value": "False",
            },
        ],
    )
    storage.write_rows.assert_any_call(
        TEAMS_TABLE,
        [
            {
                "org": "dummyorg",
                "audited_at": "2026-08-14T00:00:00Z",
                "team_name": "Platform",
                "slug": "platform",
                "description": "Platform team",
                "privacy": "closed",
                "notification_setting": "notifications_enabled",
                "permission": "admin",
                "parent": None,
            }
        ],
    )
    storage.write_rows.assert_any_call(
        OUTSIDE_COLLABORATORS_TABLE,
        [
            {
                "org": "dummyorg",
                "audited_at": "2026-08-14T00:00:00Z",
                "login": "outside-user",
                "id": 12345,
            }
        ],
    )
    storage.write_rows.assert_any_call(
        TWOFA_DISABLED_TABLE,
        [
            {
                "org": "dummyorg",
                "audited_at": "2026-08-14T00:00:00Z",
                "login": "no-2fa-user",
            }
        ],
    )


def test_persist_actions_posture_writes_runner_and_secret_tables():
    storage = MagicMock()
    actions = OrgActionsData(
        self_hosted_runners=1,
        runners=[
            {
                "id": 99,
                "name": "runner-1",
                "os": "linux",
                "status": "online",
                "busy": False,
                "labels": "self-hosted,linux",
            }
        ],
        org_secrets_count=1,
        org_secrets=[
            {
                "name": "SECRET_A",
                "visibility": "all",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-02T00:00:00Z",
            }
        ],
    )

    _persist_actions_posture(
        org="dummyorg",
        audited_at="2026-08-14T00:00:00Z",
        actions_data=actions,
        storage=storage,
    )

    storage.create_table.assert_any_call(
        ORG_ACTIONS_RUNNERS_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "runner_id": "INTEGER",
            "name": "TEXT",
            "os": "TEXT",
            "status": "TEXT",
            "busy": "TEXT",
            "labels": "TEXT",
        },
    )
    storage.create_table.assert_any_call(
        ORG_ACTIONS_SECRETS_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "name": "TEXT",
            "visibility": "TEXT",
            "created_at": "TEXT",
            "updated_at": "TEXT",
        },
    )


def test_persist_ghas_alerts_writes_code_and_secret_scanning_tables():
    storage = MagicMock()
    code = OrgCodeScanningAlertsData(
        access="ok",
        open_count=1,
        alerts=[
            {
                "rule_id": "py/sql-injection",
                "severity": "high",
                "repo": "org/repo-a",
                "state": "open",
            }
        ],
    )
    secret = OrgSecretScanningAlertsData(
        access="ok",
        open_count=1,
        alerts=[
            {
                "secret_type": "GitHub Token",
                "repo": "org/repo-b",
                "state": "open",
                "created_at": "2026-01-01T00:00:00Z",
            }
        ],
    )

    _persist_ghas_alerts(
        org="dummyorg",
        audited_at="2026-08-14T00:00:00Z",
        code_scanning=code,
        secret_scanning=secret,
        storage=storage,
    )

    storage.create_table.assert_any_call(
        ORG_CODE_SCANNING_ALERTS_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "rule_id": "TEXT",
            "severity": "TEXT",
            "repo": "TEXT",
            "state": "TEXT",
        },
    )
    storage.create_table.assert_any_call(
        ORG_SECRET_SCANNING_ALERTS_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "secret_type": "TEXT",
            "repo": "TEXT",
            "state": "TEXT",
            "created_at": "TEXT",
        },
    )


def test_persist_rulesets_writes_org_rulesets_table():
    storage = MagicMock()
    rulesets_data = MagicMock()
    rulesets_data.rulesets = [
        {
            "id": 123,
            "name": "default-branch-protection",
            "target": "branch",
            "enforcement": "active",
        }
    ]

    _persist_rulesets(
        org="dummyorg",
        audited_at="2026-08-14T00:00:00Z",
        rulesets_data=rulesets_data,
        storage=storage,
    )

    storage.create_table.assert_any_call(
        ORG_RULESETS_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "ruleset_id": "INTEGER",
            "name": "TEXT",
            "target": "TEXT",
            "enforcement": "TEXT",
            "raw_json": "TEXT",
        },
    )
