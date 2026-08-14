"""Organisation-level security posture report built on core modules."""

from __future__ import annotations

import json
import sys
import time
from typing import Any, Literal

import pandas as pd

from core.collector import OrgEndpointCollector
from core.config import AuditConfig
from core.github_api import (
    OrgActionsEndpoint,
    OrgAuditLogEndpoint,
    OrgCodeScanningAlertsEndpoint,
    OrgMembersEndpoint,
    OrgOutsideCollaboratorsEndpoint,
    OrgOverviewEndpoint,
    OrgRulesetsEndpoint,
    OrgSecretScanningAlertsEndpoint,
    OrgTeamsEndpoint,
    OrgWebhooksEndpoint,
    dependency_supply_chain_summary,
)
from core.github_client import GitHubHttpClient
from core.models import (
    OrgActionsData,
    OrgCodeScanningAlertsData,
    OrgRulesetsData,
    OrgSecretScanningAlertsData,
    OrgWebhooksData,
)
from core.output_paths import OutputPathResolver
from core.presenters import (
    build_org_actions_posture_rows,
    build_org_ruleset_rows,
    build_org_security_summary,
    build_org_settings_rows,
    build_org_webhook_rows,
)
from core.repo_list import load_repo_list_file
from core.storage import SqliteOrgStorage
from core.validation import direct_invocation_guard

# Constants

section_break = "\n" + ("=" * 80) + "\n"
sub_section_break = "\n" + ("-" * 80) + "\n"

WEBHOOKS_TABLE = "org_webhooks"
GITHUB_APPS_TABLE = "org_github_apps"
ORG_SETTINGS_TABLE = "org_settings"
TEAMS_TABLE = "teams"
OUTSIDE_COLLABORATORS_TABLE = "outside_collaborators"
TWOFA_DISABLED_TABLE = "twofa_disabled"
ORG_ACTIONS_RUNNERS_TABLE = "org_actions_runners"
ORG_ACTIONS_SECRETS_TABLE = "org_actions_secrets"
ORG_CODE_SCANNING_ALERTS_TABLE = "org_code_scanning_alerts"
ORG_SECRET_SCANNING_ALERTS_TABLE = "org_secret_scanning_alerts"
ORG_RULESETS_TABLE = "org_rulesets"

# Keys considered safe to print in full without redaction - i.e. not expected to contain sensitive info and
# useful for debugging/summary purposes. This is not an exhaustive list of all non-sensitive keys,
# just a curated subset for quick reference in logs.
_SAFE_SUMMARY_KEYS = (
    "org_name",
    "public_repos",
    "total_private_repos",
    "2fa_requirement_enabled",
    "default_repo_permission",
    "default_branch",
    "total_members",
    "members_without_2fa",
    "outside_collaborators",
    "teams_count",
    "code_scanning_open_alerts",
    "credential_scanning_open_alerts",
    "repos_checked_for_supply_chain",
    "repos_with_sbom",
    "repos_with_branch_protection",
    "self_hosted_runners",
    "allowed_actions_policy",
    "org_credential_count",
    "default_workflow_permissions",
    "org_webhooks_count",
    "installed_github_apps",
    "org_rulesets_count",
)


def extract_df(report: dict, *keys: str) -> pd.DataFrame:
    """Extract a DataFrame from a nested report dict using a sequence of keys."""
    data = report
    for key in keys:
        data = data.get(key, {}) if isinstance(data, dict) else {}
    if isinstance(data, list):
        return pd.DataFrame(data)
    else:
        return pd.DataFrame()


def _load_cache(
    org: str, storage: SqliteOrgStorage, database_path: str
) -> dict[str, Any]:
    """Load cached posture data for an org, if available and not expired."""
    try:
        cached = storage.read_cache(org)
        if cached is None:
            return {}
        cache, updated_at = cached
        age_min = (time.time() - updated_at) / 60
        print(
            f"  Loaded cache ({age_min:.0f} min old): {database_path}",
            file=sys.stderr,
        )
        return cache
    except Exception as exc:
        print(f"  Cache load failed: {exc}", file=sys.stderr)
        return {}


def _save_cache(
    org: str, cache: dict[str, Any], storage: SqliteOrgStorage, database_path: str
) -> None:
    """Save posture data to cache with current timestamp."""
    updated_at = time.time()
    storage.upsert_cache(org, cache, updated_at)
    print(f"  Saved cache: {database_path}", file=sys.stderr)


def _persist_webhook_integrations(
    org: str,
    audited_at: str,
    webhooks_data: OrgWebhooksData,
    storage: SqliteOrgStorage,
) -> None:
    """Persist org webhook and GitHub app posture rows to SQLite."""
    storage.create_table(
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
    hook_rows = [
        {
            "org": org,
            "audited_at": audited_at,
            "hook_id": hook.get("id"),
            "name": hook.get("name"),
            "active": str(hook.get("active"))
            if hook.get("active") is not None
            else None,
            "events": hook.get("events"),
            "url": hook.get("url"),
            "config_url": hook.get("config_url"),
            "created_at": hook.get("created_at"),
            "updated_at": hook.get("updated_at"),
        }
        for hook in webhooks_data.hooks
    ]
    storage.write_rows(WEBHOOKS_TABLE, hook_rows)

    storage.create_table(
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

    app_rows: list[dict[str, Any]] = []
    if webhooks_data.installed_apps_detail:
        app_rows = [
            {
                "org": org,
                "audited_at": audited_at,
                "app_slug": app.app_slug,
                "installation_id": app.installation_id,
                "repository_selection": app.repository_selection,
                "permissions": ", ".join(
                    f"{scope}:{level}"
                    for scope, level in sorted(app.permissions.items())
                ),
            }
            for app in webhooks_data.installed_apps_detail
        ]
    elif webhooks_data.installed_apps:
        # Fallback for minimal endpoint responses that only include app slugs.
        app_rows = [
            {
                "org": org,
                "audited_at": audited_at,
                "app_slug": app_slug,
                "installation_id": None,
                "repository_selection": None,
                "permissions": "",
            }
            for app_slug in webhooks_data.installed_apps
        ]

    storage.write_rows(GITHUB_APPS_TABLE, app_rows)


def _persist_actions_posture(
    org: str,
    audited_at: str,
    actions_data: OrgActionsData,
    storage: SqliteOrgStorage,
) -> None:
    """Persist org-level Actions runner and secret details."""
    storage.create_table(
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
    runner_rows = [
        {
            "org": org,
            "audited_at": audited_at,
            "runner_id": runner.get("id"),
            "name": runner.get("name"),
            "os": runner.get("os"),
            "status": runner.get("status"),
            "busy": str(runner.get("busy")) if runner.get("busy") is not None else None,
            "labels": runner.get("labels"),
        }
        for runner in actions_data.runners
    ]
    storage.write_rows(ORG_ACTIONS_RUNNERS_TABLE, runner_rows)

    storage.create_table(
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
    secret_rows = [
        {
            "org": org,
            "audited_at": audited_at,
            "name": secret.get("name"),
            "visibility": secret.get("visibility"),
            "created_at": secret.get("created_at"),
            "updated_at": secret.get("updated_at"),
        }
        for secret in actions_data.org_secrets
    ]
    storage.write_rows(ORG_ACTIONS_SECRETS_TABLE, secret_rows)


def _persist_ghas_alerts(
    org: str,
    audited_at: str,
    code_scanning: OrgCodeScanningAlertsData,
    secret_scanning: OrgSecretScanningAlertsData,
    storage: SqliteOrgStorage,
) -> None:
    """Persist code and secret scanning org-level alert rows."""
    storage.create_table(
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
    code_rows = [
        {
            "org": org,
            "audited_at": audited_at,
            "rule_id": alert.get("rule_id"),
            "severity": alert.get("severity"),
            "repo": alert.get("repo"),
            "state": alert.get("state"),
        }
        for alert in code_scanning.alerts
    ]
    storage.write_rows(ORG_CODE_SCANNING_ALERTS_TABLE, code_rows)

    storage.create_table(
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
    secret_rows = [
        {
            "org": org,
            "audited_at": audited_at,
            "secret_type": alert.get("secret_type"),
            "repo": alert.get("repo"),
            "state": alert.get("state"),
            "created_at": alert.get("created_at"),
        }
        for alert in secret_scanning.alerts
    ]
    storage.write_rows(ORG_SECRET_SCANNING_ALERTS_TABLE, secret_rows)


def _persist_rulesets(
    org: str,
    audited_at: str,
    rulesets_data: OrgRulesetsData,
    storage: SqliteOrgStorage,
) -> None:
    """Persist org ruleset details when available."""
    storage.create_table(
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
    ruleset_rows = [
        {
            "org": org,
            "audited_at": audited_at,
            "ruleset_id": ruleset.get("id"),
            "name": ruleset.get("name"),
            "target": ruleset.get("target"),
            "enforcement": ruleset.get("enforcement"),
            "raw_json": json.dumps(ruleset, default=str),
        }
        for ruleset in rulesets_data.rulesets
    ]
    storage.write_rows(ORG_RULESETS_TABLE, ruleset_rows)


def _persist_org_settings_entities(
    org: str,
    audited_at: str,
    org_overview: dict[str, Any],
    org_settings: dict[str, Any],
    storage: SqliteOrgStorage,
) -> None:
    """Persist key org posture entities used by dashboard/querying."""
    storage.create_table(
        ORG_SETTINGS_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "setting_name": "TEXT NOT NULL",
            "setting_value": "TEXT",
        },
    )

    setting_rows = [
        {
            "org": org,
            "audited_at": audited_at,
            "setting_name": "name",
            "setting_value": str(org_overview.get("name")),
        },
        {
            "org": org,
            "audited_at": audited_at,
            "setting_name": "description",
            "setting_value": str(org_overview.get("description")),
        },
        {
            "org": org,
            "audited_at": audited_at,
            "setting_name": "public_repo_count",
            "setting_value": str(org_overview.get("public_repos")),
        },
        {
            "org": org,
            "audited_at": audited_at,
            "setting_name": "private_repo_count",
            "setting_value": str(org_overview.get("total_private_repos")),
        },
        {
            "org": org,
            "audited_at": audited_at,
            "setting_name": "created_at",
            "setting_value": str(org_overview.get("created_at")),
        },
        {
            "org": org,
            "audited_at": audited_at,
            "setting_name": "updated_at",
            "setting_value": str(org_overview.get("updated_at")),
        },
        {
            "org": org,
            "audited_at": audited_at,
            "setting_name": "two_factor_requirement_enabled",
            "setting_value": str(org_overview.get("two_factor_requirement_enabled")),
        },
        {
            "org": org,
            "audited_at": audited_at,
            "setting_name": "default_repository_permission",
            "setting_value": str(org_overview.get("default_repository_permission")),
        },
        {
            "org": org,
            "audited_at": audited_at,
            "setting_name": "default_branch",
            "setting_value": str(org_overview.get("default_repository_branch")),
        },
        {
            "org": org,
            "audited_at": audited_at,
            "setting_name": "web_commit_signoff_required",
            "setting_value": str(org_overview.get("web_commit_signoff_required")),
        },
    ]
    storage.write_rows(
        ORG_SETTINGS_TABLE,
        setting_rows,
    )

    storage.create_table(
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
    team_rows = [
        {
            "org": org,
            "audited_at": audited_at,
            "team_name": team.get("name"),
            "slug": team.get("slug"),
            "description": team.get("description"),
            "privacy": team.get("privacy"),
            "notification_setting": team.get("notification_setting"),
            "permission": team.get("permission"),
            "parent": team.get("parent"),
        }
        for team in org_settings.get("teams", [])
    ]
    storage.write_rows(TEAMS_TABLE, team_rows)

    storage.create_table(
        OUTSIDE_COLLABORATORS_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "login": "TEXT",
            "id": "INTEGER",
        },
    )
    collaborator_rows = [
        {
            "org": org,
            "audited_at": audited_at,
            "login": collaborator.get("login"),
            "id": collaborator.get("id"),
        }
        for collaborator in org_settings.get("outside_collaborators", {}).get(
            "collaborators", []
        )
    ]
    storage.write_rows(OUTSIDE_COLLABORATORS_TABLE, collaborator_rows)

    storage.create_table(
        TWOFA_DISABLED_TABLE,
        {
            "org": "TEXT NOT NULL",
            "audited_at": "TEXT NOT NULL",
            "login": "TEXT",
        },
    )
    twofa_rows = [
        {
            "org": org,
            "audited_at": audited_at,
            "login": member.get("login"),
        }
        for member in org_settings.get("members_without_2fa", {}).get("members", [])
    ]
    storage.write_rows(TWOFA_DISABLED_TABLE, twofa_rows)


def run_full_audit(
    org: str,
    auth_method: Literal["pat", "app", "cli"] | None = None,
    repo_full_names: list[str] | None = None,
    use_cache: bool = False,
    database_path: str = "",
) -> dict[str, Any]:
    """Run a full audit for the given organization."""
    cache_storage = SqliteOrgStorage(database_path)
    cache_storage.init()
    cache = _load_cache(org, cache_storage, database_path) if use_cache else {}
    client = GitHubHttpClient(auth_method)

    audited_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    report: dict[str, Any] = {
        "org": org,
        "audited_at": audited_at,
    }

    print(f"\nCollecting data for org: {org}", file=sys.stderr)
    collector = OrgEndpointCollector(
        client=client,
        endpoints=[
            OrgOverviewEndpoint,
            OrgMembersEndpoint,
            OrgOutsideCollaboratorsEndpoint,
            OrgTeamsEndpoint,
            OrgAuditLogEndpoint,
            OrgCodeScanningAlertsEndpoint,
            OrgSecretScanningAlertsEndpoint,
            OrgActionsEndpoint,
            OrgWebhooksEndpoint,
            OrgRulesetsEndpoint,
        ],
    )

    print("\n-- org_endpoints --", file=sys.stderr)
    org_data = collector.collect(org)

    report["org_overview"] = org_data["org_overview"].data

    print("\n Collecting High-Level Org Settings...", file=sys.stderr)
    report["1_org_settings"] = build_org_settings_rows(org_data)
    _persist_org_settings_entities(
        org=org,
        audited_at=audited_at,
        org_overview=report["org_overview"],
        org_settings=report["1_org_settings"],
        storage=cache_storage,
    )

    print("\n Collecting GHAS Alert Data...", file=sys.stderr)

    report["2_ghas_alerts"] = {
        "code_scanning": org_data["org_code_scanning_alerts"].model_dump(),
        "secret_scanning": org_data["org_secret_scanning_alerts"].model_dump(),
    }
    _persist_ghas_alerts(
        org=org,
        audited_at=audited_at,
        code_scanning=org_data["org_code_scanning_alerts"],
        secret_scanning=org_data["org_secret_scanning_alerts"],
        storage=cache_storage,
    )

    print("\n Collecting Dependency Supply Chain Data...", file=sys.stderr)

    section3_col_name = "3_dependency_supply_chain"
    if section3_col_name in cache:
        report[section3_col_name] = cache[section3_col_name]
        print(f"\n-- {section3_col_name} -- (cached)", file=sys.stderr)
    else:
        print(f"\n-- {section3_col_name} --", file=sys.stderr)
        t0 = time.monotonic()
        report[section3_col_name] = {
            "summary": dependency_supply_chain_summary(
                org,
                client,
                repo_full_names=repo_full_names,
            )
        }
        print(f"  done ({time.monotonic() - t0:.1f}s)", file=sys.stderr)
        cache[section3_col_name] = report[section3_col_name]
        _save_cache(org, cache, cache_storage, database_path)

    print("\n Collecting GitHub Actions Posture Data...", file=sys.stderr)

    report["4_actions_posture"] = {
        "details": build_org_actions_posture_rows(org_data["org_actions"])
    }
    _persist_actions_posture(
        org=org,
        audited_at=audited_at,
        actions_data=org_data["org_actions"],
        storage=cache_storage,
    )

    print("\n Collecting Webhooks and GitHub Apps Data...", file=sys.stderr)
    _persist_webhook_integrations(
        org=org,
        audited_at=audited_at,
        webhooks_data=org_data["org_webhooks"],
        storage=cache_storage,
    )

    report["5_webhooks_integrations"] = {
        "details": build_org_webhook_rows(org_data["org_webhooks"]),
    }

    print("\n Collecting Organization Rulesets Data...", file=sys.stderr)

    report["6_rulesets"] = {"details": build_org_ruleset_rows(org_data["org_rulesets"])}
    _persist_rulesets(
        org=org,
        audited_at=audited_at,
        rulesets_data=org_data["org_rulesets"],
        storage=cache_storage,
    )

    rulesets_access = org_data["org_rulesets"].access
    if rulesets_access != "ok":
        print(
            "WARNING: org rulesets could not be listed. "
            f"Access detail: {rulesets_access}",
            file=sys.stderr,
        )
        if auth_method == "app":
            print(
                "  GitHub App auth may lack required org rulesets read permission. "
                "Try PAT auth with appropriate org admin scope if rulesets are expected.",
                file=sys.stderr,
            )

    return report


def write_excel(report: dict[str, Any], path: str) -> None:
    """Write the org security posture report to an Excel file."""
    summary = build_org_security_summary(report)

    # Map sheet names to DataFrames for writing
    sheet_to_df_mapping = {
        "Summary": pd.DataFrame(list(summary.items()), columns=["metric", "value"]),
        "Org Settings": pd.DataFrame(
            list(report.get("org_overview", {}).items()), columns=["setting", "value"]
        ),
        "2FA Disabled": extract_df(
            report, "1_org_settings", "members_without_2fa", "members"
        ),
        "Outside Collaborators": extract_df(
            report, "1_org_settings", "outside_collaborators", "collaborators"
        ),
        "Teams": extract_df(report, "1_org_settings", "teams"),
        "Code Scanning Alerts": extract_df(
            report, "2_ghas_alerts", "code_scanning", "alerts"
        ),
        "Secret Scanning Alerts": extract_df(
            report, "2_ghas_alerts", "secret_scanning", "alerts"
        ),
        "Dependency Supply Chain": extract_df(
            report, "3_dependency_supply_chain", "summary", "details"
        ),
        "Self-Hosted Runners": extract_df(
            report, "4_actions_posture", "details", "runners", "runners"
        ),
        "Org Secrets": extract_df(
            report, "4_actions_posture", "details", "credential_inventory", "names"
        ),
        "Webhooks": extract_df(
            report, "5_webhooks_integrations", "details", "webhooks", "hooks"
        ),
        "GitHub Apps": extract_df(
            report, "5_webhooks_integrations", "details", "github_apps", "apps"
        ),
        "Rulesets": extract_df(report, "6_rulesets", "details", "rulesets"),
    }

    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        for sheet_name, df in sheet_to_df_mapping.items():
            if not df.empty:
                print(f"Writing sheet: {sheet_name} ({len(df)} rows)", file=sys.stderr)
                df.to_excel(writer, index=False, sheet_name=sheet_name)
            else:
                print(f"Skipping empty sheet: {sheet_name}", file=sys.stderr)

    print(f"Wrote {path}", file=sys.stderr)


def run(
    config: AuditConfig,
    auth: str | None,
    base_output_dir: str,
    base_internal_dir: str,
    **kwargs,
) -> None:
    """Main entry point for org security posture audit script."""
    resolver = OutputPathResolver(config, base_output_dir, base_internal_dir)
    org_security_posture_config = config.org_security_posture

    # Define Variables from Config
    database_path = resolver.database_path(org_security_posture_config.database_path)
    github_organization = config.github_organization
    output_filename = org_security_posture_config.output_filename
    repo_file = config.repo_list_file
    use_cache = org_security_posture_config.use_cache

    # Org Security Posture Config Debug
    print(section_break, file=sys.stderr)

    print(
        "org_security_posture to be executed with the following config values:",
        file=sys.stderr,
    )

    print(section_break, file=sys.stderr)

    print(f"Auth method: {auth}", file=sys.stderr)
    print(f"Database Path: {database_path}", file=sys.stderr)
    print(f"GitHub Organization: {github_organization}", file=sys.stderr)
    print(f"Using repo file: {repo_file}", file=sys.stderr)
    print(f"Output filename: {output_filename}", file=sys.stderr)
    print(f"Use Cache: {use_cache}", file=sys.stderr)

    print(sub_section_break, file=sys.stderr)

    repo_scope: list[str] | None = None
    try:
        repo_scope = load_repo_list_file(repo_file)
    except Exception as exc:
        print(f"Failed to read repo file: {exc}", file=sys.stderr)
        sys.exit(2)

    org_prefix = f"{github_organization}/"
    repo_scope = [name for name in repo_scope if name.startswith(org_prefix)]
    print(
        f"Using {len(repo_scope)} repos from {repo_file} for supply-chain checks",
        file=sys.stderr,
    )

    print(
        f"Running org security posture audit for: {github_organization}",
        file=sys.stderr,
    )
    report = run_full_audit(
        github_organization,
        auth,
        repo_full_names=repo_scope,
        use_cache=use_cache,
        database_path=str(database_path),
    )

    print("\n Audit complete. Building summary...", file=sys.stderr)
    summary = build_org_security_summary(report)

    print("\n=== SECURITY POSTURE SUMMARY ===", file=sys.stderr)
    for key in _SAFE_SUMMARY_KEYS:
        if key in summary:
            print(f"  {key}: {summary[key]}", file=sys.stderr)

    excel_path = resolver.script_output_file(
        org_security_posture_config.output_subdir, output_filename
    )
    write_excel(report, str(excel_path))


if __name__ == "__main__":
    direct_invocation_guard(__file__)
