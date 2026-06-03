#!/usr/bin/env python3
"""Organisation-level security posture report built on core modules."""

from __future__ import annotations

import argparse
import atexit
import os
import sys
import time
from pathlib import Path
from typing import Any, Literal

# add project root to path for core imports
# TODO: Remove once pyproject.toml is build-system configured
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd

from core.collector import OrgEndpointCollector
from core.config import AuditConfig, load_audit_config
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
from core.presenters import build_org_security_summary
from core.repo_list import load_repo_list_file
from core.storage import SqliteOrgStorage
from core.utils import base_directory_setup

section_break = "\n" + ("=" * 80) + "\n"
sub_section_break = "\n" + ("-" * 80) + "\n"

# TODO:
BASE_OUTPUT_DIR, BASE_INTERNAL_DIR, PROJECT_ROOT = base_directory_setup()

# Configure Output Directories
OUTPUT_DIR = os.path.join(BASE_OUTPUT_DIR, "org_security_posture")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Set Default Cache and Repo List Paths
ORG_CACHE_DB_PATH = os.path.join(BASE_INTERNAL_DIR, "org_posture_cache.db")

__start_time: float | None = None


# TODO: Consider moving to core.utils as repeated across scripts or to main.py when shared entrypoint developed
def _report_elapsed() -> None:
    """Report elapsed time on script exit."""
    if __start_time is not None:
        elapsed = time.monotonic() - __start_time
        print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)


atexit.register(_report_elapsed)


def _parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Audit organisation security posture using core collectors."
    )
    parser.add_argument(
        "--config-file",
        default=None,
        type=Path,
        help=("Path to audit config YAML. Defaults to config/audit_config.yaml."),
    )
    parser.add_argument(
        "--auth",
        choices=["pat", "app", "cli"],
        default=None,
        help="Select GitHub authentication method explicitly",
    )
    return parser.parse_args()


def _load_cache(org: str, storage: SqliteOrgStorage) -> dict[str, Any]:
    """Load cached posture data for an org, if available and not expired."""
    try:
        cached = storage.read_cache(org)
        if cached is None:
            return {}
        cache, updated_at = cached
        age_min = (time.time() - updated_at) / 60
        print(
            f"  Loaded cache ({age_min:.0f} min old): {ORG_CACHE_DB_PATH}",
            file=sys.stderr,
        )
        return cache
    except Exception as exc:
        print(f"  Cache load failed: {exc}", file=sys.stderr)
        return {}


def _save_cache(org: str, cache: dict[str, Any], storage: SqliteOrgStorage) -> None:
    """Save posture data to cache with current timestamp."""
    updated_at = time.time()
    storage.upsert_cache(org, cache, updated_at)
    print(f"  Saved cache: {ORG_CACHE_DB_PATH}", file=sys.stderr)


def run_full_audit(
    org: str,
    auth_method: Literal["pat", "app", "cli"] | None = None,
    repo_full_names: list[str] | None = None,
    use_cache: bool = False,
) -> dict[str, Any]:
    """Run a full audit for the given organization."""
    cache_storage = SqliteOrgStorage(ORG_CACHE_DB_PATH)
    cache_storage.init()
    cache = _load_cache(org, cache_storage) if use_cache else {}
    client = GitHubHttpClient(auth_method)

    report: dict[str, Any] = {
        "org": org,
        "audited_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
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
    report["1_org_settings"] = {
        "total_members": {
            "access": "ok",
            "total_members": org_data["org_members"].total_members,
            "public_members": None,
        },
        "members_without_2fa": {
            "access": "ok",
            "members": [
                {"login": login}
                for login in org_data["org_members"].members_without_2fa
            ],
        },
        "outside_collaborators": {
            "access": org_data["org_outside_collaborators"].access,
            "collaborators": org_data["org_outside_collaborators"].collaborators,
        },
        "teams": org_data["org_teams"].teams,
        "audit_log_recent": {
            "access": org_data["org_audit_log"].access,
            "entries": org_data["org_audit_log"].entries,
        },
    }

    print("\n Collecting GHAS Alert Data...", file=sys.stderr)

    report["2_ghas_alerts"] = {
        "code_scanning": org_data["org_code_scanning_alerts"].model_dump(),
        "secret_scanning": org_data["org_secret_scanning_alerts"].model_dump(),
    }

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
        _save_cache(org, cache, cache_storage)

    print("\n Collecting GitHub Actions Posture Data...", file=sys.stderr)

    report["4_actions_posture"] = {
        "details": {
            "runners": {
                "access": "ok",
                "total_count": org_data["org_actions"].self_hosted_runners,
                "runners": [],
            },
            "actions_permissions": {
                "access": "ok",
                "allowed_actions": org_data["org_actions"].allowed_actions_policy,
            },
            "credential_inventory": {
                "access": "ok",
                "total_count": org_data["org_actions"].org_secrets_count,
                "names": [],
            },
            "default_workflow_permissions": {
                "access": "ok",
                "default_workflow_permissions": org_data[
                    "org_actions"
                ].default_workflow_permissions,
            },
        }
    }

    print("\n Collecting Webhooks and GitHub Apps Data...", file=sys.stderr)
    report["5_webhooks_integrations"] = {
        "details": {
            "webhooks": {
                "access": "ok",
                "count": org_data["org_webhooks"].webhooks_count,
                "hooks": [],
            },
            "github_apps": {
                "access": "ok",
                "total_count": len(org_data["org_webhooks"].installed_apps),
                "apps": [
                    {"app_slug": slug}
                    for slug in org_data["org_webhooks"].installed_apps
                ],
            },
        }
    }

    print("\n Collecting Organization Rulesets Data...", file=sys.stderr)

    report["6_rulesets"] = {
        "details": {
            "access": "ok",
            "count": org_data["org_rulesets"].count,
            "rulesets": org_data["org_rulesets"].rulesets,
        }
    }

    return report


def write_excel(report: dict[str, Any], path: str) -> None:
    """Write the org security posture report to an Excel file."""
    summary = build_org_security_summary(report)
    summary_df = pd.DataFrame(list(summary.items()), columns=["metric", "value"])

    overview = report.get("org_overview", {})
    overview_df = pd.DataFrame(list(overview.items()), columns=["setting", "value"])

    org_settings = report.get("1_org_settings", {})
    mfa_df = pd.DataFrame(
        org_settings.get("members_without_2fa", {}).get("members", [])
    )
    collabs_df = pd.DataFrame(
        org_settings.get("outside_collaborators", {}).get("collaborators", [])
    )
    teams_df = pd.DataFrame(org_settings.get("teams", []))

    ghas = report.get("2_ghas_alerts", {})
    code_df = pd.DataFrame(ghas.get("code_scanning", {}).get("alerts", []))
    secret_df = pd.DataFrame(ghas.get("secret_scanning", {}).get("alerts", []))

    deps_df = pd.DataFrame(
        report.get("3_dependency_supply_chain", {})
        .get("summary", {})
        .get("details", [])
    )

    actions = report.get("4_actions_posture", {}).get("details", {})
    runners_df = pd.DataFrame(actions.get("runners", {}).get("runners", []))
    credentials_df = pd.DataFrame(
        {"credential_name": actions.get("credential_inventory", {}).get("names", [])}
    )

    webhooks = report.get("5_webhooks_integrations", {}).get("details", {})
    hooks_df = pd.DataFrame(webhooks.get("webhooks", {}).get("hooks", []))
    apps_df = pd.DataFrame(webhooks.get("github_apps", {}).get("apps", []))

    rulesets_df = pd.DataFrame(
        report.get("6_rulesets", {}).get("details", {}).get("rulesets", [])
    )

    # Map sheet names to DataFrames for writing
    sheet_to_df_mapping = {
        "Summary": summary_df,
        "Org Settings": overview_df,
        "2FA Disabled": mfa_df,
        "Outside Collaborators": collabs_df,
        "Teams": teams_df,
        "Code Scanning Alerts": code_df,
        "Secret Scanning Alerts": secret_df,
        "Supply Chain": deps_df,
        "Runners": runners_df,
        "Org Credentials": credentials_df,
        "Webhooks": hooks_df,
        "GitHub Apps": apps_df,
        "Rulesets": rulesets_df,
    }

    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        for sheet_name, df in sheet_to_df_mapping.items():
            if not df.empty:
                print(f"Writing sheet: {sheet_name} ({len(df)} rows)", file=sys.stderr)
                df.to_excel(writer, index=False, sheet_name=sheet_name)
            else:
                print(f"Skipping empty sheet: {sheet_name}", file=sys.stderr)

    print(f"Wrote {path}", file=sys.stderr)


def main() -> None:
    """Main entry point for org security posture audit script."""
    global __start_time
    __start_time = time.monotonic()

    args = _parse_args()

    config: AuditConfig = load_audit_config(args.config_file)

    org_security_posture_config = config.org_security_posture

    # Define Variables from Config
    database_path = Path(org_security_posture_config.database_path)
    if not database_path.is_absolute():
        database_path = Path(PROJECT_ROOT) / database_path
    database_path.parent.mkdir(parents=True, exist_ok=True)
    global ORG_CACHE_DB_PATH
    ORG_CACHE_DB_PATH = str(database_path)
    github_organization = config.github_organization
    output_filename = org_security_posture_config.output_filename
    repo_file = config.repo_list_file
    use_cache = org_security_posture_config.use_cache

    if repo_file is not None and not Path(repo_file).is_absolute():
        repo_file = str(Path(PROJECT_ROOT) / repo_file)

    # Org Security Posture Config Debug
    print(section_break, file=sys.stderr)

    print(
        "org_security_posture to be executed with the following config values:",
        file=sys.stderr,
    )

    print(section_break, file=sys.stderr)

    print(f"Auth method: {args.auth}", file=sys.stderr)
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
        args.auth,
        repo_full_names=repo_scope,
        use_cache=use_cache,
    )

    print("\n Audit complete. Building summary...", file=sys.stderr)
    summary = build_org_security_summary(report)

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

    print("\n=== SECURITY POSTURE SUMMARY ===", file=sys.stderr)
    for key in _SAFE_SUMMARY_KEYS:
        if key in summary:
            print(f"  {key}: {summary[key]}", file=sys.stderr)

    excel_path = os.path.join(OUTPUT_DIR, output_filename)
    write_excel(report, excel_path)


if __name__ == "__main__":
    main()
