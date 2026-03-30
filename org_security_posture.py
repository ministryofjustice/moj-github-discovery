#!/usr/bin/env python3
"""Organisation-level security posture report built on core modules."""

from __future__ import annotations

import argparse
import atexit
import os
import sys
import time
from typing import Any

import pandas as pd

from core.collector import OrgEndpointCollector
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

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ORG_CACHE_DB_PATH = os.path.join(SCRIPT_DIR, "org_posture_cache.db")
DEFAULT_REPO_FILE = os.path.join(SCRIPT_DIR, "repo_list.yaml")
__start_time: float | None = None


def _report_elapsed() -> None:
    if __start_time is not None:
        elapsed = time.monotonic() - __start_time
        print(f"Elapsed time: {elapsed:.2f}s", file=sys.stderr)


atexit.register(_report_elapsed)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit organisation security posture using core collectors."
    )
    parser.add_argument("org", help="GitHub organisation login.")
    parser.add_argument("--excel", help="Write Excel workbook output.")
    parser.add_argument(
        "--repo-file",
        nargs="?",
        const=DEFAULT_REPO_FILE,
        help=(
            "Limit supply-chain checks to repos in a file. "
            "Pass a path, or use --repo-file without a value to default to repo_list.yaml."
        ),
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Ignore on-disk posture cache and fetch fresh data.",
    )
    return parser.parse_args()


def _load_cache(org: str, storage: SqliteOrgStorage) -> dict[str, Any]:
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
    updated_at = time.time()
    storage.upsert_cache(org, cache, updated_at)
    print(f"  Saved cache: {ORG_CACHE_DB_PATH}", file=sys.stderr)


def run_full_audit(
    org: str,
    repo_full_names: list[str] | None = None,
    use_cache: bool = True,
) -> dict[str, Any]:
    cache_storage = SqliteOrgStorage(ORG_CACHE_DB_PATH)
    cache_storage.init()
    cache = _load_cache(org, cache_storage) if use_cache else {}
    client = GitHubHttpClient()

    report: dict[str, Any] = {
        "org": org,
        "audited_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

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

    report["2_ghas_alerts"] = {
        "code_scanning": org_data["org_code_scanning_alerts"].model_dump(),
        "secret_scanning": org_data["org_secret_scanning_alerts"].model_dump(),
    }

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
            "secrets": {
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

    report["6_rulesets"] = {
        "details": {
            "access": "ok",
            "count": org_data["org_rulesets"].count,
            "rulesets": org_data["org_rulesets"].rulesets,
        }
    }

    return report


def write_excel(report: dict[str, Any], path: str) -> None:
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
    secrets_df = pd.DataFrame(
        {"secret_name": actions.get("secrets", {}).get("names", [])}
    )

    webhooks = report.get("5_webhooks_integrations", {}).get("details", {})
    hooks_df = pd.DataFrame(webhooks.get("webhooks", {}).get("hooks", []))
    apps_df = pd.DataFrame(webhooks.get("github_apps", {}).get("apps", []))

    rulesets_df = pd.DataFrame(
        report.get("6_rulesets", {}).get("details", {}).get("rulesets", [])
    )

    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        summary_df.to_excel(writer, index=False, sheet_name="Summary")
        if not overview_df.empty:
            overview_df.to_excel(writer, index=False, sheet_name="Org Settings")
        if not mfa_df.empty:
            mfa_df.to_excel(writer, index=False, sheet_name="2FA Disabled")
        if not collabs_df.empty:
            collabs_df.to_excel(writer, index=False, sheet_name="Outside Collaborators")
        if not teams_df.empty:
            teams_df.to_excel(writer, index=False, sheet_name="Teams")
        if not code_df.empty:
            code_df.to_excel(writer, index=False, sheet_name="Code Scanning Alerts")
        if not secret_df.empty:
            secret_df.to_excel(writer, index=False, sheet_name="Secret Scanning Alerts")
        if not deps_df.empty:
            deps_df.to_excel(writer, index=False, sheet_name="Supply Chain")
        if not runners_df.empty:
            runners_df.to_excel(writer, index=False, sheet_name="Runners")
        if not secrets_df.empty:
            secrets_df.to_excel(writer, index=False, sheet_name="Org Secrets")
        if not hooks_df.empty:
            hooks_df.to_excel(writer, index=False, sheet_name="Webhooks")
        if not apps_df.empty:
            apps_df.to_excel(writer, index=False, sheet_name="GitHub Apps")
        if not rulesets_df.empty:
            rulesets_df.to_excel(writer, index=False, sheet_name="Rulesets")

    print(f"Wrote {path}", file=sys.stderr)


def main() -> None:
    global __start_time
    __start_time = time.monotonic()

    args = _parse_args()

    repo_scope: list[str] | None = None
    if args.repo_file:
        try:
            repo_scope = load_repo_list_file(args.repo_file)
        except Exception as exc:
            print(f"Failed to read repo file: {exc}", file=sys.stderr)
            sys.exit(2)

        org_prefix = f"{args.org}/"
        repo_scope = [name for name in repo_scope if name.startswith(org_prefix)]
        print(
            f"Using {len(repo_scope)} repos from {args.repo_file} for supply-chain checks",
            file=sys.stderr,
        )

    print(f"Running org security posture audit for: {args.org}", file=sys.stderr)
    report = run_full_audit(
        args.org,
        repo_full_names=repo_scope,
        use_cache=not args.no_cache,
    )

    summary = build_org_security_summary(report)
    print("\n=== SECURITY POSTURE SUMMARY ===", file=sys.stderr)
    for key, value in summary.items():
        print(f"  {key}: {value}", file=sys.stderr)

    if args.excel:
        write_excel(report, args.excel)


if __name__ == "__main__":
    main()
